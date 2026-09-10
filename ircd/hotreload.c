/*
 * IRC - Internet Relay Chat, ircd/hotreload.c
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Orchestration of a hot reload.
 */
#include "config.h"

#include "hotreload.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_tls.h"
#include "listener.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "send.h"
#include "tls_ktls.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/** Descriptor holding the state dump we were execed with; -1 unless booted with -R. */
int hotreload_fd = -1;
/** Non-zero when booted with -K, to check a dump instead of serving it. */
int hotreload_check = 0;

/** Head of the listener list.  listener.h does not export it, and
 * hotreload_load.c reaches it the same way. */
extern struct Listener *ListenerPollList;

/** Interval between two waitpid() probes of the pre-flight child, in
 * microseconds. */
#define HR_POLL_USEC 50000
/** Highest descriptor number hr_close_all_except() is ever asked to sweep. */
#define HR_MAX_SWEEP_FD 65536

/** Test whether a local connection can be carried across a reload.
 *
 * This is the single rule the whole reload is built on, and both halves need
 * the same answer: server_reload() sheds exactly the connections it says no
 * for, and hotreload_dump() writes exactly the ones it says yes for.  Two
 * copies of the rule would let the dump name a descriptor the shed had
 * already closed, or drop a client that is still connected after the exec.
 *
 * A registered local user with a live descriptor is carriable, unless it is
 * dying (IsDead) or its TLS record layer lives in the library rather than in
 * the kernel: the library goes with the image, so a session that is not
 * kernel-offloaded cannot be driven raw afterwards.  ircd_tls_offloaded()
 * also reports a session left raw by an earlier reload as offloaded, because
 * it has no library object to lose; see its contract in ircd_tls.h.
 *
 * @param[in] cptr Client to test.
 * @return Non-zero when the dump can carry \a cptr across the exec.
 */
int hotreload_client_carriable(const struct Client *cptr)
{
  if (!cptr)
    return 0;
  if (!IsUser(cptr) || !MyConnect(cptr))
    return 0;
  if (cli_fd(cptr) < 0 || IsDead(cptr))
    return 0;
  if (IsTLS(cptr) && !ircd_tls_offloaded(cptr))
    return 0;

  return 1;
}

/** Test whether \a text is one or more decimal digits and nothing else.
 * @param[in] text String to inspect.
 * @return Non-zero when \a text is a non-empty run of digits.
 */
static int hr_all_digits(const char *text)
{
  if (!*text)
    return 0;

  while (*text) {
    if (*text < '0' || *text > '9')
      return 0;
    text++;
  }

  return 1;
}

/** Build the argument vector to re-exec this server with.
 *
 * The vector is this server's own command line with any hot reload
 * bookkeeping stripped: a reload of a reloaded server would otherwise
 * accumulate one "-R <fd>" pair per generation, and every pair but the last
 * would name a descriptor that died with the previous exec.  Both spellings
 * getopt() accepts are dropped, a separate "-R" plus its operand and a
 * joined "-R<digits>".
 *
 * @param[in] fdtext Descriptor number of the state dump, in decimal.
 * @param[in] check Non-zero to append "-K", for the pre-flight child.
 * @return Freshly allocated NULL terminated vector; release with MyFree().
 *   The strings inside it are borrowed, not copied.
 */
static char **hr_build_argv(const char *fdtext, int check)
{
  char **out;
  int i;
  int n = 0;

  /* argv, plus "-R", the descriptor, "-K" and the NULL terminator. */
  out = (char **)MyMalloc(sizeof(*out) * (thisServer.argc + 4));

  for (i = 0; i < thisServer.argc && thisServer.argv[i]; i++) {
    char *arg = thisServer.argv[i];

    /* argv[0] is the program name, never an option. */
    if (i > 0 && !strcmp(arg, "-R")) {
      i++;                      /* and skip the descriptor that follows it */
      continue;
    }
    if (i > 0 && !strncmp(arg, "-R", 2) && hr_all_digits(arg + 2))
      continue;
    if (i > 0 && !strcmp(arg, "-K"))
      continue;

    out[n++] = arg;
  }

  out[n++] = (char *)"-R";
  out[n++] = (char *)fdtext;
  if (check)
    out[n++] = (char *)"-K";
  out[n] = 0;

  return out;
}

/** Run the pre-flight child and wait for its verdict.
 *
 * The child is this same binary, execed with "-K" so that it reads the dump,
 * builds every client and channel in memory and exits without ever writing to
 * a socket.  It is the only way to learn that the binary at SPATH cannot
 * serve this dump while there is still a working server to fall back on.
 *
 * @param[in] fdtext Descriptor number of the state dump, in decimal.
 * @param[out] detail Receives a human readable failure reason.
 * @param[in] len Size of \a detail.
 * @return Non-zero when the child exited zero, zero on any failure.
 */
static int hr_preflight(const char *fdtext, char *detail, size_t len)
{
  char **argv_check = hr_build_argv(fdtext, 1);
  int seconds = feature_int(FEAT_RELOAD_TIMEOUT);
  struct sigaction chld_wait, chld_old;
  time_t deadline;
  int status = 0;
  int reaped = 0;
  int rc = 1;
  pid_t pid;

  /* Clamp the deadline here rather than trust the feature.  The wait below is
   * a blocking poll inside the event loop: nothing else is served while it
   * runs, so an operator who sets RELOAD_TIMEOUT to zero (no wait at all, a
   * healthy child reaped as a failure) or to something enormous (the whole
   * server wedged behind a hung child) has broken the server with a config
   * value.  One to thirty seconds is the usable range -- half a minute of a
   * frozen event loop is already as much as a network will tolerate. */
  if (seconds < 1)
    seconds = 1;
  if (seconds > 30)
    seconds = 30;

  /* The kqueue engine (engine_kqueue.c) sets every registered signal, SIGCHLD
   * included, to SIG_IGN.  For SIGCHLD that tells the kernel to reap children
   * itself, so the pre-flight child never becomes a waitable zombie and the
   * waitpid() below returns ECHILD ("No child processes") -- which aborted
   * every reload on FreeBSD.  Install a disposition under which the child is
   * waitable for the span of the pre-flight and restore the engine's handler
   * afterwards.  The event loop is paused here, so nothing else needs SIGCHLD
   * meanwhile, and the kqueue EVFILT_SIGNAL registration is independent of the
   * sigaction disposition, so it survives untouched.  The self-pipe engines
   * (epoll/poll/select) already use a real handler, so this is a no-op there. */
  memset(&chld_wait, 0, sizeof(chld_wait));
  chld_wait.sa_handler = SIG_DFL;
  sigemptyset(&chld_wait.sa_mask);
  chld_wait.sa_flags = 0;
  sigaction(SIGCHLD, &chld_wait, &chld_old);

  pid = fork();
  if (pid == 0) {
    execv(SPATH, argv_check);
    _exit(127);
  }

  if (pid < 0) {
    ircd_snprintf(0, detail, len, "fork failed: %s", strerror(errno));
    MyFree(argv_check);
    rc = 0;
    goto restore;
  }

  MyFree(argv_check);

  /* Wall clock, not a count of iterations: usleep() sleeps for at least the
   * interval it is given and returns early on a signal, so counting probes
   * makes the real deadline anything from a fraction of the configured time
   * (a server taking signals) to well over it (a loaded box). */
  deadline = time(NULL) + seconds;

  do {
    pid_t done = waitpid(pid, &status, WNOHANG);

    if (done == pid) {
      reaped = 1;
      break;
    }
    if (done < 0 && errno != EINTR) {
      /* The child is still out there and nothing else will ever reap it, so
       * it would run on as an orphan of a server that has given up on it --
       * and it holds the dump descriptor open. */
      ircd_snprintf(0, detail, len, "waitpid failed: %s", strerror(errno));
      kill(pid, SIGKILL);
      waitpid(pid, &status, 0);
      rc = 0;
      goto restore;
    }
    /* usleep() returning EINTR has slept for an unknown part of the interval;
     * the loop condition re-reads the clock, so simply probe again. */
    usleep(HR_POLL_USEC);
  } while (time(NULL) < deadline);

  if (!reaped) {
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    ircd_snprintf(0, detail, len, "timeout after %d seconds", seconds);
    rc = 0;
    goto restore;
  }

  if (WIFSIGNALED(status)) {
    ircd_snprintf(0, detail, len, "signal %d", WTERMSIG(status));
    rc = 0;
    goto restore;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    ircd_snprintf(0, detail, len, "exit status %d",
                  WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    rc = 0;
    goto restore;
  }

  rc = 1;

restore:
  /* Restore the engine's SIGCHLD disposition (SIG_IGN under kqueue). */
  sigaction(SIGCHLD, &chld_old, NULL);
  return rc;
}

/** Dump state and exec this server in place, keeping connections open.
 *
 * Why exec in place rather than start a successor and let this process go:
 * the process id must not change.  Under docker the daemon is pid 1 of the
 * container or a direct child of the entrypoint, and under systemd it is the
 * unit's MainPID; either way a successor with a new pid reads as an exited
 * service, and the supervisor tears down the container or the unit with every
 * connection this whole exercise exists to preserve.  execv() replaces the
 * image while keeping the pid, the descriptor table and this process' place
 * in the supervision tree.
 *
 * @section order Why the pre-flight runs before anything is shed
 *
 * Shedding is irreversible: an SQUIT is on the wire and a killed TLS client
 * is gone whether or not the reload that wanted it gone ever happens.  So
 * every check that can fail runs first, while a failure still costs nothing:
 *
 *   1. SPATH must be executable and a temporary file must be creatable.
 *      Both are one syscall, and both are what a reload usually trips over:
 *      a half-finished install, a full or read-only temporary directory.
 *   2. A dump of the current state is written and handed to the pre-flight
 *      child, which is this binary execed with "-K": it reads the dump,
 *      rebuilds every client and channel in memory and exits without ever
 *      touching a socket.  It is the only way to learn that the binary at
 *      SPATH cannot serve this dump while there is still a working server to
 *      fall back on.  The dump names the connections that are here now
 *      rather than the ones that will be, and that is exactly what makes it
 *      a valid test: hotreload_dump() writes only what
 *      hotreload_client_carriable() accepts, which is the same set the shed
 *      below keeps.
 *   3. Only once the child has said yes does anything get shed.
 *   4. The dump is then written a second time over the same temporary file,
 *      because the first is stale the moment the shed runs: it names
 *      descriptors that are now closed and send queues that have since taken
 *      the QUIT and ERROR lines.  The image that execs reads dump #2, which
 *      is the state as it actually is.
 *
 * Why the descriptor keep set is exactly what it is: execv() carries over
 * every descriptor that is not close-on-exec, and the new image knows nothing
 * about the ones it is not told about, so anything left open leaks for the
 * lifetime of the server.  Three kinds of descriptor must survive, and
 * nothing else may:
 *
 *   - the client sockets of the local users still in LocalClientArray, which
 *     the dump names by number and hotreload_load.c adopts;
 *   - the listening sockets in ListenerPollList, which the dump names by
 *     address and port and inetport() reclaims through
 *     hotreload_claim_listener().  Rebinding them instead would open a window
 *     where connections are refused, and could fail outright while the old
 *     socket is still bound;
 *   - the dump itself, whose number is passed on the new command line.
 *
 * Everything else goes, and deliberately so: the event engine descriptor
 * (epoll, kqueue) is meaningless to a new image and is not inherited by one
 * on every platform, the resolver socket is rebuilt from the fresh config, an
 * iauth child's pipes belong to a child that dies with this image, and the
 * pid file lock must be dropped here so that the new image's check_pid() can
 * take it again.  hr_close_all_except() sweeps to the process descriptor
 * ceiling rather than to MAXCONNECTIONS because those non-client descriptors
 * sit wherever the kernel put them, which is above the client range whenever
 * the process fd limit is higher.
 *
 * @param[in] reason Human readable reason for the reload, for the logs.
 * @param[in] by Local client that issued the reload, or NULL for a signal.
 * @return 1 when \a by was exited by the shedding walk, so that the caller
 *   returns CPTR_KILLED instead of touching a freed client; 0 otherwise.
 *   Every abort path now returns before the shed, so an abort always returns
 *   0 and \a by is always still alive; once the shed has run the only way
 *   out of this function is the exec, or exit(8) when the exec fails.
 */
int server_reload(const char *reason, struct Client *by)
{
  static int reloading;
  struct Listener *listener;
  struct Client *cptr;
  char **argv_reload;
  char fdtext[16];
  char detail[128];
  int *keep;
  unsigned int nkeep = 0;
  unsigned int nlisteners = 0;
  FILE *f;
  long ceiling;
  int dumpfd;
  int flags;
  int by_exited = 0;
  int i;

  if (reloading) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Reload already in progress");
    return 0;                   /* nothing was shed, so `by' is untouched */
  }
  reloading = 1;

  log_write(LS_SYSTEM, L_WARNING, 0, "Reloading server: %s", reason);
  sendto_opmask_butone(0, SNO_OLDSNO, "Reloading server: %s", reason);

  /* 1. The cheap checks, before anything is spent.  An SPATH that cannot be
   * executed is the one failure the pre-flight child cannot report usefully:
   * it comes back as "exit status 127" from a fork we need not have made,
   * and it is exactly what a half-finished install looks like. */
  if (access(SPATH, X_OK)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Reload aborted: %s is not executable", SPATH);
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "Reload aborted: %s is not executable", SPATH);
    reloading = 0;
    return 0;                   /* nothing shed, so `by' is untouched */
  }

  if (!(f = tmpfile())) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Reload aborted: cannot create state file: %s", strerror(errno));
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "Reload aborted: cannot create state file: %s",
                         strerror(errno));
    reloading = 0;
    return 0;                   /* nothing shed, so `by' is untouched */
  }

  dumpfd = fileno(f);

  /* tmpfile() hands back a close-on-exec descriptor; the whole point of this
   * one is that it survives the exec. */
  if ((flags = fcntl(dumpfd, F_GETFD)) >= 0)
    fcntl(dumpfd, F_SETFD, flags & ~FD_CLOEXEC);

  /* 2. Dump #1, and the pre-flight that reads it.  hotreload_dump() filters
   * on hotreload_client_carriable(), so this already describes the state the
   * shed below will leave behind, minus the QUIT and ERROR lines the shed
   * itself queues. */
  if (!hotreload_dump(f)) {
    log_write(LS_SYSTEM, L_ERROR, 0, "Reload aborted: state dump failed");
    sendto_opmask_butone(0, SNO_OLDSNO, "Reload aborted: state dump failed");
    fclose(f);
    reloading = 0;
    return 0;                   /* nothing shed, so `by' is untouched */
  }

  fflush(f);
  lseek(dumpfd, 0, SEEK_SET);

  ircd_snprintf(0, fdtext, sizeof(fdtext), "%d", dumpfd);

  if (!hr_preflight(fdtext, detail, sizeof(detail))) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Reload aborted: pre-flight check failed (%s)", detail);
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "Reload aborted: pre-flight check failed (%s)",
                         detail);
    fclose(f);
    reloading = 0;
    return 0;                   /* back to the event loop; nothing was lost */
  }

  /* Logged as well as noticed: the notice below only reaches a send queue,
   * and this process execs before the event loop ever drains one, so the log
   * is the only place an operator can see afterwards that the pre-flight
   * passed.  Flushing it instead is not an option -- dump #2 holds a copy of
   * every send queue, and the new image would send it twice. */
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "Reload pre-flight ok, shedding links and non-carriable "
            "connections");
  sendto_opmask_butone(0, SNO_OLDSNO,
                       "Reload pre-flight ok, shedding links and "
                       "non-carriable connections");

  /* 3. Shed everything the dump cannot carry.  Nothing below returns to the
   * event loop.  exit_client() on one entry of LocalClientArray can take
   * remote clients with it, but never another local connection, so walking
   * by index is safe; the slot is re-read afterwards all the same. */
  for (i = 0; i <= HighestFd; i++) {
    if (!(cptr = LocalClientArray[i]) || cptr == &me)
      continue;

    if (IsDead(cptr) || cli_fd(cptr) < 0) {
      /* Already on its way out: the dump would name a descriptor that is
       * gone, or one the event loop is about to close. */
      if (cptr == by)
        by_exited = 1;
      exit_client(cptr, cptr, &me, "Server reloading");
    } else if (!IsUser(cptr)) {
      /* Servers, servers in handshake, unregistered users and connections
       * still inside the WEBIRC or websocket handshake.  For a server this
       * sends the SQUIT and removes its remote users; the link comes back on
       * its own once the new image is serving. */
      if (cptr == by)
        by_exited = 1;
      exit_client(cptr, cptr, &me, "Server reloading");
    } else if (IsTLS(cptr) && !ircd_tls_offloaded(cptr)) {
      /* The record layer for this session lives in the TLS library, and the
       * library goes with the image.  A session left raw by an earlier reload
       * has no library object at all, and ircd_tls_offloaded() reports it as
       * offloaded for exactly that reason; see its contract in ircd_tls.h. */
      if (cptr == by)
        by_exited = 1;
      exit_client(cptr, cptr, &me,
                  "Server reloading (TLS session cannot be carried over, "
                  "please reconnect)");
    } else if (cli_listing(cptr)) {
      /* The dump carries no LIST cursor, so end the listing here, exactly as
       * exit_one_client() would have. */
      MyFree(cli_listing(cptr));
      cli_listing(cptr) = NULL;
    }

    if (LocalClientArray[i] != cptr)
      continue;                 /* it went; nothing else to do with the slot */
  }

  /* Push the ERROR and QUIT lines written above out to the wire before dump
   * #2 records whatever is left in the send queues. */
  flush_connections(0);

  /* 4. Dump #2, over the same temporary file.  There is no way back from
   * here -- the links are already down -- so a failure at this point is
   * fatal rather than an abort: better a supervisor restart, which the
   * clients survive as a reconnect, than an exec into a truncated dump that
   * the new image would adopt half of. */
  /* fseek() rather than a raw lseek(): it moves the stdio stream and the
   * descriptor offset together, and unlike rewind() it reports a failure. */
  if (ftruncate(dumpfd, 0) || fseek(f, 0L, SEEK_SET)) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "Reload: cannot rewind state file after shedding: %s",
              strerror(errno));
    exit(8);
  }

  if (!hotreload_dump(f)) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "Reload: state dump failed after shedding, cannot continue");
    exit(8);
  }

  fflush(f);
  lseek(dumpfd, 0, SEEK_SET);

  for (listener = ListenerPollList; listener; listener = listener->next)
    nlisteners++;

  keep = (int *)MyMalloc(sizeof(*keep) * (MAXCONNECTIONS + 2 * nlisteners + 1));

  for (i = 0; i <= HighestFd; i++) {
    if (!(cptr = LocalClientArray[i]) || cptr == &me)
      continue;

    /* The same predicate the dump filters on, applied again here because the
     * flush_connections(0) above can change the answer: a write that hits
     * EPIPE runs dead_link(), which marks the client dead and takes it off
     * the poll set but leaves both the descriptor open and the Client in
     * LocalClientArray.  Such a client is in no dump, so nothing in the new
     * image will ever own its socket; carrying the descriptor across the exec
     * would leak it for the life of the process with the peer left hanging on
     * a connection nobody reads.  Skipping it here drops it through to
     * hr_close_all_except() below, and the close puts a FIN on the wire. */
    if (!hotreload_client_carriable(cptr)) {
      /* A kernel-offloaded session gets its close_notify first: the peer's
       * TLS stack reads a bare FIN as a truncation attack and reports it as
       * an error rather than as a clean disconnect. */
      if (IsTLS(cptr) && IsTLSRaw(cptr) && cli_fd(cptr) >= 0)
        tls_ktls_send_close_notify(cli_fd(cptr));
      continue;
    }

    /* Free the library session but leave the socket, and the kernel record
     * state on it, exactly as it is: the new image drives it raw. */
    if (IsTLS(cptr))
      ircd_tls_detach(cptr);

    if (cli_fd(cptr) >= 0)
      keep[nkeep++] = cli_fd(cptr);
  }

  for (listener = ListenerPollList; listener; listener = listener->next) {
    if (listener->fd_v4 >= 0)
      keep[nkeep++] = listener->fd_v4;
    if (listener->fd_v6 >= 0)
      keep[nkeep++] = listener->fd_v6;
  }

  keep[nkeep++] = dumpfd;

  log_close();

  /* MAXCONNECTIONS is the ircd's client descriptor ceiling, not the
   * process': the event engine, the log files and the resolver sit above it
   * whenever the process fd limit is higher. */
  ceiling = sysconf(_SC_OPEN_MAX);
  if (ceiling < MAXCONNECTIONS)
    ceiling = MAXCONNECTIONS;
  if (ceiling > HR_MAX_SWEEP_FD)
    ceiling = HR_MAX_SWEEP_FD;

  hr_close_all_except(keep, nkeep, (int)ceiling);
  MyFree(keep);

  argv_reload = hr_build_argv(fdtext, 0);
  execv(SPATH, argv_reload);

  /* Have to reopen since it has been closed above. */
  log_reopen();
  log_write(LS_SYSTEM, L_CRIT, 0, "execv(%s) failed after reload: %m", SPATH);
  exit(8);

  /* NOTREACHED.  by_exited is read here only so that the shedding walk's
   * bookkeeping is not dead code to the compiler. */
  return by_exited;
}

/** Write a state dump to a file below RELOAD_DUMP_DIR, for debugging.
 *
 * A state dump holds every local user's nick, host, address, account,
 * operator privileges, silence list and pending send queue, so the file it
 * lands in must be chosen by the administrator and not by whoever types the
 * command.  Three rules do that:
 *
 *   - \a name is a plain file name.  Anything holding a '/', and the two
 *     directory names "." and "..", is refused, so the dump cannot be steered
 *     out of the configured directory by a relative or absolute path;
 *   - the directory is RELOAD_DUMP_DIR, or the working directory (DPATH) when
 *     that feature is unset.  It is never taken from the command;
 *   - the file is created with O_EXCL | O_NOFOLLOW and mode 0600, so an
 *     existing file, a symlink planted in the directory, or a file whose
 *     permissions someone widened beforehand all fail rather than being
 *     written through.  O_EXCL means a dump never overwrites, which also
 *     rules out truncating a file the server itself needs.
 *
 * @param[in] name Plain file name to write the dump to.
 * @return Non-zero on success, zero on failure with errno set.
 */
int hotreload_dump_to_path(const char *name)
{
  const char *dir;
  char path[1024];
  FILE *f;
  int ok;
  int fd;

  if (!name || !*name || strchr(name, '/') || !strcmp(name, ".")
      || !strcmp(name, "..")) {
    errno = EINVAL;
    return 0;
  }

  dir = feature_str(FEAT_RELOAD_DUMP_DIR);
  if (!dir || !*dir)
    dir = ".";                  /* DPATH: the daemon's working directory */

  ircd_snprintf(0, path, sizeof(path), "%s/%s", dir, name);

  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (fd < 0)
    return 0;                   /* errno is the caller's to report */

  if (!(f = fdopen(fd, "w"))) {
    int saved = errno;

    close(fd);
    errno = saved;
    return 0;
  }

  ok = hotreload_dump(f);

  if (fclose(f))
    ok = 0;

  /* EINVAL is reserved for the name check above, which is the one failure
   * m_reload.c reports back to the oper by name; a write error that happened
   * to leave EINVAL behind must not be dressed up as a bad file name. */
  if (!ok && EINVAL == errno)
    errno = EIO;

  return ok;
}
