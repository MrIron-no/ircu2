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

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/** Descriptor holding the state dump we were execed with; -1 unless booted with -R. */
int hotreload_fd = -1;
/** Non-zero when booted with -K, to check a dump instead of serving it. */
int hotreload_check = 0;

/** Head of the listener list.  listener.h does not export it, and
 * hotreload_load.c reaches it the same way. */
extern struct Listener *ListenerPollList;

/** The command line this server was started with.  ircd.c owns it; the
 * reload needs it verbatim to build the vector it re-execs with. */
extern struct Daemon thisServer;

/** Interval between two waitpid() probes of the pre-flight child, in
 * microseconds. */
#define HR_POLL_USEC 50000
/** Number of poll intervals in one second, for the pre-flight deadline. */
#define HR_POLLS_PER_SEC (1000000 / HR_POLL_USEC)
/** Highest descriptor number hr_close_all_except() is ever asked to sweep. */
#define HR_MAX_SWEEP_FD 65536

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
  int deadline = seconds * HR_POLLS_PER_SEC;
  int status = 0;
  int reaped = 0;
  int waited;
  pid_t pid;

  pid = fork();
  if (pid == 0) {
    execv(SPATH, argv_check);
    _exit(127);
  }

  if (pid < 0) {
    ircd_snprintf(0, detail, len, "fork failed: %s", strerror(errno));
    MyFree(argv_check);
    return 0;
  }

  MyFree(argv_check);

  for (waited = 0; waited <= deadline; waited++) {
    pid_t done = waitpid(pid, &status, WNOHANG);

    if (done == pid) {
      reaped = 1;
      break;
    }
    if (done < 0 && errno != EINTR) {
      ircd_snprintf(0, detail, len, "waitpid failed: %s", strerror(errno));
      return 0;
    }
    usleep(HR_POLL_USEC);
  }

  if (!reaped) {
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    ircd_snprintf(0, detail, len, "timeout after %d seconds", seconds);
    return 0;
  }

  if (WIFSIGNALED(status)) {
    ircd_snprintf(0, detail, len, "signal %d", WTERMSIG(status));
    return 0;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    ircd_snprintf(0, detail, len, "exit status %d",
                  WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
  }

  return 1;
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
 */
void server_reload(const char *reason)
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
  int i;

  if (reloading) {
    sendto_opmask_butone(0, SNO_OLDSNO, "Reload already in progress");
    return;
  }
  reloading = 1;

  log_write(LS_SYSTEM, L_WARNING, 0, "Reloading server: %s", reason);
  sendto_opmask_butone(0, SNO_OLDSNO, "Reloading server: %s", reason);

  /* Shed everything the dump cannot carry.  exit_client() on one entry of
   * LocalClientArray can take remote clients with it, but never another
   * local connection, so walking by index is safe; the slot is re-read
   * afterwards all the same. */
  for (i = 0; i <= HighestFd; i++) {
    if (!(cptr = LocalClientArray[i]) || cptr == &me)
      continue;

    if (IsDead(cptr) || cli_fd(cptr) < 0) {
      /* Already on its way out: the dump would name a descriptor that is
       * gone, or one the event loop is about to close. */
      exit_client(cptr, cptr, &me, "Server reloading");
    } else if (!IsUser(cptr)) {
      /* Servers, servers in handshake, unregistered users and connections
       * still inside the WEBIRC or websocket handshake.  For a server this
       * sends the SQUIT and removes its remote users; the link comes back on
       * its own once the new image is serving. */
      exit_client(cptr, cptr, &me, "Server reloading");
    } else if (IsTLS(cptr) && !IsTLSRaw(cptr) && !ircd_tls_offloaded(cptr)) {
      /* The record layer for this session lives in the TLS library, and the
       * library goes with the image.
       *
       * IsTLSRaw is the survivor of an earlier reload: it has no library
       * session left for ircd_tls_offloaded() to look at (that is what
       * ircd_tls_detach() did to it), but the kernel record state it is
       * driven through is still on the socket, and it only ever became raw
       * because it was fully offloaded when the last dump was written.  It
       * carries over again unchanged. */
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

  /* Push the ERROR and QUIT lines written above out to the wire before the
   * dump records whatever is left in the send queues. */
  flush_connections(0);

  if (!(f = tmpfile())) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Reload aborted: cannot create state file: %s", strerror(errno));
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "Reload aborted: cannot create state file: %s",
                         strerror(errno));
    reloading = 0;
    return;
  }

  dumpfd = fileno(f);

  /* tmpfile() hands back a close-on-exec descriptor; the whole point of this
   * one is that it survives the exec. */
  if ((flags = fcntl(dumpfd, F_GETFD)) >= 0)
    fcntl(dumpfd, F_SETFD, flags & ~FD_CLOEXEC);

  if (!hotreload_dump(f)) {
    log_write(LS_SYSTEM, L_ERROR, 0, "Reload aborted: state dump failed");
    sendto_opmask_butone(0, SNO_OLDSNO, "Reload aborted: state dump failed");
    fclose(f);
    reloading = 0;
    return;
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
    return;                     /* back to the event loop; nothing was lost */
  }

  /* Logged as well as noticed: the notice below only reaches a send queue,
   * and this process execs before the event loop ever drains one, so the log
   * is the only place an operator can see afterwards that the pre-flight
   * passed.  Flushing it instead is not an option -- the dump already holds
   * a copy of every send queue, and the new image would send it twice. */
  log_write(LS_SYSTEM, L_NOTICE, 0, "Reload pre-flight ok, exec'ing %s", SPATH);
  sendto_opmask_butone(0, SNO_OLDSNO, "Reload pre-flight ok, exec'ing %s",
                       SPATH);

  /* The pre-flight child read the dump to EOF through the file offset it
   * shares with us. */
  lseek(dumpfd, 0, SEEK_SET);

  for (listener = ListenerPollList; listener; listener = listener->next)
    nlisteners++;

  keep = (int *)MyMalloc(sizeof(*keep) * (MAXCONNECTIONS + 2 * nlisteners + 1));

  for (i = 0; i <= HighestFd; i++) {
    if (!(cptr = LocalClientArray[i]) || cptr == &me)
      continue;

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
}

/** Write a state dump to a file, for debugging.
 * @param[in] path File to write the dump to.
 * @return Non-zero on success, zero on failure.
 */
int hotreload_dump_to_path(const char *path)
{
  FILE *f;
  int ok;

  if (!(f = fopen(path, "w")))
    return 0;                   /* errno is the caller's to report */

  ok = hotreload_dump(f);

  if (fclose(f))
    ok = 0;

  return ok;
}
