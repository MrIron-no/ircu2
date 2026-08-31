/*
 * kqueue_reenable_t.c -- standalone kqueue diagnostic (BSD only).
 *
 * NOT part of the automake build (kqueue does not exist on the Linux CI box,
 * and it links nothing from ircd).  Build and run it by hand on the FreeBSD
 * host that shows the "TLS handshake timed out from unknown server" stall:
 *
 *     cc -o kqueue_reenable_t kqueue_reenable_t.c
 *     ./kqueue_reenable_t
 *
 * It reproduces, without any TLS or network race, the exact question behind
 * ircd/engine_kqueue.c: when a read filter is disarmed, data arrives on the
 * socket, and the filter is re-armed, does kevent() re-deliver that buffered
 * data?  It runs the OLD engine sequence (EV_ADD|EV_DISABLE to disarm, then
 * EV_ADD|EV_ENABLE to re-arm) and the NEW/fixed sequence (EV_DELETE to disarm,
 * then a fresh EV_ADD|EV_ENABLE to re-arm) on the same buffered byte.
 *
 * Exit status / output:
 *   old=NO,  new=yes  -> reproduces the stall and confirms the fix (expected).
 *   old=yes, new=yes  -> this kernel re-delivers either way; the stall is NOT
 *                        this mechanism -- the engine fix is not the cause and
 *                        we must look elsewhere.
 *   new=NO            -> the fix path ALSO misses the data: the fix is wrong
 *                        for this kernel.
 * Returns 0 only when new delivers and old does not (fix reproduced+confirmed).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Drain any events currently queued on kq (a 0-timeout kevent poll). */
static void drain(int kq)
{
  struct kevent ev;
  struct timespec ts = { 0, 0 };
  while (kevent(kq, 0, 0, &ev, 1, &ts) == 1)
    ;
}

/* 1 if EVFILT_READ for fd is reported ready within a 0 timeout. */
static int poll_read(int kq, int fd)
{
  struct kevent ev;
  struct timespec ts = { 0, 0 };
  int n = kevent(kq, 0, 0, &ev, 1, &ts);
  return n == 1 && ev.filter == EVFILT_READ && ev.ident == (uintptr_t) fd;
}

/* Run one disarm/re-arm cycle.  use_delete selects the fixed sequence.
 * Returns 1 if the byte written while disarmed is re-delivered after re-arm. */
static int cycle(int kq, int fd, int peer, int use_delete)
{
  struct kevent chg;
  char buf[16];
  int delivered;

  /* arm, and clear any readiness so the poll below is unambiguous */
  EV_SET(&chg, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
  kevent(kq, &chg, 1, 0, 0, 0);
  drain(kq);

  /* disarm: old engine used EV_ADD|EV_DISABLE; fix uses EV_DELETE */
  if (use_delete)
    EV_SET(&chg, fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
  else
    EV_SET(&chg, fd, EVFILT_READ, EV_ADD | EV_DISABLE, 0, 0, 0);
  kevent(kq, &chg, 1, 0, 0, 0);

  /* data arrives while the filter is disarmed */
  if (write(peer, "z", 1) != 1) {
    perror("write");
    return -1;
  }

  /* re-arm (identical flags for both paths) and poll */
  EV_SET(&chg, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
  kevent(kq, &chg, 1, 0, 0, 0);
  delivered = poll_read(kq, fd);

  /* cleanup: consume the byte, remove the filter */
  (void) read(fd, buf, sizeof buf);
  EV_SET(&chg, fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
  kevent(kq, &chg, 1, 0, 0, 0);
  drain(kq);
  return delivered;
}

int main(void)
{
  int kq, sp[2], old_delivers, new_delivers;

  if ((kq = kqueue()) < 0) {
    perror("kqueue");
    return 2;
  }
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
    perror("socketpair");
    return 2;
  }

  old_delivers = cycle(kq, sp[0], sp[1], 0);
  new_delivers = cycle(kq, sp[0], sp[1], 1);

  close(sp[0]);
  close(sp[1]);
  close(kq);

  if (old_delivers < 0 || new_delivers < 0)
    return 2;

  printf("EV_ADD|EV_DISABLE then EV_ADD|EV_ENABLE re-delivers buffered data: %s\n",
         old_delivers ? "yes" : "NO");
  printf("EV_DELETE        then EV_ADD|EV_ENABLE re-delivers buffered data: %s\n",
         new_delivers ? "yes" : "NO");

  if (!old_delivers && new_delivers)
    puts("=> reproduces the stall (old path) and confirms the fix (new path).");
  else if (old_delivers && new_delivers)
    puts("=> this kernel re-delivers either way: the stall is NOT this "
         "mechanism -- the engine fix is not the cause, look elsewhere.");
  else if (!new_delivers)
    puts("=> the fix path ALSO misses the data: the fix is wrong for this "
         "kernel.");

  return (new_delivers && !old_delivers) ? 0 : 1;
}
