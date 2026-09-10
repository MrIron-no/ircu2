/* tls_ktls_t.c - unit tests for the raw kernel-TLS record layer (tls_ktls.c).
 *
 * Raw mode drives a hot-reloaded connection's socket with no TLS library
 * session behind it: the kernel does the record framing, so reads must go
 * through recvmsg() with a control buffer or a control record (an alert, a
 * KeyUpdate) would be invisible -- and a plain read() with one pending fails
 * EIO without consuming it.  These tests cover:
 *   - tls_ktls_classify(): the record-type policy, which is a pure function
 *     and therefore the one part of this module testable without a real
 *     kTLS-offloaded socket (that needs a full handshake and a kernel ULP);
 *   - tls_ktls_recv() over an AF_UNIX socketpair, which carries no TLS ULP
 *     and so exercises the no-cmsg paths: data, would-block, and peer EOF;
 *   - tls_ktls_send_close_notify() on a socket with no ULP: it must fail
 *     softly (0), never abort, since close_connection() calls it on any fd
 *     flagged raw;
 *   - tls_ktls_supported() reporting this build's platform support.
 */

#include "ircd_log.h"
#include "tls_ktls.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/* --- A: record classification --------------------------------------------- */

/* The policy is deliberately strict: application data passes, a well-formed
 * close_notify is an orderly EOF, and everything else -- a fatal alert, a
 * KeyUpdate we cannot answer without a session, a handshake or heartbeat
 * record, a truncated alert -- is fatal.  Raw mode has no library to
 * renegotiate or rekey with, so "not plain data" means "drop the link". */
static void test_classify(void)
{
  static const unsigned char close_notify[2] = { 1, 0 };
  static const unsigned char fatal_alert[2]  = { 2, 80 };
  static const unsigned char key_update[5]   = { 0x18, 0, 0, 1, 1 };
  static const unsigned char one_byte[1]     = { 1 };
  static const unsigned char data[3]         = { 'a', 'b', 'c' };

  /* 23: application data */
  assert(tls_ktls_classify(23, data, sizeof(data)) == TLS_KTLS_DATA);
  assert(tls_ktls_classify(23, NULL, 0) == TLS_KTLS_DATA);

  /* 21 alert: warning(1) close_notify(0) is the orderly shutdown */
  assert(tls_ktls_classify(21, close_notify, sizeof(close_notify))
         == TLS_KTLS_CLOSE_NOTIFY);

  /* 21 alert: anything else is fatal, including a truncated alert body */
  assert(tls_ktls_classify(21, fatal_alert, sizeof(fatal_alert))
         == TLS_KTLS_FATAL);
  assert(tls_ktls_classify(21, one_byte, sizeof(one_byte)) == TLS_KTLS_FATAL);
  assert(tls_ktls_classify(21, NULL, 0) == TLS_KTLS_FATAL);

  /* 22 handshake (a TLS1.3 KeyUpdate): no session to rekey with */
  assert(tls_ktls_classify(22, key_update, sizeof(key_update))
         == TLS_KTLS_FATAL);

  /* every other record type */
  assert(tls_ktls_classify(20, NULL, 0) == TLS_KTLS_FATAL);
  assert(tls_ktls_classify(24, NULL, 0) == TLS_KTLS_FATAL);
  assert(tls_ktls_classify(0, NULL, 0) == TLS_KTLS_FATAL);
  assert(tls_ktls_classify(255, NULL, 0) == TLS_KTLS_FATAL);

  printf("Passed: record classification\n");
}

/* --- B: recv over a socketpair (no TLS ULP, so no cmsg ever arrives) ------- */

static void test_recv_socketpair(void)
{
  int sv[2];
  char buf[64];
  unsigned int count = 0xdeadbeef;
  int closed = -1;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    printf("FAILED: socketpair: %s\n", strerror(errno));
    exit(1);
  }

  /* nothing queued: MSG_DONTWAIT must report a block, not stall the daemon */
  assert(tls_ktls_recv(sv[0], buf, sizeof(buf), &count, &closed) == IO_BLOCKED);
  assert(count == 0);
  assert(closed == 0);

  /* ordinary data: exactly the bytes written, no more */
  assert(write(sv[1], "PING :x\r\n", 9) == 9);
  count = 0xdeadbeef;
  closed = -1;
  assert(tls_ktls_recv(sv[0], buf, sizeof(buf), &count, &closed) == IO_SUCCESS);
  assert(count == 9);
  assert(closed == 0);
  assert(!memcmp(buf, "PING :x\r\n", 9));

  /* drained again */
  assert(tls_ktls_recv(sv[0], buf, sizeof(buf), &count, &closed) == IO_BLOCKED);
  assert(count == 0);
  assert(closed == 0);

  /* peer gone: a 0-byte read is EOF, reported as success with closed set --
   * tls_io_recv() is what turns that into the daemon's EOF contract. */
  close(sv[1]);
  count = 0xdeadbeef;
  closed = -1;
  assert(tls_ktls_recv(sv[0], buf, sizeof(buf), &count, &closed) == IO_SUCCESS);
  assert(count == 0);
  assert(closed == 1);

  close(sv[0]);
  printf("Passed: recv over socketpair (data, block, EOF)\n");
}

/* A bad descriptor is an ordinary failure, not an assertion or a crash. */
static void test_recv_bad_fd(void)
{
  char buf[16];
  unsigned int count = 0xdeadbeef;
  int closed = -1;

  assert(tls_ktls_recv(-1, buf, sizeof(buf), &count, &closed) == IO_FAILURE);
  assert(count == 0);
  printf("Passed: recv on a bad descriptor fails cleanly\n");
}

/* --- C: close_notify on a socket with no TLS ULP --------------------------- */

/* close_connection() sends this on any fd flagged raw.  Where the kernel
 * refuses the cmsg -- no ULP on the socket, an already-reset connection, a
 * platform without kernel TLS -- it must simply report "not sent" and let the
 * close proceed, never abort and never block.
 *
 * An AF_UNIX socketpair is NOT such a case, though it looks like one: Linux's
 * AF_UNIX sendmsg path ignores an ancillary message whose cmsg_level is not
 * SOL_SOCKET rather than rejecting it, so the call succeeds and the two alert
 * octets are delivered to the peer as ordinary stream data (measured on
 * 6.12: sendmsg = 2, peer recv = 2 bytes "01 00").  That is exactly why
 * close_connection() gates this call on IsTLSRaw(): the function reports what
 * the kernel did, and only the caller knows whether the fd really carries a
 * kernel TLS record layer.  A TCP socket with no ULP does refuse. */
static void test_close_notify_without_ulp(void)
{
  int sv[2];
  int tcp;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    printf("FAILED: socketpair: %s\n", strerror(errno));
    exit(1);
  }
  /* the cmsg is ignored, the 2 bytes go out: "sent" is the honest answer */
  assert(tls_ktls_send_close_notify(sv[0]) == 1);
  close(sv[0]);
  close(sv[1]);

  /* an unconnected TCP socket rejects the send outright */
  tcp = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp < 0) {
    printf("FAILED: socket: %s\n", strerror(errno));
    exit(1);
  }
  assert(tls_ktls_send_close_notify(tcp) == 0);
  close(tcp);

  /* and a descriptor that is not a socket at all */
  assert(tls_ktls_send_close_notify(-1) == 0);

  printf("Passed: close_notify reports what the kernel did, never aborts\n");
}

/* --- D: platform support --------------------------------------------------- */

static void test_supported(void)
{
#if defined(__linux__)
  assert(tls_ktls_supported() == 1);
#else
  assert(tls_ktls_supported() == 0 || tls_ktls_supported() == 1);
#endif
  printf("Passed: platform support reported (%d)\n", tls_ktls_supported());
}

int
main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  test_classify();
  test_recv_socketpair();
  test_recv_bad_fd();
  test_close_notify_without_ulp();
  test_supported();

  printf("All tls_ktls tests passed.\n");
  return 0;
}
