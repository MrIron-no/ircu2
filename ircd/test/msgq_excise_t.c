/* msgq_excise_t.c - unit test for identity-based removal of a drained
 * TLS partial-write remainder (msgq_excise()).
 *
 * Regression for the send-path finding where a con_rexmit remainder that
 * finished draining was removed from the sendq by byte count (via
 * msgq_delete()) instead of by identity.  msgq_delete() deletes in
 * (partial-normal, prio, normal) order, so a priority message enqueued while
 * the socket was blocked would be deleted in place of the drained normal
 * message -- re-sending the normal message's tail as duplicate bytes and
 * dropping the priority message.  msgq_excise() removes the exact message the
 * remainder points into, regardless of what jumped ahead of it.
 */

#include "client.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "msgq.h"

#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

extern struct Client me;

/* --- stubs for symbols pulled in by msgq.o that these tests never reach --- */
int feature_bool(enum Feature feat) { (void)feat; return 0; }
/* Large enough for FEAT_BUFFERPOOL so msgq_alloc() actually allocates. */
int feature_int(enum Feature feat) { (void)feat; return 1 << 20; }
void flush_connections(struct Client *cptr) { (void)cptr; }
void kill_highest_sendq(int servers_too) { (void)servers_too; }
int send_reply(struct Client *to, int reply, ...) { (void)to; (void)reply; return 0; }
void server_panic(const char *message) { (void)message; }
const char *visible_username(const struct Client *cptr) { (void)cptr; return ""; }

/** Build a queued MsgBuf carrying \a text (msgq_make appends CRLF). */
static struct MsgBuf *mk(const char *text)
{
  return msgq_make(&me, "%s", text);
}

/** Map \a mq and return the base pointer of segment \a want, or NULL. */
static const char *seg_base(struct MsgQ *mq, int want, int *n_out)
{
  struct iovec iov[16];
  unsigned int len = 0;
  int n = msgq_mapiov(mq, iov, sizeof(iov) / sizeof(iov[0]), &len);

  if (n_out)
    *n_out = n;
  return (want >= 0 && want < n) ? (const char *)iov[want].iov_base : 0;
}

/** True if the first mapped segment of \a mq begins with \a text. */
static int first_is(struct MsgQ *mq, const char *text)
{
  int n;
  const char *base = seg_base(mq, 0, &n);

  return n >= 1 && base && !strncmp(base, text, strlen(text));
}

/* A whole normal message is deferred (con_rexmit), a priority message is
 * enqueued while the socket is blocked, then the normal message finishes
 * draining and is excised.  The priority message must survive untouched. */
static void
test_excise_normal_keeps_prio(void)
{
  struct MsgQ mq;
  const char *base;
  unsigned int len_norm, len_ping;
  int n;

  msgq_init(&mq);

  msgq_add(&mq, mk("NORMALMSG"), 0);      /* normal message, sent == 0 */
  len_norm = mq.length;

  /* con_rexmit captures the normal message's pointer via msgq_mapiov,
   * exactly as ircd_tls_sendv does, before any priority message exists. */
  base = seg_base(&mq, 0, &n);
  assert(n == 1);

  msgq_add(&mq, mk("PING"), 1);           /* prio jumps ahead while blocked */
  len_ping = mq.length - len_norm;
  assert(mq.count == 2);

  msgq_excise(&mq, base);                  /* finished draining -> remove it */

  assert(mq.count == 1);                   /* only the PING remains */
  assert(mq.length == len_ping);
  assert(first_is(&mq, "PING"));           /* PING never deleted, still queued */

  MsgQClear(&mq);
  printf("Passed: excise removes drained normal msg, keeps priority msg\n");
}

/* con_rexmit points into the MIDDLE of the message (a multi-partial drain
 * advanced it); excise must still match by buffer containment. */
static void
test_excise_matches_mid_message(void)
{
  struct MsgQ mq;
  const char *base;
  int n;

  msgq_init(&mq);
  msgq_add(&mq, mk("A-LONGER-NORMAL-MESSAGE"), 0);

  base = seg_base(&mq, 0, &n);
  assert(n == 1 && base);

  msgq_add(&mq, mk("PING"), 1);

  msgq_excise(&mq, base + 7);               /* mid-message pointer */

  assert(mq.count == 1);
  assert(first_is(&mq, "PING"));

  MsgQClear(&mq);
  printf("Passed: excise matches a mid-message con_rexmit pointer\n");
}

/* con_rexmit can also point into a priority message; excise it from the
 * priority queue while leaving the normal message queued. */
static void
test_excise_prio_keeps_normal(void)
{
  struct MsgQ mq;
  struct iovec iov[4];
  const char *ping_base;
  unsigned int len = 0;
  int n;

  msgq_init(&mq);
  msgq_add(&mq, mk("NORMALMSG"), 0);
  msgq_add(&mq, mk("PINGPRIO"), 1);

  /* mapiov order is (partial-normal, prio, normal); with no partial-normal
   * head the priority message is mapped first. */
  n = msgq_mapiov(&mq, iov, 4, &len);
  assert(n == 2);
  ping_base = iov[0].iov_base;
  assert(!strncmp(ping_base, "PINGPRIO", 8));

  msgq_excise(&mq, ping_base);

  assert(mq.count == 1);
  assert(first_is(&mq, "NORMALMSG"));

  MsgQClear(&mq);
  printf("Passed: excise removes a priority msg, keeps normal msg\n");
}

/* With no priority message present, excise simply removes the head. */
static void
test_excise_single_normal(void)
{
  struct MsgQ mq;
  const char *base;
  int n;

  msgq_init(&mq);
  msgq_add(&mq, mk("ONLYMSG"), 0);
  base = seg_base(&mq, 0, &n);
  assert(n == 1 && base);

  msgq_excise(&mq, base);

  assert(mq.count == 0);
  assert(mq.length == 0);

  printf("Passed: excise removes a lone normal msg\n");
}

/* --- msgq_append_raw(): binary payload append for the hot reload loader --- */

/** Fill \a buf with a deterministic pseudo-random byte stream.
 * The generator is a plain LCG so the expectation is reproducible; NUL bytes
 * and CRLF pairs are planted explicitly so the append path is exercised with
 * exactly the byte values that a text-oriented queue would mangle. */
static void fill_pseudo_random(unsigned char *buf, unsigned int len)
{
  unsigned long state = 0x1234abcdUL;
  unsigned int i;

  for (i = 0; i < len; i++) {
    state = state * 1103515245UL + 12345UL;
    buf[i] = (unsigned char)((state >> 16) & 0xff);
  }

  /* Plant NULs and CRLF sequences at known offsets. */
  for (i = 0; i + 3 < len; i += 337) {
    buf[i] = '\0';
    buf[i + 1] = '\r';
    buf[i + 2] = '\n';
    buf[i + 3] = '\0';
  }
}

/* 5000 bytes of binary data appended to an empty queue must come back out of
 * msgq_mapiov() byte for byte, however many MsgBufs it was split across. */
static void
test_append_raw_roundtrip(void)
{
  struct MsgQ mq;
  struct iovec iov[16];
  unsigned char in[5000];
  unsigned char out[sizeof(in)];
  unsigned int mapped = 0;
  unsigned int total = 0;
  int n;
  int i;

  fill_pseudo_random(in, sizeof(in));

  msgq_init(&mq);
  assert(msgq_append_raw(&mq, in, sizeof(in)));

  assert(MsgQLength(&mq) == sizeof(in));

  n = msgq_mapiov(&mq, iov, sizeof(iov) / sizeof(iov[0]), &mapped);
  assert(n > 0);
  assert(mapped == sizeof(in));

  for (i = 0; i < n; i++) {
    assert(total + iov[i].iov_len <= sizeof(out));
    memcpy(out + total, iov[i].iov_base, iov[i].iov_len);
    total += iov[i].iov_len;
  }
  assert(total == sizeof(in));
  assert(!memcmp(in, out, sizeof(in)));

  MsgQClear(&mq);
  printf("Passed: append_raw round-trips %u binary bytes through mapiov\n",
         (unsigned int)sizeof(in));
}

/* Larger than one pool bucket: the data must be split across several MsgBufs
 * and still map back out as the identical byte stream in the right order. */
static void
test_append_raw_spans_buckets(void)
{
  struct MsgQ mq;
  struct iovec iov[16];
  unsigned char in[20000];
  unsigned char out[sizeof(in)];
  unsigned int mapped = 0;
  unsigned int total = 0;
  int n;
  int i;

  fill_pseudo_random(in, sizeof(in));

  msgq_init(&mq);
  assert(msgq_append_raw(&mq, in, sizeof(in)));
  assert(MsgQLength(&mq) == sizeof(in));
  assert(MsgQCount(&mq) > 1);           /* it really did split */

  n = msgq_mapiov(&mq, iov, sizeof(iov) / sizeof(iov[0]), &mapped);
  assert(n > 1);
  assert(mapped == sizeof(in));

  for (i = 0; i < n; i++) {
    assert(total + iov[i].iov_len <= sizeof(out));
    memcpy(out + total, iov[i].iov_base, iov[i].iov_len);
    total += iov[i].iov_len;
  }
  assert(total == sizeof(in));
  assert(!memcmp(in, out, sizeof(in)));

  MsgQClear(&mq);
  printf("Passed: append_raw splits %u bytes across buffers in order\n",
         (unsigned int)sizeof(in));
}

/* A zero length append must leave the queue exactly as it found it. */
static void
test_append_raw_empty_is_noop(void)
{
  struct MsgQ mq;

  msgq_init(&mq);
  assert(msgq_append_raw(&mq, "", 0));
  assert(MsgQLength(&mq) == 0);
  assert(MsgQCount(&mq) == 0);

  /* And it must not disturb data already queued either. */
  msgq_add(&mq, mk("QUEUED"), 0);
  assert(MsgQCount(&mq) == 1);
  assert(msgq_append_raw(&mq, "", 0));
  assert(MsgQCount(&mq) == 1);
  assert(first_is(&mq, "QUEUED"));

  MsgQClear(&mq);
  printf("Passed: append_raw of zero bytes is a no-op\n");
}

int
main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  test_excise_normal_keeps_prio();
  test_excise_matches_mid_message();
  test_excise_prio_keeps_normal();
  test_excise_single_normal();
  test_append_raw_roundtrip();
  test_append_raw_spans_buckets();
  test_append_raw_empty_is_noop();

  printf("All msgq tests passed.\n");
  return 0;
}
