/* proxy_protocol_t.c - unit test for the PROXY protocol v1/v2 header
 * parser (proxy_protocol_parse()) and the socket-driving reader
 * (proxy_protocol_read()).
 *
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
 */

#include "client.h"
#include "ircd_osdep.h"
#include "ircd_string.h"
#include "proxy_protocol.h"
#include "res.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

/* Socket helpers backing proxy_protocol_read() in the tests; they mirror
 * ircd/os_generic.c so the function runs against a real socketpair. */
static IOResult test_recv(int fd, char *buf, unsigned int length,
                          unsigned int *count_out, int flags)
{
  ssize_t res = recv(fd, buf, length, flags);

  if (res > 0) {
    *count_out = (unsigned int)res;
    return IO_SUCCESS;
  }
  *count_out = 0;
  if (res == 0) {
    errno = 0;
    return IO_FAILURE;
  }
  return (errno == EAGAIN || errno == EWOULDBLOCK) ? IO_BLOCKED : IO_FAILURE;
}

IOResult os_recv_nonb(int fd, char *buf, unsigned int length,
                      unsigned int *count_out)
{
  return test_recv(fd, buf, length, count_out, 0);
}

IOResult os_recv_peek_nonb(int fd, char *buf, unsigned int length,
                           unsigned int *count_out)
{
  return test_recv(fd, buf, length, count_out, MSG_PEEK);
}

static const char *res_name(enum ProxyParseResult r)
{
  switch (r) {
  case PROXY_PARSE_NEED_MORE: return "NEED_MORE";
  case PROXY_PARSE_INVALID:   return "INVALID";
  case PROXY_PARSE_OK:        return "OK";
  }
  return "?";
}

static void report(const char *name, int ok)
{
  if (ok)
    printf("PASS %s\n", name);
  else {
    printf("FAIL %s\n", name);
    failures++;
  }
}

/** Parse \a len bytes of \a buf and expect result \a want (non-OK). */
static void expect_res(const char *name, const unsigned char *buf,
                       unsigned int len, enum ProxyParseResult want)
{
  struct ProxyHeader hdr;
  enum ProxyParseResult r;

  memset(&hdr, 0, sizeof hdr);
  r = proxy_protocol_parse(buf, len, &hdr);
  if (r != want)
    printf("  %s: got %s, want %s\n", name, res_name(r), res_name(want));
  report(name, r == want);
}

/** Parse and expect OK / PROXY with the given address, port, consumed. */
static void expect_proxy(const char *name, const unsigned char *buf,
                         unsigned int len, const char *addr,
                         unsigned short port, unsigned int consumed)
{
  struct ProxyHeader hdr;
  enum ProxyParseResult r;
  const char *got = "";
  int ok;

  memset(&hdr, 0, sizeof hdr);
  r = proxy_protocol_parse(buf, len, &hdr);
  if (r == PROXY_PARSE_OK)
    got = ircd_ntoa(&hdr.src);
  ok = r == PROXY_PARSE_OK && hdr.cmd == PROXY_CMD_PROXY
    && !strcmp(got, addr) && hdr.src_port == port && hdr.consumed == consumed;
  if (!ok)
    printf("  %s: got %s cmd=%d addr=%s port=%u consumed=%u\n", name,
           res_name(r), (int)hdr.cmd, got, hdr.src_port, hdr.consumed);
  report(name, ok);
}

/** Parse and expect OK / LOCAL with \a consumed. */
static void expect_local(const char *name, const unsigned char *buf,
                         unsigned int len, unsigned int consumed)
{
  struct ProxyHeader hdr;
  enum ProxyParseResult r;
  int ok;

  memset(&hdr, 0, sizeof hdr);
  hdr.cmd = PROXY_CMD_PROXY;
  r = proxy_protocol_parse(buf, len, &hdr);
  ok = r == PROXY_PARSE_OK && hdr.cmd == PROXY_CMD_LOCAL
    && hdr.consumed == consumed;
  if (!ok)
    printf("  %s: got %s cmd=%d consumed=%u\n", name, res_name(r),
           (int)hdr.cmd, hdr.consumed);
  report(name, ok);
}

/** Expand a string literal to (buf, len) without its NUL terminator. */
#define S(str) ((const unsigned char *)(str)), (sizeof(str) - 1)

static const unsigned char v2sig[12] = {
  '\r', '\n', '\r', '\n', '\0', '\r', '\n', 'Q', 'U', 'I', 'T', '\n'
};

/** Build a v2 header into \a buf; returns total length (16 + addrlen). */
static unsigned int mk_v2(unsigned char *buf, unsigned char vercmd,
                          unsigned char famproto, unsigned int addrlen)
{
  memcpy(buf, v2sig, 12);
  buf[12] = vercmd;
  buf[13] = famproto;
  buf[14] = (addrlen >> 8) & 0xff;
  buf[15] = addrlen & 0xff;
  return 16 + addrlen;
}

/** v2 PROXY/INET/STREAM, src 203.0.113.50:51234 -> 10.0.0.1:6667;
 * any bytes beyond the 12-byte address block are TLV filler. */
static unsigned int mk_v2_inet(unsigned char *buf, unsigned int addrlen)
{
  unsigned int n = mk_v2(buf, 0x21, 0x11, addrlen);

  memset(buf + 16, 0xAB, addrlen);
  if (addrlen >= 12) {
    buf[16] = 203; buf[17] = 0; buf[18] = 113; buf[19] = 50;
    buf[20] = 10;  buf[21] = 0; buf[22] = 0;   buf[23] = 1;
    buf[24] = 51234 >> 8; buf[25] = 51234 & 0xff;
    buf[26] = 6667 >> 8;  buf[27] = 6667 & 0xff;
  }
  return n;
}

static void test_dispatch(void)
{
  expect_res("empty", (const unsigned char *)"", 0, PROXY_PARSE_NEED_MORE);
  expect_res("pro", S("PRO"), PROXY_PARSE_NEED_MORE);
  expect_res("prx", S("PRX"), PROXY_PARSE_INVALID);
  expect_res("nick", S("NICK foo\r\n"), PROXY_PARSE_INVALID);
  expect_res("v2_sig_prefix", S("\r\n\r\n"), PROXY_PARSE_NEED_MORE);
  expect_res("v2_sig_mismatch", S("\r\n\r\nX"), PROXY_PARSE_INVALID);
}

static void test_v1(void)
{
  static const char full[] = "PROXY TCP4 203.0.113.50 10.0.0.1 51234 6667\r\n";
  unsigned char big[108];

  expect_proxy("v1_tcp4", S(full), "203.0.113.50", 51234, 45);
  expect_proxy("v1_tcp6", S("PROXY TCP6 2001:db8::1 2001:db8::2 51234 6667\r\n"),
               "2001:db8::1", 51234, 47);
  expect_res("v1_family_mismatch", S("PROXY TCP4 2001:db8::1 10.0.0.1 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_tcp6_with_v4", S("PROXY TCP6 203.0.113.50 2001:db8::2 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_unknown", S("PROXY UNKNOWN\r\n"), PROXY_PARSE_INVALID);
  expect_res("v1_five_fields", S("PROXY TCP4 203.0.113.50 10.0.0.1 51234\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_seven_fields",
             S("PROXY TCP4 203.0.113.50 10.0.0.1 51234 6667 x\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_empty_field", S("PROXY TCP4  203.0.113.50 10.0.0.1 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_port_too_big",
             S("PROXY TCP4 203.0.113.50 10.0.0.1 70000 6667\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_port_nondigit",
             S("PROXY TCP4 203.0.113.50 10.0.0.1 51a34 6667\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_cidr_src", S("PROXY TCP4 203.0.113.0/24 10.0.0.1 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_wild_src", S("PROXY TCP4 203.0.113.* 10.0.0.1 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_bad_proto", S("PROXY UDP4 203.0.113.50 10.0.0.1 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_tcp4_unspec_src", S("PROXY TCP4 0.0.0.0 10.0.0.1 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_tcp6_unspec_src", S("PROXY TCP6 :: 2001:db8::2 1 2\r\n"),
             PROXY_PARSE_INVALID);
  expect_res("v1_partial", S("PROXY TCP4 203.0."), PROXY_PARSE_NEED_MORE);
  expect_proxy("v1_partial_then_full", S(full), "203.0.113.50", 51234, 45);

  memcpy(big, "PROXY ", 6);
  memset(big + 6, 'x', sizeof big - 6);
  expect_res("v1_108_no_crlf", big, sizeof big, PROXY_PARSE_INVALID);
  expect_res("v1_106_no_crlf", big, 106, PROXY_PARSE_NEED_MORE);
}

static void test_v2(void)
{
  unsigned char buf[PROXY_HDR_MAX + 64];
  unsigned int n;
  static const unsigned char v6src[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  };

  n = mk_v2_inet(buf, 12);
  expect_proxy("v2_inet", buf, n, "203.0.113.50", 51234, 28);
  expect_res("v2_15_bytes", buf, 15, PROXY_PARSE_NEED_MORE);
  expect_res("v2_20_of_28", buf, 20, PROXY_PARSE_NEED_MORE);
  expect_proxy("v2_all_28", buf, 28, "203.0.113.50", 51234, 28);

  n = mk_v2_inet(buf, 20);
  expect_proxy("v2_inet_tlv", buf, n, "203.0.113.50", 51234, 36);

  n = mk_v2(buf, 0x21, 0x21, 36);
  memset(buf + 16, 0, 36);
  memcpy(buf + 16, v6src, 16);
  buf[48] = 51234 >> 8; buf[49] = 51234 & 0xff;
  buf[50] = 6667 >> 8;  buf[51] = 6667 & 0xff;
  expect_proxy("v2_inet6", buf, n, "2001:db8::1", 51234, 52);

  n = mk_v2_inet(buf, 12);
  memset(buf + 16, 0, 4);
  expect_res("v2_inet_unspec_src", buf, n, PROXY_PARSE_INVALID);

  n = mk_v2(buf, 0x21, 0x21, 36);
  memset(buf + 16, 0, 36);
  buf[48] = 51234 >> 8; buf[49] = 51234 & 0xff;
  buf[50] = 6667 >> 8;  buf[51] = 6667 & 0xff;
  expect_res("v2_inet6_unspec_src", buf, n, PROXY_PARSE_INVALID);

  n = mk_v2_inet(buf, 12);
  buf[12] = 0x11;
  expect_res("v2_version_1", buf, n, PROXY_PARSE_INVALID);
  buf[12] = 0x22;
  expect_res("v2_cmd_2", buf, n, PROXY_PARSE_INVALID);
  buf[12] = 0x21;
  buf[13] = 0x01;
  expect_res("v2_proxy_unspec", buf, n, PROXY_PARSE_INVALID);
  buf[13] = 0x31;
  expect_res("v2_unix", buf, n, PROXY_PARSE_INVALID);
  buf[13] = 0x12;
  expect_res("v2_dgram", buf, n, PROXY_PARSE_INVALID);

  n = mk_v2_inet(buf, 8);
  expect_res("v2_inet_addrlen_8", buf, n, PROXY_PARSE_INVALID);

  n = mk_v2(buf, 0x21, 0x21, 20);
  memset(buf + 16, 0, 20);
  expect_res("v2_inet6_addrlen_20", buf, n, PROXY_PARSE_INVALID);

  mk_v2(buf, 0x21, 0x11, 1009);
  expect_res("v2_addrlen_1009", buf, 16, PROXY_PARSE_INVALID);

  n = mk_v2(buf, 0x20, 0x00, 0);
  expect_local("v2_local_unspec", buf, n, 16);

  n = mk_v2(buf, 0x20, 0x11, 12);
  memset(buf + 16, 0xEE, 12);
  expect_local("v2_local_garbage", buf, n, 28);
}

/** Every strict prefix of a complete, valid header must be NEED_MORE,
 * and trailing client bytes after the header must not change the result. */
static void test_prefixes(void)
{
  static const char v1[] = "PROXY TCP6 2001:db8::1 2001:db8::2 51234 6667\r\nNICK x\r\n";
  unsigned char buf[64];
  unsigned int n, ii;
  struct ProxyHeader hdr;
  int ok = 1;

  for (ii = 0; ii < 47; ii++)
    if (proxy_protocol_parse((const unsigned char *)v1, ii, &hdr)
        != PROXY_PARSE_NEED_MORE)
      ok = 0;
  report("v1_all_prefixes_need_more", ok);
  expect_proxy("v1_trailing_data", S(v1), "2001:db8::1", 51234, 47);

  n = mk_v2_inet(buf, 12);
  for (ok = 1, ii = 0; ii < n; ii++)
    if (proxy_protocol_parse(buf, ii, &hdr) != PROXY_PARSE_NEED_MORE)
      ok = 0;
  report("v2_all_prefixes_need_more", ok);
  memcpy(buf + n, "NICK x\r\n", 8);
  expect_proxy("v2_trailing_data", buf, n + 8, "203.0.113.50", 51234, 28);
}

/* ---- proxy_protocol_read() over a socketpair ---- */

/** A fake local client whose socket is one end of a socketpair. */
struct ReadFixture {
  struct Client cli;
  struct Connection con;
  int sv[2];
};

static int rf_open(struct ReadFixture *f)
{
  memset(f, 0, sizeof *f);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) < 0) {
    perror("socketpair");
    return 0;
  }
  if (fcntl(f->sv[0], F_SETFL, fcntl(f->sv[0], F_GETFL) | O_NONBLOCK) < 0) {
    perror("fcntl");
    return 0;
  }
  cli_connect(&f->cli) = &f->con;
  con_fd(&f->con) = f->sv[0];
  return 1;
}

static void rf_close(struct ReadFixture *f)
{
  close(f->sv[0]);
  if (f->sv[1] >= 0)
    close(f->sv[1]);
}

/** Write \a len bytes of \a buf to the peer end. */
static void rf_send(struct ReadFixture *f, const void *buf, unsigned int len)
{
  if (write(f->sv[1], buf, len) != (ssize_t)len)
    perror("write");
}

/** Return 1 if exactly \a len bytes equal to \a want are left unread on
 * the ircd end of the socket (drains them). */
static int rf_left(struct ReadFixture *f, const void *want, unsigned int len)
{
  char buf[2048];
  ssize_t got = recv(f->sv[0], buf, sizeof buf, MSG_DONTWAIT);

  if (got < 0)
    got = 0;
  if ((unsigned int)got != len || memcmp(buf, want, len)) {
    printf("  left %d byte(s), want %u\n", (int)got, len);
    return 0;
  }
  return 1;
}

/** Call proxy_protocol_read() and check its result and the stored prefix. */
static int rf_read(struct ReadFixture *f, struct ProxyHeader *hdr, int want,
                   size_t want_len)
{
  int r = proxy_protocol_read(&f->cli, hdr);

  if (r != want || f->con.con_ws_handshake_len != want_len) {
    printf("  read: got %d stored=%u, want %d stored=%u\n", r,
           (unsigned int)f->con.con_ws_handshake_len, want,
           (unsigned int)want_len);
    return 0;
  }
  return 1;
}

static int hdr_is(const struct ProxyHeader *hdr, const char *addr)
{
  const char *got = ircd_ntoa(&hdr->src);

  if (hdr->cmd != PROXY_CMD_PROXY || strcmp(got, addr)) {
    printf("  hdr: cmd=%d src=%s, want %s\n", (int)hdr->cmd, got, addr);
    return 0;
  }
  return 1;
}

static void test_read(void)
{
  static const char v1[] = "PROXY TCP4 203.0.113.50 10.0.0.1 51234 6667\r\n";
  struct ReadFixture f;
  struct ProxyHeader hdr;
  unsigned char buf[PROXY_HDR_MAX + 64];
  unsigned int n;
  int ok;

  /* v1 header and the first IRC line arrive together. */
  if (!rf_open(&f))
    return;
  rf_send(&f, v1, sizeof v1 - 1);
  rf_send(&f, "NICK a\r\n", 8);
  ok = rf_read(&f, &hdr, 1, 0) && hdr_is(&hdr, "203.0.113.50")
    && rf_left(&f, "NICK a\r\n", 8);
  report("read_v1_full_keeps_trailing", ok);
  rf_close(&f);

  /* v2 INET header plus 5 trailing bytes. */
  if (!rf_open(&f))
    return;
  n = mk_v2_inet(buf, 12);
  memcpy(buf + n, "ABCDE", 5);
  rf_send(&f, buf, n + 5);
  ok = rf_read(&f, &hdr, 1, 0) && hdr_is(&hdr, "203.0.113.50")
    && rf_left(&f, "ABCDE", 5);
  report("read_v2_full_keeps_trailing", ok);
  rf_close(&f);

  /* v1 split after 9 bytes: the partial prefix is consumed. */
  if (!rf_open(&f))
    return;
  rf_send(&f, v1, 9);
  ok = rf_read(&f, &hdr, 0, 9) && rf_left(&f, "", 0);
  rf_send(&f, v1 + 9, sizeof v1 - 1 - 9);
  rf_send(&f, "X", 1);
  ok = ok && rf_read(&f, &hdr, 1, 0) && hdr_is(&hdr, "203.0.113.50")
    && rf_left(&f, "X", 1);
  report("read_v1_split", ok);
  rf_close(&f);

  /* v2 split inside the 16-byte fixed prefix. */
  if (!rf_open(&f))
    return;
  n = mk_v2_inet(buf, 12);
  rf_send(&f, buf, 7);
  ok = rf_read(&f, &hdr, 0, 7) && rf_left(&f, "", 0);
  rf_send(&f, buf + 7, n - 7);
  ok = ok && rf_read(&f, &hdr, 1, 0) && hdr_is(&hdr, "203.0.113.50")
    && rf_left(&f, "", 0);
  report("read_v2_split_in_prefix", ok);
  rf_close(&f);

  /* Nothing sent yet. */
  if (!rf_open(&f))
    return;
  ok = rf_read(&f, &hdr, 0, 0);
  report("read_empty_blocks", ok);
  rf_close(&f);

  /* Not a PROXY header: rejected, and the bytes were only peeked. */
  if (!rf_open(&f))
    return;
  rf_send(&f, "NICK x\r\n", 8);
  ok = rf_read(&f, &hdr, -1, 0) && rf_left(&f, "NICK x\r\n", 8);
  report("read_invalid_only_peeked", ok);
  rf_close(&f);

  /* Peer closed without sending anything. */
  if (!rf_open(&f))
    return;
  close(f.sv[1]);
  f.sv[1] = -1;
  ok = rf_read(&f, &hdr, -1, 0);
  report("read_peer_closed", ok);
  rf_close(&f);

  /* 1024 bytes of v1 with no CRLF. */
  if (!rf_open(&f))
    return;
  memcpy(buf, "PROXY ", 6);
  memset(buf + 6, 'x', PROXY_HDR_MAX - 6);
  rf_send(&f, buf, PROXY_HDR_MAX);
  ok = rf_read(&f, &hdr, -1, 0);
  report("read_v1_oversize", ok);
  rf_close(&f);

  /* v2 claiming more than PROXY_HDR_MAX. */
  if (!rf_open(&f))
    return;
  mk_v2(buf, 0x21, 0x11, 1009);
  rf_send(&f, buf, 16);
  ok = rf_read(&f, &hdr, -1, 0);
  report("read_v2_addrlen_1009", ok);
  rf_close(&f);

  /* v2 with a 900-byte address block, arriving as 600 + 316 bytes. */
  if (!rf_open(&f))
    return;
  n = mk_v2_inet(buf, 900);
  memcpy(buf + n, "Z", 1);
  rf_send(&f, buf, 600);
  ok = rf_read(&f, &hdr, 0, 600) && rf_left(&f, "", 0);
  rf_send(&f, buf + 600, n - 600 + 1);
  ok = ok && rf_read(&f, &hdr, 1, 0) && hdr_is(&hdr, "203.0.113.50")
    && rf_left(&f, "Z", 1);
  report("read_v2_large_split", ok);
  rf_close(&f);
}

int
main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  test_dispatch();
  test_v1();
  test_v2();
  test_prefixes();
  test_read();

  if (failures) {
    printf("%d proxy_protocol test(s) FAILED.\n", failures);
    return 1;
  }
  printf("All proxy_protocol tests passed.\n");
  return 0;
}
