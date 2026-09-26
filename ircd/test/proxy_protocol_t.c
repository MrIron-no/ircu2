/* proxy_protocol_t.c - unit test for the PROXY protocol v1/v2 header
 * parser (proxy_protocol_parse()).
 *
 * Copyright (C) 2026 MrIron <mriron@undernet.org>
 */

#include "ircd_string.h"
#include "proxy_protocol.h"
#include "res.h"

#include <stdio.h>
#include <string.h>

static int failures;

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

int
main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  test_dispatch();
  test_v1();
  test_v2();
  test_prefixes();

  if (failures) {
    printf("%d proxy_protocol test(s) FAILED.\n", failures);
    return 1;
  }
  printf("All proxy_protocol tests passed.\n");
  return 0;
}
