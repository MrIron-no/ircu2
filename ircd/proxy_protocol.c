/*
 * IRC - Internet Relay Chat, ircd/proxy_protocol.c
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
 * @brief HAProxy PROXY protocol header parser.
 *
 * Two wire formats are accepted at the very start of a connection:
 *
 * v1 (text): a single line of at most PROXY_V1_MAX bytes including CRLF,
 *   "PROXY <TCP4|TCP6> <src> <dst> <sport> <dport>\r\n", fields separated
 *   by exactly one space.  <src> must be a plain address of the family
 *   named by the protocol; ports are decimal 0..65535.  "PROXY UNKNOWN"
 *   and any other shape are rejected.
 *
 * v2 (binary): the 12-byte signature "\r\n\r\n\0\r\nQUIT\n", then
 *   ver/cmd (high nibble version 2; low nibble 0 LOCAL, 1 PROXY),
 *   fam/proto (high nibble 0 UNSPEC, 1 INET, 2 INET6, 3 UNIX; low nibble
 *   0 UNSPEC, 1 STREAM, 2 DGRAM), then a big-endian 16-bit length of the
 *   address block that follows.  LOCAL ignores the address block.  PROXY
 *   requires STREAM over INET (src addr at 16, src port at 24) or INET6
 *   (src addr at 16, src port at 48).  TLVs after the addresses are
 *   skipped, never inspected.  Headers longer than PROXY_HDR_MAX are
 *   rejected.
 *
 * The parser is fed everything received so far and returns NEED_MORE
 * until a decision can be made; the answer never changes as more bytes
 * of the same header arrive.
 */
#include "config.h"

#include "proxy_protocol.h"
#include "ircd_string.h"
#include "res.h"

#include <string.h>

/** Binary v2 signature. */
static const unsigned char proxy_v2_sig[12] = {
  '\r', '\n', '\r', '\n', '\0', '\r', '\n', 'Q', 'U', 'I', 'T', '\n'
};

/** Text v1 prefix. */
static const unsigned char proxy_v1_prefix[6] = {
  'P', 'R', 'O', 'X', 'Y', ' '
};

/** Parse a decimal port of 1-5 digits, at most 65535.
 * @param[in] str NUL-terminated field.
 * @param[out] port Receives the port in host order.
 * @return Non-zero on success.
 */
static int proxy_parse_port(const char *str, unsigned short *port)
{
  unsigned int val = 0;
  unsigned int ii;

  for (ii = 0; str[ii]; ii++) {
    if (str[ii] < '0' || str[ii] > '9' || ii >= 5)
      return 0;
    val = val * 10 + (str[ii] - '0');
  }
  if (ii == 0 || val > 65535)
    return 0;
  *port = (unsigned short)val;
  return 1;
}

/** Parse a v1 (text) header.  \a buf starts with "PROXY ". */
static enum ProxyParseResult
proxy_parse_v1(const unsigned char *buf, unsigned int len,
               struct ProxyHeader *out)
{
  char line[PROXY_V1_MAX + 1];
  char *fields[6];
  unsigned int lim = len < PROXY_V1_MAX ? len : PROXY_V1_MAX;
  unsigned int linelen, ii, start, count;
  unsigned short sport, dport;
  unsigned char bits;
  int is_tcp4;

  for (linelen = 0; linelen + 1 < lim; linelen++)
    if (buf[linelen] == '\r' && buf[linelen + 1] == '\n')
      break;
  if (linelen + 1 >= lim)
    return len >= PROXY_V1_MAX ? PROXY_PARSE_INVALID : PROXY_PARSE_NEED_MORE;

  memcpy(line, buf, linelen);
  line[linelen] = '\0';

  /* Split on single spaces into exactly six non-empty fields. */
  for (ii = start = count = 0; ii <= linelen; ii++) {
    if (ii < linelen && line[ii] == '\0')
      return PROXY_PARSE_INVALID;
    if (ii < linelen && line[ii] != ' ')
      continue;
    if (ii == start || count == 6)
      return PROXY_PARSE_INVALID;
    line[ii] = '\0';
    fields[count++] = line + start;
    start = ii + 1;
  }
  if (count != 6)
    return PROXY_PARSE_INVALID;

  if (!strcmp(fields[1], "TCP4"))
    is_tcp4 = 1;
  else if (!strcmp(fields[1], "TCP6"))
    is_tcp4 = 0;
  else
    return PROXY_PARSE_INVALID;

  if (strchr(fields[2], '/') || strchr(fields[2], '*'))
    return PROXY_PARSE_INVALID;
  if (!ipmask_parse(fields[2], &out->src, &bits))
    return PROXY_PARSE_INVALID;
  if (is_tcp4 ? !irc_in_addr_is_ipv4(&out->src)
              : irc_in_addr_is_ipv4(&out->src))
    return PROXY_PARSE_INVALID;

  if (!proxy_parse_port(fields[4], &sport)
      || !proxy_parse_port(fields[5], &dport))
    return PROXY_PARSE_INVALID;

  out->cmd = PROXY_CMD_PROXY;
  out->src_port = sport;
  out->consumed = linelen + 2;
  return PROXY_PARSE_OK;
}

/** Parse a v2 (binary) header.  \a buf starts with the v2 signature. */
static enum ProxyParseResult
proxy_parse_v2(const unsigned char *buf, unsigned int len,
               struct ProxyHeader *out)
{
  unsigned int ver, cmd, family, proto, addrlen;

  if (len < PROXY_V2_HDR_LEN)
    return PROXY_PARSE_NEED_MORE;

  ver = buf[12] >> 4;
  cmd = buf[12] & 0x0f;
  family = buf[13] >> 4;
  proto = buf[13] & 0x0f;
  addrlen = ((unsigned int)buf[14] << 8) | buf[15];

  if (ver != 2 || cmd > 1)
    return PROXY_PARSE_INVALID;
  if (PROXY_V2_HDR_LEN + addrlen > PROXY_HDR_MAX)
    return PROXY_PARSE_INVALID;
  if (len < PROXY_V2_HDR_LEN + addrlen)
    return PROXY_PARSE_NEED_MORE;

  out->consumed = PROXY_V2_HDR_LEN + addrlen;

  if (cmd == 0) {
    out->cmd = PROXY_CMD_LOCAL;
    return PROXY_PARSE_OK;
  }

  if (proto != 1)                       /* STREAM */
    return PROXY_PARSE_INVALID;

  if (family == 1) {                    /* INET */
    if (addrlen < 12)
      return PROXY_PARSE_INVALID;
    memset(&out->src, 0, sizeof out->src);
    out->src.in6_16[5] = 0xffff;
    memcpy(&out->src.in6_16[6], buf + 16, 4);
    out->src_port = (unsigned short)((buf[24] << 8) | buf[25]);
  } else if (family == 2) {             /* INET6 */
    if (addrlen < 36)
      return PROXY_PARSE_INVALID;
    memcpy(&out->src, buf + 16, 16);
    out->src_port = (unsigned short)((buf[48] << 8) | buf[49]);
  } else                                /* UNSPEC, UNIX, unknown */
    return PROXY_PARSE_INVALID;

  out->cmd = PROXY_CMD_PROXY;
  return PROXY_PARSE_OK;
}

/** Parse a PROXY protocol header from the start of a connection.
 * @param[in] buf Everything received so far.
 * @param[in] len Number of bytes in \a buf.
 * @param[out] out Receives the parsed header on PROXY_PARSE_OK.
 * @return PROXY_PARSE_OK, PROXY_PARSE_INVALID, or PROXY_PARSE_NEED_MORE
 *   when \a buf is a valid prefix of a header that is not yet complete.
 */
enum ProxyParseResult
proxy_protocol_parse(const unsigned char *buf, unsigned int len,
                     struct ProxyHeader *out)
{
  unsigned int n;

  if (len == 0)
    return PROXY_PARSE_NEED_MORE;

  n = len < sizeof proxy_v2_sig ? len : sizeof proxy_v2_sig;
  if (buf[0] == proxy_v2_sig[0]) {
    if (memcmp(buf, proxy_v2_sig, n))
      return PROXY_PARSE_INVALID;
    if (len < sizeof proxy_v2_sig)
      return PROXY_PARSE_NEED_MORE;
    return proxy_parse_v2(buf, len, out);
  }

  n = len < sizeof proxy_v1_prefix ? len : sizeof proxy_v1_prefix;
  if (memcmp(buf, proxy_v1_prefix, n))
    return PROXY_PARSE_INVALID;
  if (len < sizeof proxy_v1_prefix)
    return PROXY_PARSE_NEED_MORE;
  return proxy_parse_v1(buf, len, out);
}
