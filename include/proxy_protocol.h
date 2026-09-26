/*
 * IRC - Internet Relay Chat, include/proxy_protocol.h
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
 * @brief HAProxy PROXY protocol (v1 text / v2 binary) header parsing.
 */
#ifndef INCLUDED_proxy_protocol_h
#define INCLUDED_proxy_protocol_h

#include "ircd_tls.h"
#include "res.h"

struct Client;

#define PROXY_HDR_MAX      1024   /* peek/consume cap, bytes */
#define PROXY_V1_MAX       107    /* longest v1 line incl. CRLF */
#define PROXY_V2_HDR_LEN   16     /* signature(12)+ver/cmd(1)+fam/proto(1)+len(2) */
#define PROXY_HEADER_TIMEOUT TLS_HANDSHAKE_TIMEOUT  /* seconds; include ircd_tls.h */

enum ProxyParseResult { PROXY_PARSE_NEED_MORE, PROXY_PARSE_INVALID, PROXY_PARSE_OK };
enum ProxyCommand     { PROXY_CMD_LOCAL, PROXY_CMD_PROXY };

struct ProxyHeader {
  enum ProxyCommand   cmd;
  struct irc_in_addr  src;       /* valid only when cmd == PROXY_CMD_PROXY */
  unsigned short      src_port;  /* host order; valid only when cmd == PROXY_CMD_PROXY */
  unsigned int        consumed;  /* total header length in bytes */
};

extern enum ProxyParseResult proxy_protocol_parse(const unsigned char *buf, unsigned int len, struct ProxyHeader *out);
extern int proxy_protocol_read(struct Client *cptr, struct ProxyHeader *out);

#endif /* INCLUDED_proxy_protocol_h */
