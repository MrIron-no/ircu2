/*
 * IRC - Internet Relay Chat, ircd/tls_io.c
 * Copyright (C) 2026 UndernetIRC Coding Committee
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
 * @brief Core TLS I/O orchestration (socket-interest model).
 */
#include "config.h"

#include "tls_io.h"
#include "client.h"
#include "ircd_events.h"
#include "ircd_tls.h"
#include "msgq.h"

/** The base (plaintext) writable desire: queued output or an active /LIST. */
static int base_want_writable(struct Client *cptr)
{
  return MsgQLength(&cli_sendQ(cptr)) != 0 || cli_listing(cptr);
}

int tls_want_writable(struct Client *cptr)
{
  /* Called only for TLS connections (update_write() handles plaintext inline).
   * Starts from the same base rule as plaintext, then applies the TLS
   * cross-direction overrides — the single place that rule lives. */
  int want = base_want_writable(cptr);

  if (con_tls_want_wr(cli_connect(cptr)) == IRCD_TLS_WANT_READ)
    want = 0;                       /* a write waiting to read must not spin */
  if (con_tls_want_wr(cli_connect(cptr)) == IRCD_TLS_WANT_WRITE)
    want = 1;                       /* a write waiting to write needs writable */
  if (con_tls_want_rd(cli_connect(cptr)) == IRCD_TLS_WANT_WRITE)
    want = 1;                       /* a read waiting to write needs writable */
  return want;
}

unsigned int tls_desired_events(struct Client *cptr)
{
  unsigned int ev = SOCK_EVENT_READABLE;   /* always want application input */

  if (tls_want_writable(cptr))
    ev |= SOCK_EVENT_WRITABLE;
  return ev;
}
