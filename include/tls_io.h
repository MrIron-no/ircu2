/*
 * IRC - Internet Relay Chat, include/tls_io.h
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
 * @brief Core TLS I/O orchestration shared by all backends.
 *
 * This module owns the mapping from a connection's I/O state to its socket
 * event interest.  TLS breaks the plaintext assumption that "readable = want
 * to read, writable = want to send": a TLS write can be blocked waiting to
 * read the socket and vice versa (renegotiation, TLS1.3 KeyUpdate, a partial
 * record).  Rather than sprinkle special cases through the event loop, the
 * desired interest is computed from state in exactly one place here, so the
 * socket interest can never drift out of sync with what the TLS layer needs.
 */
#ifndef INCLUDED_tls_io_h
#define INCLUDED_tls_io_h

struct Client;

/** Non-zero if the connection currently wants writable events.
 *
 * The plaintext rule is "there is queued output or a /LIST in progress".  TLS
 * overrides it: a write blocked waiting to read must NOT assert writable (the
 * level-triggered writable event would spin), and a read blocked waiting to
 * write must assert it even with an empty send queue.
 */
int tls_want_writable(struct Client *cptr);

/** Full socket event interest mask (SOCK_EVENT_*) the connection should hold,
 * accounting for TLS cross-direction blocking.  Used by the unified event
 * driver; readable is always wanted for a live connection. */
unsigned int tls_desired_events(struct Client *cptr);

#endif /* INCLUDED_tls_io_h */
