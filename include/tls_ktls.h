/*
 * IRC - Internet Relay Chat, include/tls_ktls.h
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
 * @brief Raw kernel TLS record I/O.
 *
 * Once a TLS session has been offloaded to the kernel record layer, its
 * socket can be read and written without the TLS library: the kernel does
 * the record framing.  That is what lets a session survive a hot reload,
 * where the new image inherits the socket but not the library state.  The
 * functions here drive such a socket directly.
 */
#ifndef INCLUDED_tls_ktls_h
#define INCLUDED_tls_ktls_h

#ifndef INCLUDED_ircd_osdep_h
#include "ircd_osdep.h"         /* IOResult */
#endif

#ifndef INCLUDED_stddef_h
#include <stddef.h>             /* size_t */
#define INCLUDED_stddef_h
#endif

/** How a kernel TLS record should be treated by the caller. */
enum tls_ktls_record { TLS_KTLS_DATA, TLS_KTLS_CLOSE_NOTIFY, TLS_KTLS_FATAL };

/** Classify a non-application record read from a kernel TLS socket. */
enum tls_ktls_record tls_ktls_classify(int record_type, const unsigned char *payload, size_t len);
/** Read application data from a kernel TLS socket. */
IOResult tls_ktls_recv(int fd, char *buf, unsigned int length, unsigned int *count_out, int *closed_out);
/** Send a close_notify alert on a kernel TLS socket; 1 sent, 0 not sent. */
int tls_ktls_send_close_notify(int fd);   /* 1 sent, 0 not sent */
/** Return 1 when this build has kernel TLS (SOL_TLS) support. */
int tls_ktls_supported(void);             /* 1 when built with SOL_TLS support */

#endif /* INCLUDED_tls_ktls_h */
