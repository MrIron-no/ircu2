/*
 * IRC - Internet Relay Chat, ircd/tls_ktls.c
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
 */
#include "config.h"

#include "tls_ktls.h"

/** Classify a non-application record read from a kernel TLS socket.
 * @param[in] record_type TLS record type reported by the kernel.
 * @param[in] payload Record payload.
 * @param[in] len Length of \a payload in bytes.
 * @return How the caller should treat the record.
 */
enum tls_ktls_record tls_ktls_classify(int record_type, const unsigned char *payload, size_t len)
{
  (void)record_type;
  (void)payload;
  (void)len;
  return TLS_KTLS_FATAL;
}

/** Read application data from a kernel TLS socket.
 * @param[in] fd Socket to read from.
 * @param[out] buf Buffer for the data read.
 * @param[in] length Size of \a buf in bytes.
 * @param[out] count_out Receives the number of bytes read.
 * @param[out] closed_out Receives non-zero if the peer sent close_notify.
 * @return I/O result of the read.
 */
IOResult tls_ktls_recv(int fd, char *buf, unsigned int length, unsigned int *count_out, int *closed_out)
{
  (void)fd;
  (void)buf;
  (void)length;
  (void)count_out;
  (void)closed_out;
  return IO_FAILURE;
}

/** Send a close_notify alert on a kernel TLS socket.
 * @param[in] fd Socket to send on.
 * @return Non-zero if the alert was sent, zero if it was not.
 */
int tls_ktls_send_close_notify(int fd)
{
  (void)fd;
  return 0;
}

/** Test whether this build has kernel TLS support.
 * @return Non-zero when built with SOL_TLS support.
 */
int tls_ktls_supported(void)
{
  return 0;
}
