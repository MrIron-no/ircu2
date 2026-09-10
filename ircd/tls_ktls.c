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
#include "ircd_log.h"
#include "s_debug.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/* Platform gating.  Both supported kernels expose the record type of an
 * inbound record, and let an outbound record's type be chosen, through an
 * ancillary message on the socket -- but at different levels, with different
 * cmsg types and different payloads.  Everything platform-specific is reduced
 * to the four macros below plus ktls_cmsg_record_type(); if a platform does
 * not have kernel TLS at all, TLS_KTLS_SUPPORTED stays undefined and this
 * module degrades to plain recv() with no record visibility. */
#if defined(__linux__)

#include <sys/socket.h>
#include <linux/tls.h>

#ifdef SOL_TLS
#define TLS_KTLS_SUPPORTED  1
#define TLS_KTLS_CMSG_LEVEL SOL_TLS
#define TLS_KTLS_CMSG_GET   TLS_GET_RECORD_TYPE
#define TLS_KTLS_CMSG_SET   TLS_SET_RECORD_TYPE
#endif

#elif defined(__FreeBSD__)

#include <sys/socket.h>
#include <netinet/in.h>         /* IPPROTO_TCP */
#include <netinet/tcp.h>        /* TLS_GET_RECORD, TLS_SET_RECORD_TYPE */
#include <sys/ktls.h>           /* struct tls_get_record */

#ifdef TLS_GET_RECORD
#define TLS_KTLS_SUPPORTED  1
#define TLS_KTLS_CMSG_LEVEL IPPROTO_TCP
#define TLS_KTLS_CMSG_GET   TLS_GET_RECORD
#define TLS_KTLS_CMSG_SET   TLS_SET_RECORD_TYPE
#endif

#else

#include <sys/socket.h>

#endif

/* Not every platform has these; where they are missing the daemon's sockets
 * are already non-blocking and SIGPIPE is already ignored, so zero is safe. */
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/** TLS record type: alert (RFC 8446 s5.1). */
#define TLS_RECORD_ALERT        21
/** TLS record type: application data (RFC 8446 s5.1). */
#define TLS_RECORD_APPLICATION  23

/** Alert level: warning (RFC 8446 s6). */
#define TLS_ALERT_LEVEL_WARNING  1
/** Alert description: close_notify (RFC 8446 s6.1). */
#define TLS_ALERT_CLOSE_NOTIFY   0

/** Size of the ancillary-data buffer for one record-type cmsg.  A fixed 64
 * bytes, aligned by the union, is comfortably more than any of these carry
 * (one octet on Linux, a struct tls_get_record on FreeBSD) and keeps the
 * buffer off the heap on a per-read path. */
union tls_ktls_cbuf {
  struct cmsghdr h;             /**< forces cmsg alignment */
  unsigned char b[64];          /**< the storage itself */
};

#ifdef TLS_KTLS_SUPPORTED
/** Extract the TLS record type carried by a record-type control message.
 * @param[in] cm Control message already matched on level and type.
 * @return The TLS record type, or -1 if the message is too short to hold one.
 */
static int ktls_cmsg_record_type(const struct cmsghdr *cm)
{
#if defined(__FreeBSD__)
  struct tls_get_record tgr;

  if (cm->cmsg_len < CMSG_LEN(sizeof(tgr)))
    return -1;
  memcpy(&tgr, CMSG_DATA(cm), sizeof(tgr));
  return tgr.tls_type;
#else
  unsigned char type;

  if (cm->cmsg_len < CMSG_LEN(sizeof(type)))
    return -1;
  memcpy(&type, CMSG_DATA(cm), sizeof(type));
  return type;
#endif
}
#endif /* TLS_KTLS_SUPPORTED */

/** Classify a non-application record read from a kernel TLS socket.
 * @param[in] record_type TLS record type reported by the kernel.
 * @param[in] payload Record payload.
 * @param[in] len Length of \a payload in bytes.
 * @return How the caller should treat the record.
 */
enum tls_ktls_record tls_ktls_classify(int record_type,
                                       const unsigned char *payload, size_t len)
{
  /* Raw mode has no TLS library behind the socket, so the only record it can
   * act on is application data -- and the only other record it can make sense
   * of is the orderly close.  A KeyUpdate would need a rekey we cannot
   * perform, a renegotiation likewise, and a fatal alert is fatal by
   * definition: all of them end the connection rather than being ignored,
   * because ignoring a record we cannot process leaves the two sides
   * disagreeing about the key schedule. */
  if (record_type == TLS_RECORD_APPLICATION)
    return TLS_KTLS_DATA;

  if (record_type == TLS_RECORD_ALERT
      && payload && len >= 2
      && payload[0] == TLS_ALERT_LEVEL_WARNING
      && payload[1] == TLS_ALERT_CLOSE_NOTIFY)
    return TLS_KTLS_CLOSE_NOTIFY;

  return TLS_KTLS_FATAL;
}

/** Read application data from a kernel TLS socket.
 *
 * The read must go through recvmsg() with a control buffer: the kernel reports
 * a non-application record's type only as ancillary data, and a plain read()
 * with such a record pending fails EIO *without consuming it*, which would
 * wedge the connection in a readable-event loop.
 *
 * @param[in] fd Socket to read from.
 * @param[out] buf Buffer for the data read.
 * @param[in] length Size of \a buf in bytes.
 * @param[out] count_out Receives the number of bytes read.
 * @param[out] closed_out Receives non-zero if the peer sent close_notify.
 * @return I/O result of the read.
 */
IOResult tls_ktls_recv(int fd, char *buf, unsigned int length,
                       unsigned int *count_out, int *closed_out)
{
  ssize_t n;
#ifdef TLS_KTLS_SUPPORTED
  struct msghdr msg;
  struct iovec iov;
  union tls_ktls_cbuf cbuf;
  struct cmsghdr *cm;
  int record_type = -1;
#endif

  assert(0 != buf);
  assert(0 != count_out);
  assert(0 != closed_out);

  *count_out = 0;
  *closed_out = 0;

#ifdef TLS_KTLS_SUPPORTED
  memset(&msg, 0, sizeof(msg));
  memset(&cbuf, 0, sizeof(cbuf));
  iov.iov_base = buf;
  iov.iov_len = length;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf.b;
  msg.msg_controllen = sizeof(cbuf.b);

  n = recvmsg(fd, &msg, MSG_DONTWAIT);
  if (n < 0)
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
           ? IO_BLOCKED : IO_FAILURE;

  /* Control data that did not fit is a record we cannot classify.  Treating
   * it as data would hand a raw alert or handshake record to the parser. */
  if (msg.msg_flags & MSG_CTRUNC) {
    Debug((DEBUG_ERROR, "kTLS fd %d: truncated record-type control data", fd));
    *closed_out = 1;
    errno = EPROTO;
    return IO_FAILURE;
  }

  for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
    if (cm->cmsg_level == TLS_KTLS_CMSG_LEVEL
        && cm->cmsg_type == TLS_KTLS_CMSG_GET)
      record_type = ktls_cmsg_record_type(cm);

  /* No record-type cmsg at all: the socket carries no TLS ULP (or the kernel
   * tags only non-application records).  Plain bytes, plain EOF. */
  if (record_type >= 0) {
    switch (tls_ktls_classify(record_type, (const unsigned char *)buf,
                              (size_t)n)) {
    case TLS_KTLS_DATA:
      break;
    case TLS_KTLS_CLOSE_NOTIFY:
      /* Orderly shutdown.  The alert bytes are in buf and are not data. */
      *closed_out = 1;
      return IO_SUCCESS;
    default:
      Debug((DEBUG_ERROR, "kTLS fd %d: unhandled record type %d", fd,
             record_type));
      *closed_out = 1;
      errno = EPROTO;
      return IO_FAILURE;
    }
  }
#else
  n = recv(fd, buf, length, MSG_DONTWAIT);
  if (n < 0)
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
           ? IO_BLOCKED : IO_FAILURE;
#endif

  if (n == 0) {
    *closed_out = 1;
    return IO_SUCCESS;
  }
  *count_out = (unsigned int)n;
  return IO_SUCCESS;
}

/** Send a close_notify alert on a kernel TLS socket.
 *
 * Best effort by design: this runs from close_connection(), which must go
 * through whatever the kernel says.  A socket with no TLS ULP, a peer that
 * already reset, or a platform without kernel TLS all simply mean "not sent".
 *
 * @param[in] fd Socket to send on.
 * @return Non-zero if the alert was sent, zero if it was not.
 */
int tls_ktls_send_close_notify(int fd)
{
#ifdef TLS_KTLS_SUPPORTED
  static const unsigned char alert[2] =
    { TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY };
  struct msghdr msg;
  struct iovec iov;
  union tls_ktls_cbuf cbuf;
  struct cmsghdr *cm;
  unsigned char type = TLS_RECORD_ALERT;
  ssize_t n;

  memset(&msg, 0, sizeof(msg));
  memset(&cbuf, 0, sizeof(cbuf));
  iov.iov_base = (void *)alert;
  iov.iov_len = sizeof(alert);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf.b;
  msg.msg_controllen = CMSG_SPACE(sizeof(type));

  cm = CMSG_FIRSTHDR(&msg);
  cm->cmsg_level = TLS_KTLS_CMSG_LEVEL;
  cm->cmsg_type = TLS_KTLS_CMSG_SET;
  cm->cmsg_len = CMSG_LEN(sizeof(type));
  memcpy(CMSG_DATA(cm), &type, sizeof(type));
  msg.msg_controllen = cm->cmsg_len;

  /* Never block and never take a SIGPIPE on a socket we are about to close. */
  n = sendmsg(fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (n != (ssize_t)sizeof(alert)) {
    Debug((DEBUG_DEBUG, "kTLS fd %d: close_notify not sent (%d)", fd,
           n < 0 ? errno : 0));
    return 0;
  }
  return 1;
#else
  (void)fd;
  return 0;
#endif
}

/** Test whether this build has kernel TLS support.
 * @return Non-zero when built with SOL_TLS support.
 */
int tls_ktls_supported(void)
{
#ifdef TLS_KTLS_SUPPORTED
  return 1;
#else
  return 0;
#endif
}
