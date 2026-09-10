/*
 * IRC - Internet Relay Chat, ircd/tls_io.c
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
 * @brief Core TLS I/O orchestration (socket-interest model).
 */
#include "config.h"

#include "tls_io.h"
#include "client.h"
#include "ircd_events.h"
#include "ircd_osdep.h"
#include "ircd_tls.h"
#include "msgq.h"
#include "ircd_string.h"
#include "tls_ktls.h"
#include <errno.h>
#include <stdio.h>
#include "ircd_snprintf.h"

#include <sys/uio.h>   /* struct iovec */

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

  /* raw kTLS: the kernel owns the record layer, so there is no cross-direction
   * blocking to model — a write is a plain socket write and a read a plain
   * recvmsg.  con_tls_want_rd/wr are whatever the pre-reload session last left
   * there and must be ignored outright: a stale WANT_READ would otherwise pin
   * writable interest off and park the send queue for good. */
  if (IsTLSRaw(cptr))
    return want;

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

/** Mark the socket dead and clear both blocked-direction markers, so
 * deliver_it()/read_packet() never fall back to the plaintext path and the
 * connection is reaped.  Split out of tls_io_fatal() for raw kTLS mode, which
 * has no library session to drop. */
static void tls_io_mark_dead(struct Client *cptr)
{
  struct Connection *con = cli_connect(cptr);

  SetFlag(cptr, FLAG_DEADSOCKET);
  con_tls_want_rd(con) = IRCD_TLS_WANT_NONE;
  con_tls_want_wr(con) = IRCD_TLS_WANT_NONE;
}

/** Core-owned teardown after a fatal backend I/O error: hard-drop the session,
 * then mark the connection dead.  Backends do no teardown of their own for the
 * read/write paths. */
static void tls_io_fatal(struct Client *cptr)
{
  tls_backend_drop(cptr);
  tls_io_mark_dead(cptr);
}

/** Record the direction a blocked write is waiting on, or tear the session
 * down on a fatal error — in one place. */
static void tls_io_note_write(struct Client *cptr, IOResult io,
                              enum ircd_tls_want want)
{
  if (io == IO_FAILURE)
    tls_io_fatal(cptr);
  else
    con_tls_want_wr(cli_connect(cptr)) =
      (io == IO_BLOCKED) ? want : IRCD_TLS_WANT_NONE;
}

IOResult tls_io_sendv(struct Client *cptr, struct MsgQ *buf,
                      unsigned int *count_in, unsigned int *count_out)
{
  struct iovec iov[512];
  struct Connection *con = cli_connect(cptr);
  enum ircd_tls_want want = IRCD_TLS_WANT_NONE;
  unsigned int written;
  int ii, count, made_progress = 0;
  IOResult io;

  *count_in = 0;
  *count_out = 0;

  /* raw kTLS: the kernel frames the records, so this is a plain writev on a
   * plain socket — same short-write semantics as plaintext.  Deliberately no
   * con_rexmit bookkeeping (that exists only because a TLS library can accept
   * part of a record and demand the identical pointer back) and no
   * con_tls_want_wr, which stays IRCD_TLS_WANT_NONE. */
  if (IsTLSRaw(cptr))
    return os_sendv_nonb(cli_fd(cptr), buf, count_in, count_out);

  if (con->con_rexmit)
  {
    /* con_rexmit is a raw pointer into the head queued message left unfinished
     * by a prior partial write.  Drain it to completion (a short write does not
     * mean the socket is full), then remove that exact message by identity with
     * msgq_excise().  These bytes are deliberately NOT added to *count_out:
     * msgq_delete() deletes in (partial-normal, prio, normal) order, so
     * crediting a whole normal message here would instead delete a priority
     * message that jumped ahead while we were blocked. */
    const char *rexmit_base = con->con_rexmit;

    while (con->con_rexmit)
    {
      io = tls_backend_write(cptr, con->con_rexmit, con->con_rexmit_len,
                             &written, &want);
      if (io != IO_SUCCESS)
      {
        tls_io_note_write(cptr, io, want);
        if (io == IO_FAILURE)
          *count_out = 0;
        return io;
      }
      if (written == con->con_rexmit_len)
      {
        con->con_rexmit_len = 0;
        con->con_rexmit = NULL;
      }
      else
      {
        con->con_rexmit = (char *)con->con_rexmit + written;
        con->con_rexmit_len -= written;
      }
    }
    msgq_excise(buf, rexmit_base);
    made_progress = 1;
    /* fall through to send more from the now-shorter queue */
  }

  count = msgq_mapiov(buf, iov, sizeof(iov) / sizeof(iov[0]), count_in);
  for (ii = 0; ii < count; ++ii)
  {
    io = tls_backend_write(cptr, iov[ii].iov_base, iov[ii].iov_len,
                           &written, &want);
    if (io == IO_SUCCESS)
    {
      *count_out += written;
      if (written < iov[ii].iov_len)
      {
        /* Short write: park the remainder in con_rexmit and drain it.  These
         * bytes are in mapiov order, so they are safe to credit to *count_out. */
        con->con_rexmit = (char *)iov[ii].iov_base + written;
        con->con_rexmit_len = iov[ii].iov_len - written;
        while (con->con_rexmit)
        {
          io = tls_backend_write(cptr, con->con_rexmit, con->con_rexmit_len,
                                 &written, &want);
          if (io != IO_SUCCESS)
          {
            tls_io_note_write(cptr, io, want);
            if (io == IO_FAILURE)
              *count_out = 0;
            return io;
          }
          *count_out += written;
          if (written == con->con_rexmit_len)
          {
            con->con_rexmit_len = 0;
            con->con_rexmit = NULL;
          }
          else
          {
            con->con_rexmit = (char *)con->con_rexmit + written;
            con->con_rexmit_len -= written;
          }
        }
      }
      continue;
    }

    /* Blocked or fatal before any byte of this iov was accepted. */
    con->con_rexmit = iov[ii].iov_base;
    con->con_rexmit_len = iov[ii].iov_len;
    tls_io_note_write(cptr, io, want);
    if (io == IO_FAILURE)
      *count_out = 0;
    return io;
  }

  if (*count_out || made_progress)
  {
    con_tls_want_wr(con) = IRCD_TLS_WANT_NONE;
    return IO_SUCCESS;
  }
  return IO_BLOCKED;
}

IOResult tls_io_recv(struct Client *cptr, char *buf, unsigned int length,
                     unsigned int *count_out)
{
  enum ircd_tls_want want = IRCD_TLS_WANT_NONE;
  IOResult io;

  /* raw kTLS: read through the kernel record layer.  con_tls_want_rd is left
   * at IRCD_TLS_WANT_NONE — there is no session that can block cross-
   * direction, so there is nothing to record. */
  if (IsTLSRaw(cptr))
  {
    int closed = 0;

    io = tls_ktls_recv(cli_fd(cptr), buf, length, count_out, &closed);
    if (io == IO_FAILURE)
    {
      /* No library session to drop — only the socket dies.  tls_io_fatal()
       * would call tls_backend_drop() on a NULL session. */
      tls_io_mark_dead(cptr);
      return IO_FAILURE;
    }
    if (closed)
    {
      /* raw-mode EOF contract.
       *
       * tls_ktls_recv() reports an orderly close (a peer close_notify record,
       * or a plain FIN) as IO_SUCCESS with zero bytes.  That is NOT what
       * read_packet() understands as end-of-file: os_recv_nonb() — the
       * plaintext primitive whose contract read_packet() was written against
       * — turns a zero-byte recv() into IO_FAILURE with errno cleared to 0
       * (ircd/os_generic.c), and read_packet()'s IO_FAILURE arm is the only
       * one that returns 0 to close the link.  A zero-byte IO_SUCCESS instead
       * falls through every `length > 0` test as "nothing arrived" and
       * returns 1, so the connection would stay open and the level-triggered
       * readable event would re-fire on the pending EOF forever.
       *
       * So translate here, at the one place that knows: raw EOF becomes
       * exactly os_recv_nonb()'s EOF signal, and a peer close_notify closes
       * the connection down precisely the path a plaintext FIN does
       * (read_packet() returns 0 -> client_sock_callback()'s "EOF from
       * client" -> exit_client()). */
      *count_out = 0;
      errno = 0;
      return IO_FAILURE;
    }
    return io;
  }

  io = tls_backend_read(cptr, buf, length, count_out, &want);

  if (io == IO_FAILURE)
    tls_io_fatal(cptr);
  else
    /* A read blocked waiting to write the socket must ask the event loop for a
     * writable event; read_packet()'s IO_BLOCKED path asserts it. */
    con_tls_want_rd(cli_connect(cptr)) =
      (io == IO_BLOCKED) ? want : IRCD_TLS_WANT_NONE;
  return io;
}

void tls_io_store_fingerprint(struct Client *cptr, const unsigned char *digest,
                              unsigned int len)
{
  char *p = cli_tls_fingerprint(cptr);

  if (len == 32 && !IsCloudflarePort(cptr))
  {
    unsigned int i;
    for (i = 0; i < len; ++i)
      sprintf(p + i * 2, "%02x", digest[i]);
    p[len * 2] = '\0';
  }
  else
    memset(p, 0, 65);
}

void tls_io_store_fingerprint_hex(struct Client *cptr, const char *hex)
{
  char *p = cli_tls_fingerprint(cptr);

  if (hex && hex[0] && strlen(hex) <= 64 && !IsCloudflarePort(cptr))
    ircd_strncpy(p, hex, 64);
  else
    memset(p, 0, 65);
}

/** Set \a reason to a plain message (bounded), the core's one reason writer. */
static void tls_io_reason(char *reason, size_t reasonlen, const char *msg)
{
  if (reason && reasonlen)
    ircd_snprintf(0, reason, reasonlen, "%s", msg);
}

int ircd_tls_negotiate(struct Client *cptr, char *reason, size_t reasonlen,
                       enum ircd_tls_want *want)
{
  struct tls_peer peer;
  IOResult io;

  if (reason && reasonlen)
    reason[0] = '\0';
  if (want)
    *want = IRCD_TLS_WANT_NONE;

  /* No session left to negotiate: fail rather than report success, or
   * start_auth() would run on every subsequent event while FLAG_NEGOTIATING_TLS
   * stays set. */
  if (!s_tls(&cli_socket(cptr)))
  {
    tls_io_reason(reason, reasonlen, "TLS setup failed (no session)");
    ClearNegotiatingTLS(cptr);
    return -1;
  }

  memset(&peer, 0, sizeof(peer));
  io = tls_backend_handshake(cptr, &peer, reason, reasonlen, want);
  if (io == IO_BLOCKED)
    return 0;
  if (io == IO_FAILURE)
    return -1;   /* reason filled by the backend; the caller drops the session */

  /* Handshake complete — apply the trust policy the backend does not. */
  if (ircd_tls_peer_cert_required(cptr) && !peer.have_cert)
  {
    tls_io_reason(reason, reasonlen,
                  "no peer certificate presented (certificate required)");
    return -1;
  }
  if (ircd_tls_verifypeer_enabled(cptr) && !peer.verified)
  {
    tls_io_reason(reason, reasonlen,
                  peer.verify_err[0] ? peer.verify_err
                                     : "certificate verification failed");
    return -1;
  }

  if (peer.digest_len)
    tls_io_store_fingerprint(cptr, peer.digest, peer.digest_len);
  else
    tls_io_store_fingerprint_hex(cptr, peer.fp_hex[0] ? peer.fp_hex : NULL);

  ClearNegotiatingTLS(cptr);
  return 1;
}
