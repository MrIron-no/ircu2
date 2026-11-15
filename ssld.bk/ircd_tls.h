/*
 * IRC - Internet Relay Chat, include/ircd_tls.h
 * Copyright (C) 2019 Michael Poole
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
 * @brief Functions for handling TLS-protected connections.
 */
#ifndef INCLUDED_ircd_tls_h
#define INCLUDED_ircd_tls_h

#include <sys/uio.h>
#include <stddef.h>
#include <stdint.h>

#define IO_BLOCKED 0
#define IO_FAILURE -1

enum {
    TLSD_HANDSHAKE = 1,
    TLSD_HANDSHAKE_DONE = 2,
    TLSD_SEND_PLAINTEXT = 3,
    TLSD_RECV_PLAINTEXT = 4,
    TLSD_CLOSE = 5,
};

enum tls_session_state {
    TLS_SESSION_HANDSHAKE,
    TLS_SESSION_ESTABLISHED,
    TLS_SESSION_CLOSING,
    TLS_SESSION_ERROR
};

struct tlsd_msg_hdr {
    uint32_t type;
    uint32_t session_id;
    uint32_t len;
};

struct TlsSession {
    int fd;              // The actual socket fd
    uint32_t session_id; // Unique session identifier
    void *ssl;
    enum tls_session_state state;
    char *rexmit;
    size_t rexmit_len;
    char fingerprint[65];
};

/* Initialize the TLS library and load cert/key files.
 * Returns 0 on success, non-zero on failure.
 */
int ircd_tls_init(const char *certfile, const char *keyfile);

/* Clean up all TLS state. */
void ircd_tls_cleanup(void);

/* Create a new TLS session for a given fd.
 * is_server: nonzero for server mode, zero for client mode.
 * Returns a new TlsSession* or NULL on failure.
 */
struct TlsSession *tls_session_create(int fd, int is_server);

/* Free a TLS session and all associated resources. */
void tls_session_free(struct TlsSession *sess);

/* Perform or continue the TLS handshake.
 * Returns 1 if handshake complete, 0 if in progress, -1 on error.
 */
int tls_session_handshake(struct TlsSession *sess);

/* Read decrypted data from the TLS session.
 * Returns number of bytes read, 0 if would block, -1 on error.
 */
ssize_t tls_session_read(struct TlsSession *sess, void *buf, size_t len);

/* Write data to the TLS session using iovec.
 * Returns total bytes written, 0 if would block, -1 on error.
 */
ssize_t tls_session_sendv(struct TlsSession *sess, struct iovec *iov, int iovcnt);

#endif /* INCLUDED_ircd_tls_h */
