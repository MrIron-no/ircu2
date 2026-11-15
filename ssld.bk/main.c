/*
 * IRC - Internet Relay Chat, ircd/tls_gnutls.c
 * Copyright (C) 2019 Michael Poole
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <sys/select.h>  // For fd_set and FD_SETSIZE
#include "ircd_tls.h"
#include "log.h"

#define MAX_SESSIONS 256

static int ipc_fd = 0;
static struct TlsSession *sessions_by_id[MAX_SESSIONS] = {0};

static ssize_t read_full(int fd, void *buf, size_t len);

static void fatal(const char *msg) {
    log_write(LOG_LEVEL_ERROR, msg);
    ircd_tls_cleanup();
    log_close();
    exit(1);
}

static void send_to_ircd(uint8_t type, uint32_t session_id, const void *data, size_t len) {
    struct tlsd_msg_hdr hdr = {
        .type = type,
        .session_id = session_id,
        .len = (uint32_t)len
    };
    struct iovec iov[2];
    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);
    int iovcnt = 1;
    if (data && len > 0) {
        iov[1].iov_base = (void *)data;
        iov[1].iov_len = len;
        iovcnt = 2;
    }
    writev(ipc_fd, iov, iovcnt);
}

static void handle_ipc_message() {
    char buf[4096];
    ssize_t n;
    struct tlsd_msg_hdr *hdr;

    // Peek at the header to determine the message type
    n = recv(ipc_fd, buf, sizeof(struct tlsd_msg_hdr), MSG_PEEK);
    if (n == 0) {
        log_write(LOG_LEVEL_DEBUG, "IPC fd %d closed (EOF) in handle_ipc_message", ipc_fd);
        return;
    }
    if (n < 0) {
        log_write(LOG_LEVEL_DEBUG, "Error peeking header from fd %d: %s", ipc_fd, strerror(errno));
        return;
    }
    if ((size_t)n < sizeof(struct tlsd_msg_hdr)) {
        log_write(LOG_LEVEL_DEBUG, "Message too short for header (%zd bytes)", n);
        return;
    }

    hdr = (struct tlsd_msg_hdr *)buf;
    log_write(LOG_LEVEL_DEBUG, "Received message type %u for session %u (peek)", hdr->type, hdr->session_id);

    if (hdr->type == TLSD_HANDSHAKE) {
        log_write(LOG_LEVEL_DEBUG, "Handling TLSD_HANDSHAKE for session %u", hdr->session_id);
        // Validate session id from IRCd
        if (hdr->session_id >= MAX_SESSIONS) {
            log_write(LOG_LEVEL_DEBUG, "Invalid session id from IRCd: %u", hdr->session_id);
            return;
        }
        if (sessions_by_id[hdr->session_id]) {
            log_write(LOG_LEVEL_DEBUG, "Session slot %u already in use!", hdr->session_id);
            return;
        }

        // Now actually read the message and fd using recvmsg()
        struct msghdr msg = {0};
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        n = recvmsg(ipc_fd, &msg, 0);
        if (n < (ssize_t)sizeof(struct tlsd_msg_hdr)) {
            log_write(LOG_LEVEL_DEBUG, "Handshake message too short (got %zd bytes)", n);
            return;
        }

        int passed_fd = -1;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&passed_fd, CMSG_DATA(cmsg), sizeof(int));
        }
        log_write(LOG_LEVEL_DEBUG, "Received fd %d from IRCd for session %u", passed_fd, hdr->session_id);
        if (passed_fd < 0) {
            log_write(LOG_LEVEL_DEBUG, "No fd passed for handshake");
            return;
        }

        // Now use passed_fd for the TLS session!
        struct TlsSession *sess = tls_session_create(passed_fd, 1);
        if (!sess) {
            log_write(LOG_LEVEL_DEBUG, "Failed to create TLS session for fd %d", passed_fd);
            close(passed_fd);
            return;
        }

        sess->session_id = hdr->session_id;  // Store session ID
        sessions_by_id[hdr->session_id] = sess;

        sess->state = TLS_SESSION_HANDSHAKE;
        log_write(LOG_LEVEL_DEBUG, "Starting handshake for session %u (fd=%d)", hdr->session_id, passed_fd);
        int hs = tls_session_handshake(sess);
        if (hs == 1) {
            sess->state = TLS_SESSION_ESTABLISHED;
            log_write(LOG_LEVEL_DEBUG, "TLS handshake complete for fd %d (fp=%s)",
                sess->fd,  sess->fingerprint[0] != '\0' ? sess->fingerprint : "none");

            send_to_ircd(TLSD_HANDSHAKE_DONE, hdr->session_id,
                    sess->fingerprint[0] != '\0' ? sess->fingerprint : NULL,
                    sess->fingerprint[0] != '\0' ? sizeof(sess->fingerprint) : 0);
            // After handshake completes:
//            struct tlsd_msg_hdr out_hdr = { TLSD_HANDSHAKE_DONE, sess->ircd_fd, 0 };
//            write(ipc_fd, &out_hdr, sizeof(out_hdr));
        } else if (hs == IO_BLOCKED) {
            sess->state = TLS_SESSION_HANDSHAKE;
            log_write(LOG_LEVEL_DEBUG, "TLS handshake in progress for session %u (fd=%d)", hdr->session_id, passed_fd);
        } else {
            sess->state = TLS_SESSION_ERROR;
            log_write(LOG_LEVEL_DEBUG, "TLS handshake failed for session %u (fd=%d)", hdr->session_id, passed_fd);
            tls_session_free(sess);
            sessions_by_id[hdr->session_id] = NULL;
            close(passed_fd);
        }
        return;
    }

    // For all other message types, use read_full as before
    n = read_full(ipc_fd, buf, sizeof(struct tlsd_msg_hdr));
    if (n == 0) {
        log_write(LOG_LEVEL_DEBUG, "IPC fd %d closed (EOF) in handle_ipc_message (read_full)", ipc_fd);
        return;
    }
    if (n < 0) {
        log_write(LOG_LEVEL_DEBUG, "Error reading header from fd %d: %s", ipc_fd, strerror(errno));
        return;
    }
    if ((size_t)n < sizeof(struct tlsd_msg_hdr)) {
        log_write(LOG_LEVEL_DEBUG, "Message too short for header (%zd bytes) (read_full)", n);
        return;
    }

    hdr = (struct tlsd_msg_hdr *)buf;
    log_write(LOG_LEVEL_DEBUG, "Processing message type %u for session %u (read_full)", hdr->type, hdr->session_id);

    // Step 2: Read the payload if any
    size_t datalen = hdr->len;
    if (datalen > sizeof(buf) - sizeof(struct tlsd_msg_hdr)) {
        log_write(LOG_LEVEL_DEBUG, "Payload too large (%zu bytes)", datalen);
        return;
    }
    if (datalen > 0) {
        n = read_full(ipc_fd, buf + sizeof(struct tlsd_msg_hdr), datalen);
        if ((size_t)n < datalen) {
            log_write(LOG_LEVEL_DEBUG, "Message too short for data (%zd/%zu bytes)", n, datalen);
            return;
        }
    }

    // Incoming message
    switch (hdr->type) {
        case TLSD_HANDSHAKE: {
            // This case should not be reached anymore, as handshake is handled above.
            log_write(LOG_LEVEL_DEBUG, "Got handshake request (unexpected in switch), session_id=%u", hdr->session_id);
            break;
        }
        case TLSD_HANDSHAKE_DONE: {
            log_write(LOG_LEVEL_DEBUG, "Received HANDSHAKE_DONE (should not happen from IRCd)");
            break;
        }
        case TLSD_SEND_PLAINTEXT: {
            if (hdr->session_id < MAX_SESSIONS && sessions_by_id[hdr->session_id]) {
                struct TlsSession *sess = sessions_by_id[hdr->session_id];
                size_t datalen = hdr->len;
                if ((size_t)n < datalen) {
                    log_write(LOG_LEVEL_DEBUG, "SEND_PLAINTEXT: message too short for data (%zd/%zu bytes)", n, datalen);
                    return;
                }
                char *data = buf + sizeof(struct tlsd_msg_hdr);
                struct iovec iov = { .iov_base = data, .iov_len = datalen };
                ssize_t sent = tls_session_sendv(sess, &iov, 1);
                log_write(LOG_LEVEL_DEBUG, "Sent %zd bytes of plaintext to TLS client (session %u)", sent, hdr->session_id);
            }
            break;
        }
        case TLSD_RECV_PLAINTEXT: {
            if (hdr->session_id < MAX_SESSIONS && sessions_by_id[hdr->session_id]) {
                size_t datalen = hdr->len;
                write(ipc_fd, buf, sizeof(struct tlsd_msg_hdr) + datalen);
                log_write(LOG_LEVEL_DEBUG, "Forwarded %zu bytes of plaintext from TLS client (session %u) to IRCd", datalen, hdr->session_id);
            }
            break;
        }
        case TLSD_CLOSE: {
            if (hdr->session_id < MAX_SESSIONS && sessions_by_id[hdr->session_id]) {
                tls_session_free(sessions_by_id[hdr->session_id]);
                sessions_by_id[hdr->session_id] = NULL;
                log_write(LOG_LEVEL_DEBUG, "Closed TLS session %u", hdr->session_id);
            }
            break;
        }
        default:
            log_write(LOG_LEVEL_DEBUG, "Unknown message type: %u", hdr->type);
            break;
    }
}

// Read exactly len bytes from fd into buf, handling partial reads
static ssize_t read_full(int fd, void *buf, size_t len) {
    size_t total = 0;
    char *p = buf;
    while (total < len) {
        ssize_t n = read(fd, p + total, len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return -1;
        }
        if (n == 0) break; // EOF
        total += n;
    }
    return total;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    signal(SIGPIPE, SIG_IGN);

    // Die when parent dies
    prctl(PR_SET_PDEATHSIG, SIGTERM);

    if (log_init("/home/iron/ircu/lib/ssld.log", LOG_LEVEL_DEBUG) != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }

    log_write(LOG_LEVEL_DEBUG, "Starting TLS daemon...");

    if (ircd_tls_init("/home/iron/ircu/lib/ircd.crt", "/home/iron/ircu/lib/ircd.key") != 0) {
        fprintf(stderr, "TLS initialization failed\n");
        return 1;
    }

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(ipc_fd, &readfds);
        int maxfd = ipc_fd;

        // Add all TLS session fds in handshake/established to the set
        for (int i = 0; i < MAX_SESSIONS; ++i) {
            struct TlsSession *sess = sessions_by_id[i];
            if (sess && (sess->state == TLS_SESSION_HANDSHAKE || sess->state == TLS_SESSION_ESTABLISHED)) {
                FD_SET(sess->fd, &readfds);
                if (sess->fd > maxfd)
                    maxfd = sess->fd;
            }
        }

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            fatal("select");
        }

        // Handle messages from IRCd
        if (FD_ISSET(ipc_fd, &readfds)) {
            handle_ipc_message();
        }

        // Retry handshake for sessions in progress
        for (int i = 0; i < MAX_SESSIONS; ++i) {
            struct TlsSession *sess = sessions_by_id[i];
            if (sess && sess->state == TLS_SESSION_HANDSHAKE && FD_ISSET(sess->fd, &readfds)) {
                int hs = tls_session_handshake(sess);
                if (hs == 1) {
                    sess->state = TLS_SESSION_ESTABLISHED;
                    log_write(LOG_LEVEL_DEBUG, "TLS handshake complete for fd %d (retry loop) (fp=%s)",
                        sess->fd,  sess->fingerprint[0] != '\0' ? sess->fingerprint : "none");

                    send_to_ircd(TLSD_HANDSHAKE_DONE, i,  // Use array index as session ID
                            sess->fingerprint[0] != '\0' ? sess->fingerprint : NULL,
                            sess->fingerprint[0] != '\0' ? sizeof(sess->fingerprint) : 0);

//                    struct tlsd_msg_hdr out_hdr = { TLSD_HANDSHAKE_DONE, sess->ircd_fd, 0 };
//                    write(ipc_fd, &out_hdr, sizeof(out_hdr));
                } else if (hs < 0) {
                    sess->state = TLS_SESSION_ERROR;
                    log_write(LOG_LEVEL_DEBUG, "TLS handshake failed for fd %d (retry loop)", sess->fd);
                    int fd_to_close = sess->fd; // Save before free
                    tls_session_free(sess);
                    sessions_by_id[i] = NULL;
                    close(fd_to_close);
                    continue;
                }
                // If hs == 0, still in progress, do nothing
            }
        }

        // Handle established TLS sessions: read from TLS client and forward to IRCd
        for (int i = 0; i < MAX_SESSIONS; ++i) {
            struct TlsSession *sess = sessions_by_id[i];
            if (!sess || sess->state != TLS_SESSION_ESTABLISHED || sess->fd <= 0 || !FD_ISSET(sess->fd, &readfds))
                continue;

            if (sess->fd >= FD_SETSIZE) {
                log_write(LOG_LEVEL_DEBUG, "sessions[%d]->fd (%d) >= FD_SETSIZE (%d), skipping", i, sess->fd, FD_SETSIZE);
                continue;
            }

            char buf[4096];
            ssize_t n = tls_session_read(sess, buf, sizeof(buf));
            if (n > 0) {
                log_write(LOG_LEVEL_DEBUG, "Received %zd bytes from TLS client (session %d)", n, i);

                struct tlsd_msg_hdr hdr = {
                    .type = TLSD_RECV_PLAINTEXT,
                    .session_id = (uint32_t)i,
                    .len = (uint32_t)n
                };

                struct iovec iov[2];
                iov[0].iov_base = &hdr;
                iov[0].iov_len = sizeof(hdr);
                iov[1].iov_base = buf;
                iov[1].iov_len = n;
                writev(ipc_fd, iov, 2);
                log_write(LOG_LEVEL_DEBUG, "Forwarded %zd bytes from TLS client (session %d) to IRCd", n, i);
            } else if (n == IO_FAILURE) {
                // TLS client closed connection or error
                log_write(LOG_LEVEL_DEBUG, "TLS session read error, closing session %d (fd=%d)", i, sess->fd);
                log_write(LOG_LEVEL_DEBUG, "Freeing session %d (fd=%d)", i, sess->fd);

                // Notify IRCd of the closure
                send_to_ircd(TLSD_CLOSE, i, NULL, 0);  // Use array index as session ID

                tls_session_free(sess);
                sessions_by_id[i] = NULL;
                continue;
            }
        }
    }

    log_write(LOG_LEVEL_DEBUG, "Shutting down...");
    close(ipc_fd);
    ircd_tls_cleanup();
    log_close();
    return 0;
}
