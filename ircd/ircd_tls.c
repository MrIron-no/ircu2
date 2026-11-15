/*
 * IRC - Internet Relay Chat, ircd/ircd_tls.c
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
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <sys/wait.h>
#include <limits.h>
#include <sys/uio.h>
#include <assert.h>

#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_debug.h"
#include "s_auth.h"
#include "client.h"
#include "ircd_osdep.h"
#include "msgq.h"
#include "packet.h"
#include "numeric.h"
#include "ircd_reply.h"
#include "class.h"

#define TLSD_MAX_MSG   4096

extern struct Client *LocalClientArray[];

struct TLSd {
    struct Socket   tlsd_socket;
    uint64_t        tlsd_recvB;
    uint64_t        tlsd_sendB;
    time_t          tlsd_start_time;
    unsigned int    tlsd_recvM;
    unsigned int    tlsd_sendM;
    char*           tlsd_version;
    char **         tlsd_argv;                        /**< argument list */
};

/** Active instance of IAuth. */
static struct TLSd *tlsd;

#define tlsd_socket(tlsd) (&(tlsd)->tlsd_socket)
#define tlsd_IsConnected(tlsd) ((tlsd) && s_fd(tlsd_socket(tlsd)) > -1)
#define tlsd_fd(tlsd) (s_fd(tlsd_socket(tlsd)))

/** Hash table for TLS sessions */
static struct Connection* tls_sessions[MAXCONNECTIONS];

/** Initialize TLS session management */
void tls_session_init(void)
{
    memset(tls_sessions, 0, sizeof(tls_sessions));
}

/** Calculate hash value for a session ID */
static unsigned int tls_session_hash(uint32_t session_id)
{
    return session_id % TLS_SESSION_HASHSIZE;
}

/** Add a new TLS session */
struct Connection* tls_session_add(struct Client* cptr)
{
    struct Connection* con;
    unsigned int hash;

    con = cli_connect(cptr);
    assert(con != NULL);  // Client must have a connection at this point

    // Generate a unique session ID
    uint32_t session_id = cli_id(cptr);
    con->con_tls_session_id = session_id;  // Store session ID in dedicated field

    hash = tls_session_hash(session_id);
    con->con_next = tls_sessions[hash];
    tls_sessions[hash] = con;

    Debug((DEBUG_DEBUG, "Created TLS session %u for client %C", session_id, cptr));
    return con;
}

/** Find a TLS session by ID */
struct Connection* tls_session_find(uint32_t session_id)
{
    struct Connection* con;
    unsigned int hash = tls_session_hash(session_id);

    for (con = tls_sessions[hash]; con; con = con->con_next) {
        if (con->con_tls_session_id == session_id && con->con_client)
            return con;
    }
    return NULL;
}

/** Remove a TLS session */
void tls_session_remove(struct Connection* con)
{
    struct Connection** prev;
    unsigned int hash;

    if (!con || !con->con_client)
        return;

    hash = tls_session_hash(con->con_tls_session_id);

    // Remove from hash table
    for (prev = &tls_sessions[hash]; *prev; prev = &(*prev)->con_next) {
        if (*prev == con) {
            *prev = con->con_next;
            break;
        }
    }
}

/* Connect to the TLS daemon, spawning it if needed. */
int tlsd_do_spawn(struct TLSd *tlsd, int automatic)
{
    pid_t cpid;
    int s_io[2];
    int s_err[2];
    int res;

    if (automatic && CurrentTime - tlsd->tlsd_start_time < 5)
    {
        Debug((DEBUG_ERROR, "TLSd crashed fast, leaving it dead."));
        return -1;
    }

    /* Record time we tried to spawn the iauth process. */
    tlsd->tlsd_start_time = CurrentTime;

    /* Attempt to allocate a pair of sockets. */
    res = os_socketpair(s_io);
    if (res) {
        res = errno;
        Debug((DEBUG_INFO, "Unable to create TLSd socketpair: %s", strerror(res)));
        return res;
    }

    /* Mark the parent's side of the pair (element 0) as non-blocking. */
    res = os_set_nonblocking(s_io[0]);
    if (!res) {
        res = errno;
        Debug((DEBUG_INFO, "Unable to make TLSd socket non-blocking: %s", strerror(res)));
        goto fail_1;
    }

    /* Initialize the socket structure to talk to the child. */
    res = socket_add(tlsd_socket(tlsd), tlsd_eventloop_callback, tlsd,
                    SS_CONNECTED, SOCK_EVENT_READABLE, s_io[0]);
    if (!res) {
        res = errno;
        Debug((DEBUG_INFO, "Unable to register TLSd socket: %s", strerror(res)));
        goto fail_1;
    }

    /* Attempt to fork a child process. */
    cpid = fork();
    if (cpid < 0) {
        /* Error forking the child, still in parent. */
        res = errno;
        Debug((DEBUG_INFO, "Unable to fork TLSd child: %s", strerror(res)));
    fail_2:
        socket_del(tlsd_socket(tlsd));
        s_fd(tlsd_socket(tlsd)) = -1;
    fail_1:
        close(s_io[1]);
        close(s_io[0]);
        return res;
    }

    if (cpid > 0) {
        /* We are the parent process.  Close the child's sockets. */
        close(s_io[1]);

        /* Indicate success (until the child dies). */
        return 0;
    }

    /* We are the child process.
    * Duplicate our end of the socket to stdin, stdout and stderr.
    * Then close all the higher-numbered FDs and exec the process.
    */
    if (dup2(s_io[1], 0) == 0
        && dup2(s_io[1], 1) == 1
        && dup2(s_err[1], 2) == 2) {
        close_connections(0);
        execvp(tlsd->tlsd_argv[0], tlsd->tlsd_argv);
    }

    /* If we got here, something was seriously wrong. */
    fprintf(stderr, "Unable to exec TLSd: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
}

int tlsd_spawn(int argc, char *argv[]) {
    int ii;

    if (tlsd) {
        Debug((DEBUG_INFO, "TLS daemon already running"));
        return 0;
    }

    /* Initialize TLS session management */
    tls_session_init();

    /* Need to initialize a new connection. */
    tlsd = MyCalloc(1, sizeof(*tlsd));
 
    /* Populate iauth's argv array. */
    tlsd->tlsd_argv = MyCalloc(argc + 1, sizeof(tlsd->tlsd_argv[0]));
    for (ii = 0; ii < argc; ++ii)
        DupString(tlsd->tlsd_argv[ii], argv[ii]);
    tlsd->tlsd_argv[ii] = NULL;

    /* Try to spawn it, and handle the results. */
    if (tlsd_do_spawn(tlsd, 0))
        return 0;

    return 1;
}

/* Send a handshake request (pass client fd to tlsd) */
int tlsd_start_handshake(struct Client* cptr)
{
    struct Connection* con;
    struct msghdr msg;
    struct iovec iov;
    struct tlsd_msg_hdr hdr;
    char controlbuf[CMSG_SPACE(sizeof(int))];
    int fd = cli_fd(cptr);

    Debug((DEBUG_DEBUG, "Starting TLS handshake for client (fd=%d)", fd));

    /* Create new session */
    con = tls_session_add(cptr);
    if (!con) {
        Debug((DEBUG_ERROR, "Failed to create TLS session for client fd=%d", fd));
        return -1;
    }

    /* Prepare message */
    memset(&msg, 0, sizeof(msg));
    hdr.type = TLSD_HANDSHAKE;
    hdr.session_id = con->con_tls_session_id;  // Use dedicated session ID field
    hdr.len = 0;

    iov.iov_base = &hdr;
    iov.iov_len = sizeof(hdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    memset(controlbuf, 0, sizeof(controlbuf));
    msg.msg_control = controlbuf;
    msg.msg_controllen = sizeof(controlbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *) CMSG_DATA(cmsg)) = fd;

    Debug((DEBUG_DEBUG, "Sending TLS handshake request for client fd=%d to tlsd_fd=%d (session_id=%u)", 
           fd, tlsd_fd(tlsd), hdr.session_id));

    /* Send the message */
    if (sendmsg(tlsd_fd(tlsd), &msg, 0) < 0) {
        Debug((DEBUG_ERROR, "Failed to send TLS handshake request: %s", strerror(errno)));
        tls_session_remove(con);
        return -1;
    }

    // TLS TODO: removed socket close from here.
    socket_del(&(cli_socket(cptr)));

    return 0;
}

/* Send plaintext data to be encrypted and sent to the client */
IOResult tlsd_send_plaintext(struct Client* cptr, struct MsgQ *buf, unsigned int *count_in, unsigned int *count_out)
{
    struct iovec iov[17]; // 1 for header + up to 16 for data
    unsigned int total_len = 0;
    int iovcnt, i;
    ssize_t n;
    size_t sent = 0;
    struct Connection* con = cli_connect(cptr);

    if (!con || !con->con_client)
        return IO_FAILURE;

    iovcnt = msgq_mapiov(buf, iov + 1, 16, &total_len);
    if (iovcnt <= 0 || total_len == 0)
        return IO_SUCCESS;

    *count_in = total_len;
    *count_out = 0;

    struct tlsd_msg_hdr hdr = { TLSD_SEND_PLAINTEXT, con->con_tls_session_id, (uint32_t)total_len };
    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);

    n = writev(tlsd_fd(tlsd), iov, iovcnt + 1);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return IO_BLOCKED;
        return IO_FAILURE;
    }

    sent = n;
    *count_out = (sent > sizeof(hdr)) ? (sent - sizeof(hdr)) : 0;
    return (sent == (ssize_t)(sizeof(hdr) + total_len)) ? IO_SUCCESS : IO_BLOCKED;
}

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
/* Receive decrypted data from tlsd (call from event loop when tlsd_fd is readable) */
IOResult tlsd_recv_plaintext(struct Client* cptr, void *buf, size_t maxlen, unsigned int *count_out)
{
    struct tlsd_msg_hdr hdr;
    ssize_t n;
    struct Connection* con = cli_connect(cptr);

    if (!con || !con->con_client)
        return IO_FAILURE;

    *count_out = 0;

    n = read_full(tlsd_fd(tlsd), &hdr, sizeof(hdr));
    if (n != sizeof(hdr)) {
        Debug((DEBUG_ERROR, "tlsd_recv_plaintext: failed to read header: %zd", n));
        return IO_FAILURE;
    }
    if (hdr.type != TLSD_RECV_PLAINTEXT || hdr.len > maxlen || hdr.session_id != con->con_tls_session_id) {
        Debug((DEBUG_ERROR, "tlsd_recv_plaintext: invalid header: type=%u len=%u session_id=%u (expected session_id=%u)",
            hdr.type, hdr.len, hdr.session_id, con->con_tls_session_id));
        return IO_FAILURE;
    }
    n = read_full(tlsd_fd(tlsd), buf, hdr.len);
    if (n != (ssize_t)hdr.len) {
        Debug((DEBUG_ERROR, "tlsd_recv_plaintext: failed to read payload: %zd/%u", n, hdr.len));
        return IO_FAILURE;
    }

    *count_out = n;
    return IO_SUCCESS;
}

/* Close the TLS session for this client */
int tlsd_close(struct Client* cptr)
{
    struct Connection* con = cli_connect(cptr);
    if (!con || !con->con_client)
        return -1;

    struct tlsd_msg_hdr hdr = { TLSD_CLOSE, con->con_tls_session_id, 0 };
    int ret = write(tlsd_fd(tlsd), &hdr, sizeof(hdr));
    tls_session_remove(con);
    return ret;
}

/* Send a message to the TLS daemon */
int sendto_tlsd(uint8_t type, struct Client* cptr, const void *data, size_t len)
{
    struct Connection* con;
    struct tlsd_msg_hdr hdr;
    struct iovec iov[2];
    int iovcnt = 1;

    if (!tlsd || !tlsd_IsConnected(tlsd)) {
        Debug((DEBUG_ERROR, "sendto_tlsd: TLS daemon not connected"));
        return -1;
    }

    if (!cptr) {
        Debug((DEBUG_ERROR, "sendto_tlsd: NULL client pointer"));
        return -1;
    }

    con = cli_connect(cptr);
    if (!con || !con->con_client) {
        Debug((DEBUG_ERROR, "sendto_tlsd: client has no valid connection"));
        return -1;
    }

    hdr.type = type;
    hdr.session_id = con->con_tls_session_id;
    hdr.len = (uint32_t)len;

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);

    if (data && len > 0) {
        iov[1].iov_base = (void *)data;
        iov[1].iov_len = len;
        iovcnt = 2;
    }

    ssize_t ret = writev(tlsd_fd(tlsd), iov, iovcnt);
    if (ret < 0) {
        Debug((DEBUG_ERROR, "sendto_tlsd: writev failed: %s", strerror(errno)));
        return -1;
    }

    Debug((DEBUG_DEBUG, "sendto_tlsd: sent message type %u for session %u (%zd bytes)", 
           type, hdr.session_id, ret));
    return 0;
}

/* Example: call this from your event loop when tlsd_fd is readable */
void tlsd_eventloop_callback(struct Event *ev)
{
    Debug((DEBUG_DEBUG, "TLSd event loop callback"));
    char buf[TLSD_MAX_MSG];
    struct tlsd_msg_hdr hdr;
    ssize_t n;

    // Step 1: Read the header
    n = read_full(tlsd_fd(tlsd), &hdr, sizeof(hdr));
    if (n != sizeof(hdr)) {
        Debug((DEBUG_ERROR, "TLSd: Failed to read full header: %zd", n));
        if (n == 0) {
            Debug((DEBUG_ERROR, "TLSd: EOF on control socket"));
            close(tlsd_fd(tlsd));
            tlsd_fd(tlsd) = -1;
        }
        return;
    }
    Debug((DEBUG_DEBUG, "TLSd: Read header: n=%zd, type=%u, session_id=%u, len=%u", 
           n, hdr.type, hdr.session_id, hdr.len));
    if (hdr.len > sizeof(buf)) {
        Debug((DEBUG_ERROR, "TLSd: Message too large: %u", hdr.len));
        return;
    }

    // Step 2: Lookup the client by session id
    struct Connection* con = tls_session_find(hdr.session_id);
    if (!con) {
        Debug((DEBUG_ERROR, "TLSd: No session found for session_id=%u", hdr.session_id));
        return;
    }

    struct Client* cptr = con->con_client;
    Debug((DEBUG_DEBUG, "TLSd: Lookup client for session_id=%u: %p", hdr.session_id, (void*)cptr));
    if (!cptr || IsDead(cptr)) {
        Debug((DEBUG_ERROR, "TLSd: No client or client is dead for session_id=%u", hdr.session_id));
        tls_session_remove(con);
        return;
    }

    // Update last activity time for the session
//    con->con_lasttime = CurrentTime;

    switch (hdr.type) {
        case TLSD_RECV_PLAINTEXT:
            Debug((DEBUG_DEBUG, "TLSd: RECV_PLAINTEXT for session_id=%u, len=%u", hdr.session_id, hdr.len));
            n = read_full(tlsd_fd(tlsd), buf, hdr.len);
            Debug((DEBUG_DEBUG, "TLSd: Read %zd bytes of plaintext", n));
            if (n != (ssize_t)hdr.len)
                return;
            
            // Debug: show the actual data being received
            Debug((DEBUG_DEBUG, "TLSd: Received data: '%.*s'", (int)n, buf));
            
            if (dbuf_put(&(cli_recvQ(cptr)), buf, n) == 0) {
                Debug((DEBUG_ERROR, "TLSd: dbuf_put failed for session_id=%u", hdr.session_id));
                return;
            }
            // Update client activity times, matching s_bsd.c read_packet
            cli_lasttime(cptr) = CurrentTime;
            ClearPingSent(cptr);
            ClrFlag(cptr, FLAG_NONL);
            if (cli_lasttime(cptr) > cli_since(cptr))
                cli_since(cptr) = cli_lasttime(cptr);
            if (tlsd_parse_buffer(cptr) == 0) {
                Debug((DEBUG_ERROR, "TLSd: tlsd_parse_buffer signaled EOF for session_id=%u", hdr.session_id));
                exit_client(cptr, cptr, &me, "EOF from TLSd");
            }
            break;
        case TLSD_HANDSHAKE_DONE:
            Debug((DEBUG_DEBUG, "TLSd: HANDSHAKE_DONE for session_id=%u", hdr.session_id));
            if (hdr.len > 0) {
                char fingerprint[256] = {0}; // Adjust size as needed
                ssize_t n = read_full(tlsd_fd(tlsd), fingerprint, hdr.len < sizeof(fingerprint) ? hdr.len : sizeof(fingerprint) - 1);
                if (n > 0) {
                    fingerprint[n < sizeof(fingerprint) ? n : sizeof(fingerprint) - 1] = '\0';
                    // Store fingerprint in client struct
                    ircd_strncpy(cli_tls_fingerprint(cptr), fingerprint, 64);
                    Debug((DEBUG_DEBUG, "TLSd: Received fingerprint for session_id=%u: %s", hdr.session_id, cli_tls_fingerprint(cptr)));
                }
            }
            ClearNegotiatingTLS(cptr);
            if (!IsConnecting(cptr)) {
                Debug((DEBUG_DEBUG, "TLSd: Calling start_auth for session_id=%u", hdr.session_id));
                start_auth(cptr);
            }
            /* Close the original fd since it's now owned by tlsd */
            //socket_del(&(cli_socket(cptr)));
            close(cli_fd(cptr));
            LocalClientArray[cli_fd(cptr)] = 0;
            cli_fd(cptr) = -1;

            break;
        case TLSD_CLOSE:
            Debug((DEBUG_DEBUG, "TLSd: Received CLOSE for session_id=%u", hdr.session_id));
            tls_session_remove(con);  // Remove session before exiting client
            exit_client(cptr, cptr, &me, "EOF from client");

            // After exit_client() completes
            sendto_tlsd(TLSD_CLOSE_ACK, cptr, NULL, 0);
        default:
            Debug((DEBUG_ERROR, "TLSd: Unknown message type %u for session_id=%u", hdr.type, hdr.session_id));
            break;
    }
}

int tlsd_parse_buffer(struct Client *cptr)
{
    unsigned int dolen = 0;

    Debug((DEBUG_DEBUG, "tlsd_parse_buffer: %C, buffer length: %d", cptr, DBufLength(&(cli_recvQ(cptr)))));

    if (DBufLength(&(cli_recvQ(cptr))) > GetMaxFlood(cptr))
        return exit_client(cptr, cptr, &me, "Excess Flood");

    // Debug: check the conditions for message processing
    Debug((DEBUG_DEBUG, "tlsd_parse_buffer: conditions - NoNewLine=%d, IsTrusted=%d, cli_since=%ld, CurrentTime=%ld, time_diff=%ld", 
           NoNewLine(cptr), IsTrusted(cptr), cli_since(cptr), CurrentTime, cli_since(cptr) - CurrentTime));

    while (DBufLength(&(cli_recvQ(cptr))) && !NoNewLine(cptr) &&
           (IsTrusted(cptr) || cli_since(cptr) - CurrentTime < 10))
    {
        // Debug: show the raw buffer content before parsing
        const char *raw_data;
        unsigned int raw_len;
        raw_data = dbuf_map(&(cli_recvQ(cptr)), &raw_len);
        if (raw_data && raw_len > 0) {
            Debug((DEBUG_DEBUG, "tlsd_parse_buffer: raw buffer content (len=%u): '%.*s'", raw_len, (int)raw_len, raw_data));
            // Show hex dump of first 32 bytes
            char hex_dump[128];
            int hex_pos = 0;
            for (unsigned int i = 0; i < raw_len && i < 32; i++) {
                hex_pos += snprintf(hex_dump + hex_pos, sizeof(hex_dump) - hex_pos, "%02x ", (unsigned char)raw_data[i]);
            }
            Debug((DEBUG_DEBUG, "tlsd_parse_buffer: hex dump: %s", hex_dump));
        }

        dolen = dbuf_getmsg(&(cli_recvQ(cptr)), cli_buffer(cptr), BUFSIZE);
        Debug((DEBUG_DEBUG, "tlsd_parse_buffer: got message of length %u: '%s'", dolen, cli_buffer(cptr)));
        if (dolen == 0)
        {
            Debug((DEBUG_DEBUG, "tlsd_parse_buffer: dbuf_getmsg returned 0, no complete message found"));
            if (DBufLength(&(cli_recvQ(cptr))) < 510)
                SetFlag(cptr, FLAG_NONL);
            else
            {
                DBufClear(&(cli_recvQ(cptr)));
                send_reply(cptr, ERR_INPUTTOOLONG);
            }
        }
        else if (client_dopacket(cptr, dolen) == CPTR_KILLED)
            return CPTR_KILLED;

        if (IsHandshake(cptr) || IsServer(cptr))
        {
            while (1)
            {
                dolen = dbuf_get(&(cli_recvQ(cptr)), cli_buffer(cptr), BUFSIZE);
                if (dolen == 0)
                    return 1;
                if ((IsServer(cptr)
                     ? server_dopacket(cptr, cli_buffer(cptr), dolen)
                     : connect_dopacket(cptr, cli_buffer(cptr), dolen)) == CPTR_KILLED)
                    return CPTR_KILLED;
            }
        }
    }

    /*if (DBufLength(&(cli_recvQ(cptr))) && !NoNewLine(cptr) &&
        !t_onqueue(&(cli_proc(cptr))))
    {
        Debug((DEBUG_LIST, "Adding client process timer for %C", cptr));
        cli_freeflag(cptr) |= FREEFLAG_TIMER;
        timer_add(&(cli_proc(cptr)), client_timer_callback, cli_connect(cptr),
                  TT_RELATIVE, 2);
    }*/

    return 1;
}
