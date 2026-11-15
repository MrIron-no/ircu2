#ifndef INCLUDED_ircd_tls_h
#define INCLUDED_ircd_tls_h

#include <stddef.h>
#include <stdint.h>
#include "client.h"
#include "ircd_osdep.h"

// Protocol constants
#define TLSD_MAX_MSG   4096
#define TLS_SESSION_HASHSIZE 1024

// Message types for protocol
enum {
    TLSD_HANDSHAKE = 1,
    TLSD_HANDSHAKE_DONE = 2,
    TLSD_SEND_PLAINTEXT = 3,
    TLSD_RECV_PLAINTEXT = 4,
    TLSD_CLOSE = 5,
    TLSD_CLOSE_ACK = 6,
};

struct tlsd_msg_hdr {
    uint32_t type;
    uint32_t session_id;
    uint32_t len;
};

// TLS daemon management
int     tlsd_spawn(int argc, char *argv[]);
int     sendto_tlsd(uint8_t type, struct Client* cptr, const void *data, size_t len);

// TLS session operations
int     tlsd_start_handshake(struct Client* cptr);
IOResult tlsd_recv_plaintext(struct Client* cptr, void *buf, size_t maxlen, unsigned int *bytes_read);
IOResult tlsd_send_plaintext(struct Client* cptr, struct MsgQ *buf, unsigned int *bytes_count, unsigned int *bytes_written);
int     tlsd_close(struct Client* cptr);
int     tlsd_parse_buffer(struct Client *cptr);

// Event loop integration
void    tlsd_eventloop_callback(struct Event *ev);

/** Initialize TLS session management */
void tls_session_init(void);

/** Add a new TLS session */
struct Connection* tls_session_add(struct Client* cptr);

/** Find a TLS session by ID */
struct Connection* tls_session_find(uint32_t session_id);

/** Remove a TLS session */
void tls_session_remove(struct Connection* conn);

/** Clean up old sessions */
void tls_session_cleanup(void);

#endif // INCLUDED_ircd_tls_h
