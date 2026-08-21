/*
 * IRC - Internet Relay Chat, ircd/send.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
/** @file
 * @brief Send messages to certain targets.
 * @version $Id$
 */
#include "config.h"

#include "send.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "msgq.h"
#include "msg_tag.h"
#include "websocket.h"
#include "numnicks.h"
#include "parse.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>

/** Last used marker value. */
static int sentalong_marker;
/** Array of users with the corresponding server notice mask bit set. */
struct SLink *opsarray[32];     /* don't use highest bit unless you change
				   atoi to strtoul in sendto_op_mask() */
/** Linked list of all connections with data queued to send. */
static struct Connection *send_queues;

/*
 * dead_link
 *
 * An error has been detected. The link *must* be closed,
 * but *cannot* call ExitClient (m_bye) from here.
 * Instead, mark it with FLAG_DEADSOCKET. This should
 * generate ExitClient from the main loop.
 *
 * If 'notice' is not NULL, it is assumed to be a format
 * for a message to local opers. It can contain only one
 * '%s', which will be replaced by the sockhost field of
 * the failing link.
 *
 * Also, the notice is skipped for "uninteresting" cases,
 * like Persons and yet unknown connections...
 */
/** Mark a client as dead, even if they are not the current message source.
 * This is done by setting the DEADSOCKET flag on the user and letting the
 * main loop perform the actual exit logic.
 * @param[in,out] to Client being killed.
 * @param[in] notice Message for local opers.
 */
static void dead_link(struct Client *to, char *notice)
{
  SetFlag(to, FLAG_DEADSOCKET);
  /*
   * If because of BUFFERPOOL problem then clean dbuf's now so that
   * notices don't hurt operators below.
   */
  DBufClear(&(cli_recvQ(to)));
  MsgQClear(&(cli_sendQ(to)));
  client_drop_sendq(cli_connect(to));

  /*
   * Keep a copy of the last comment, for later use...
   */
  ircd_strncpy(cli_info(to), notice, REALLEN);

  if (!IsUser(to) && !IsUnknown(to) && !HasFlag(to, FLAG_CLOSING))
    sendto_opmask_butone(0, SNO_OLDSNO, "%s for %s", cli_info(to), cli_name(to));
  Debug((DEBUG_ERROR, cli_info(to)));
}

/** Test whether we can send to a client.
 * @param[in] to Client we want to send to.
 * @return Non-zero if we can send to the client.
 */
static int can_send(struct Client* to)
{
  assert(0 != to);
  return (IsDead(to) || IsMe(to) || -1 == cli_fd(to)) ? 0 : 1;
}

/** Close the connection with the highest sendq.
 * This should be called when we need to free buffer memory.
 * @param[in] servers_too If non-zero, consider killing servers, too.
 */
void
kill_highest_sendq(int servers_too)
{
  int i;
  unsigned int highest_sendq = 0;
  struct Client *highest_client = 0;

  for (i = HighestFd; i >= 0; i--)
  {
    if (!LocalClientArray[i] || (!servers_too && cli_serv(LocalClientArray[i])))
      continue; /* skip servers */
    
    /* If this sendq is higher than one we last saw, remember it */
    if (MsgQLength(&(cli_sendQ(LocalClientArray[i]))) > highest_sendq)
    {
      highest_client = LocalClientArray[i];
      highest_sendq = MsgQLength(&(cli_sendQ(highest_client)));
    }
  }

  if (highest_client)
    dead_link(highest_client, "Buffer allocation error");
}

/*
 * flush_connections
 *
 * Used to empty all output buffers for all connections. Should only
 * be called once per scan of connections. There should be a select in
 * here perhaps but that means either forcing a timeout or doing a poll.
 * When flushing, all we do is empty the obuffer array for each local
 * client and try to send it. if we cant send it, it goes into the sendQ
 * -avalon
 */
/** Flush data queued for one or all connections.
 * @param[in] cptr Client to flush (if NULL, do all).
 */
void flush_connections(struct Client* cptr)
{
  if (cptr) {
    send_queued(cptr);
  }
  else {
    struct Connection* con;
    for (con = send_queues; con; con = con_next(con)) {
      assert(0 < MsgQLength(&(con_sendQ(con))));
      send_queued(con_client(con));
    }
  }
}

/*
 * send_queued
 *
 * This function is called from the main select-loop (or whatever)
 * when there is a chance that some output would be possible. This
 * attempts to empty the send queue as far as possible...
 */
/** Attempt to send data queued for a client.
 * @param[in] to Client to send data to.
 */
void send_queued(struct Client *to)
{
  assert(0 != to);
  assert(0 != cli_local(to));

  if (IsBlocked(to) || !can_send(to))
    return;                     /* Don't bother */

  /* If we're still negotiating TLS, don't try to send data yet */
  if (IsTLS(to) && IsNegotiatingTLS(to))
    return;

  while (MsgQLength(&(cli_sendQ(to))) > 0) {
    unsigned int len;

    if ((len = deliver_it(to, &(cli_sendQ(to))))) {
      msgq_delete(&(cli_sendQ(to)), len);
      cli_lastsq(to) = MsgQLength(&(cli_sendQ(to))) / 1024;
      if (IsBlocked(to)) {
        update_write(to);
        return;
      }
    }
    else {
      if (IsDead(to)) {
        char tmp[512];
        sprintf(tmp,"Write error: %s",(strerror(cli_error(to))) ? (strerror(cli_error(to))) : "Unknown error" );
        dead_link(to, tmp);
      }
      return;
    }
  }

  /* Ok, sendq is now empty... */
  client_drop_sendq(cli_connect(to));
  update_write(to);
}

/** Queue raw octets on a client's sendq without IRC or WebSocket framing.
 *
 * Used for TLS wire writes (HTTP 101, RFC6455 ping/pong) where send_buffer()
 * must not run websocket_frame_msgbuf().
 *
 * The caller retains ownership of \a mb and must msgq_clean() it afterward,
 * matching send_buffer() callers.
 */
void
send_raw_buffer(struct Client *to, struct MsgBuf *mb, int prio)
{
  assert(0 != to);
  assert(0 != mb);

  if (cli_from(to))
    to = cli_from(to);

  if (!can_send(to))
    return;

  if (MsgQLength(&(cli_sendQ(to))) > get_sendq(to)) {
    if (IsServer(to))
      sendto_opmask_butone(0, SNO_OLDSNO, "Max SendQ limit exceeded for %C: "
			   "%zu > %zu", to, MsgQLength(&(cli_sendQ(to))),
			   get_sendq(to));
    dead_link(to, "Max sendQ exceeded");
    return;
  }

  msgq_add(&(cli_sendQ(to)), mb, prio);
  client_add_sendq(cli_connect(to), &send_queues);
  update_write(to);

  ++(cli_sendM(to));
  ++(cli_sendM(&me));

  /* Small, latency-sensitive wire writes (HTTP 101, RFC6455 ping/pong): flush
   * immediately. The 2 KiB batching rule in send_buffer() is for IRC volume. */
  send_queued(to);
}

/** Immutable per-message tag context.  Small enough to stack on any send
 * path (single-recipient sends carry only this, not the full cache). */
struct MsgTagCtx {
  struct MsgTag *tags;        /**< Tags parsed from the current input line. */
  time_t         local_time;  /**< Delivery time for server-time / @time=. */
  const char    *tok;         /**< Command token for S2S policy (or NULL). */
  int            client_relay;   /**< Has relayable client-only (+) tags. */
  int            s2s_needs_time; /**< Invent/forward @time= on S2S for this command. */
};

/** Per-fan-out prefix cache: amortizes prefix formatting across many local
 * recipients.  Embeds the message context and adds the (large) scratch
 * buffer, so it is only worth stacking on paths that actually fan out to
 * multiple local clients. */
struct TagSendCache {
  struct MsgTagCtx ctx;
  unsigned int     profile;
  unsigned int     prefix_len;
  char             prefix[OUTBOUND_TAG_MAX];
};

/** Populate a per-message tag context.  \a tok is the command token (for
 * S2S @time= / TAGMSG policy), or NULL when no command context applies. */
static void
msgtagctx_init(struct MsgTagCtx *ctx, const char *tok)
{
  ctx->tags = parse_tags();
  ctx->local_time = CurrentTime;
  ctx->tok = tok;
  ctx->client_relay = msg_tag_have_client_relay(ctx->tags);
  ctx->s2s_needs_time = tok ? msg_tag_s2s_needs_time(tok) : 0;
}

static void
tagsendcache_init(struct TagSendCache *cache)
{
  msgtagctx_init(&cache->ctx, NULL);
  cache->profile = (unsigned int)-1;
  cache->prefix_len = 0;
}

static void
tagsendcache_init_cmd(struct TagSendCache *cache, const char *tok)
{
  msgtagctx_init(&cache->ctx, tok);
  cache->profile = (unsigned int)-1;
  cache->prefix_len = 0;
}

/** IRCv3 labeled-response: output deferred for a client during one
 * capture's active window.  \a body is a heap copy of the pre-tag-prefix
 * wire line (not a reference-counted MsgBuf -- avoids entangling this with
 * msgq.c's buffer pool/refcount contract for what is normally 0-1 lines). */
struct LabelDeferred {
  char *body;
  unsigned int len;
  int prio;
  struct MsgTagCtx tagctx;    /**< copied by value: tags/tok/local_time/etc. */
  struct Client *from;
  struct LabelDeferred *next;
};

/** Safety valve against a labeled command whose reply fans out to an
 * unbounded number of lines (e.g. LIST/WHO on a large network): stop
 * deferring, flush what is buffered as a batch, and let the remainder
 * through unlabeled rather than growing this list without bound.
 *
 * Sized for a genuinely large network's LIST (thousands of channels,
 * not hundreds) to stay inside one clean batch rather than degrading to
 * unlabeled output for a perfectly ordinary-sized response. */
#define LABEL_CAPTURE_MAX_COUNT 5000
#define LABEL_CAPTURE_MAX_BYTES 1048576

/** The one capture (among possibly several outstanding on its owning
 * client) currently receiving anything sent to that client -- valid only
 * for the duration of a synchronous command dispatch or a single
 * continuation tick (see label_capture_start()/reopen()/close_window()).
 * A client's other, parked captures are untouched by send_buffer() until
 * something explicitly reopens them. */
static struct Client *label_capture_active_client;
static struct LabelCapture *label_capture_active_node;

static void label_capture_append(struct Client *to, struct Client *from,
                                 struct MsgBuf *buf, int prio,
                                 const struct MsgTagCtx *ctx,
                                 struct TagSendCache *cache);

static struct MsgBuf *
make_wire_msgbuf(struct Client *to, struct MsgBuf *body,
                 const char *prefix, unsigned int prefix_len)
{
  struct MsgBuf *wire = body;

  if (prefix_len > 0) {
    struct MsgBuf *combined;

    combined = msgq_raw_alloc(to, prefix_len + body->length + 1);
    if (!combined)
      return body;
    memcpy(combined->msg, prefix, prefix_len);
    memcpy(combined->msg + prefix_len, body->msg, body->length);
    combined->length = prefix_len + body->length;
    wire = combined;
  }

  return wire;
}

/** Try to send a buffer to a client, queueing it if needed.
 * @param[in,out] to Client to send message to.
 * @param[in] from Message source (for account-tag; may be NULL).
 * @param[in] buf Message body (without tags).
 * @param[in] prio If non-zero, send as high priority.
 * @param[in] ctx Optional per-message tag context (may be NULL).  Ignored
 *                when \a cache is non-NULL, which carries its own context.
 * @param[in] cache Optional tag-prefix cache for fan-out (may be NULL).
 */
void send_buffer(struct Client* to, struct Client* from, struct MsgBuf* buf, int prio,
                 const struct MsgTagCtx *ctx, struct TagSendCache *cache)
{
  struct MsgBuf *wire = buf;
  struct MsgBuf *owned = 0;
  struct MsgBuf *ws_framed = 0;
  char tagbuf[OUTBOUND_TAG_MAX];
  const char *prefix = 0;
  unsigned int taglen = 0;
  const struct MsgTagCtx *tctx = cache ? &cache->ctx : ctx;
  time_t local_time = tctx ? tctx->local_time : CurrentTime;
  struct MsgTag *tags = tctx ? tctx->tags : parse_tags();

  assert(0 != to);
  assert(0 != buf);

  if (cli_from(to))
    to = cli_from(to);

  if (!can_send(to))
    /*
     * This socket has already been marked as dead
     */
    return;

  if (MsgQLength(&(cli_sendQ(to))) > get_sendq(to)) {
    if (IsServer(to))
      sendto_opmask_butone(0, SNO_OLDSNO, "Max SendQ limit exceeded for %C: "
			   "%zu > %zu", to, MsgQLength(&(cli_sendQ(to))),
			   get_sendq(to));
    dead_link(to, "Max sendQ exceeded");
    return;
  }

  if (to == label_capture_active_client) {
    label_capture_append(to, from, buf, prio, ctx, cache);
    return;
  }

  if (IsServer(to)) {
    /* Older peers cannot parse @tags or TAGMSG (TM); gate on NETWORK_FEATURES.
     * Invent @time= only for client-event commands (see s2s_needs_time). */
    if (!feature_bool(FEAT_NETWORK_FEATURES)) {
      if (tctx && tctx->tok && !strcmp(tctx->tok, TOK_TAGMSG))
        return;
    } else {
      int invent = tctx ? tctx->s2s_needs_time : 0;
      taglen = msg_tag_format_s2s(tagbuf, sizeof(tagbuf), tags, local_time,
                                  invent);
      prefix = taglen ? tagbuf : 0;
    }
  } else if (cache) {
    if (cache->ctx.client_relay) {
      taglen = msg_tag_format(cache->prefix, sizeof(cache->prefix),
                              to, from, cache->ctx.tags, cache->ctx.local_time);
      prefix = taglen ? cache->prefix : 0;
    } else {
      unsigned int profile = msg_tag_profile(to);

      if (profile != cache->profile) {
        cache->profile = profile;
        cache->prefix_len = profile
          ? msg_tag_format(cache->prefix, sizeof(cache->prefix),
                           to, from, cache->ctx.tags, cache->ctx.local_time)
          : 0;
      }
      taglen = cache->prefix_len;
      prefix = taglen ? cache->prefix : 0;
    }
  } else {
    taglen = msg_tag_format(tagbuf, sizeof(tagbuf), to, from, tags, local_time);
    prefix = taglen ? tagbuf : 0;
  }

  if (prefix && taglen) {
    wire = make_wire_msgbuf(to, buf, prefix, taglen);
    if (wire != buf)
      owned = wire;
  }

  Debug((DEBUG_SEND, "Sending [%p] to %s", wire, cli_name(to)));


  /* For websocket clients, replace the IRC MsgBuf with a framed one before
   * queueing. The original buf is still owned and cleaned by the caller
   * (sendrawto_one, sendcmdto_one, ...); the framed buffer is owned here. */
  if (IsWebsocket(to)) {
    ws_framed = websocket_frame_msgbuf(to, wire->msg, wire->length);
    if (!ws_framed) {
      if (owned)
        msgq_clean(owned);
      dead_link(to, "Websocket frame error");
      return;
    }
    wire = ws_framed;
  }

  msgq_add(&(cli_sendQ(to)), wire, prio);
  /* msgq_add() took its own reference on the queued buffer, so release the
   * reference websocket_frame_msgbuf() handed us. Without this, one MsgBuf
   * leaks per outbound WebSocket message and exhausts the buffer pool. */
  if (ws_framed)
    msgq_clean(ws_framed);
  if (owned)
    msgq_clean(owned);
  client_add_sendq(cli_connect(to), &send_queues);
  update_write(to);

  /*
   * Update statistics. The following is slightly incorrect
   * because it counts messages even if queued, but bytes
   * only really sent. Queued bytes get updated in SendQueued.
   */
  ++(cli_sendM(to));
  ++(cli_sendM(&me));
  /*
   * This little bit is to stop the sendQ from growing too large when
   * there is no need for it to. Thus we call send_queued() every time
   * 2k has been added to the queue since the last non-fatal write.
   * Also stops us from deliberately building a large sendQ and then
   * trying to flood that link with data (possible during the net
   * relinking done by servers with a large load).
   */
  if (MsgQLength(&(cli_sendQ(to))) / 1024 > cli_lastsq(to))
    send_queued(to);
}

/* --- IRCv3 labeled-response capture ---------------------------------- */

/** Free \a lc's deferred-line chain and the node itself.  Caller must
 * already have unlinked \a lc from its owning client's list. */
static void
label_capture_free_node(struct LabelCapture *lc)
{
  struct LabelDeferred *entry = lc->head;

  while (entry) {
    struct LabelDeferred *next = entry->next;
    MyFree(entry->body);
    MyFree(entry);
    entry = next;
  }
  MyFree(lc);
}

/** Find \a ref on \a cptr's outstanding-capture list and unlink it.
 * Returns the node (now on no list), or NULL if not found. */
static struct LabelCapture *
label_capture_unlink(struct Client *cptr, const char *ref)
{
  struct LabelCapture **prev = &cli_labelcap(cptr);
  struct LabelCapture *lc;

  for (lc = *prev; lc; prev = &lc->next, lc = lc->next) {
    if (!strcmp(lc->ref, ref)) {
      *prev = lc->next;
      return lc;
    }
  }
  return NULL;
}

static void
label_capture_append(struct Client *to, struct Client *from,
                     struct MsgBuf *buf, int prio,
                     const struct MsgTagCtx *ctx, struct TagSendCache *cache)
{
  const struct MsgTagCtx *tctx = cache ? &cache->ctx : ctx;
  struct LabelCapture *lc = label_capture_active_node;
  struct LabelDeferred *entry;

  if (lc->streaming) {
    /* Re-emit immediately, tagged batch=ref, instead of deferring --
     * the capture-overflow safety valve below does not apply here (there
     * is nothing buffered to overflow). Un-redirected: suspend the
     * window first so this send doesn't recurse back into
     * label_capture_append() for the same capture. Unlike the buffered
     * path (msgq_raw_alloc()'d and cleaned per replayed entry at
     * finish() time), this send_buffer() call goes through the *real*
     * cli_sendQ() -- streamed output is no longer exempt from
     * list_next_channels()'s own sendQ-based pause check the way
     * buffered captures were. */
    struct MsgTag batchtag;
    struct MsgTagCtx streamctx;
    struct MsgBuf *mb;

    if (tctx)
      streamctx = *tctx;
    else
      msgtagctx_init(&streamctx, NULL);

    batchtag.next = streamctx.tags;
    batchtag.key = "batch";
    batchtag.value = lc->ref;
    streamctx.tags = &batchtag;

    label_capture_active_client = NULL;
    label_capture_active_node = NULL;

    mb = msgq_raw_alloc(to, buf->length + 1);
    memcpy(mb->msg, buf->msg, buf->length);
    mb->msg[buf->length] = '\0';
    mb->length = buf->length;

    send_buffer(to, from, mb, prio, &streamctx, NULL);
    msgq_clean(mb);

    label_capture_active_client = to;
    label_capture_active_node = lc;
    return;
  }

  if (lc->count >= LABEL_CAPTURE_MAX_COUNT
      || lc->bytes + buf->length > LABEL_CAPTURE_MAX_BYTES) {
    /* Degrade gracefully: this response no longer fits in one labeled
     * reply. Release what's buffered so far unlabeled (closing a batch
     * here would falsely claim the response ended at the overflow point),
     * then let this and any further lines for this command go out
     * normally. */
    char ref[sizeof(lc->ref)];

    ircd_strncpy(ref, lc->ref, sizeof(ref) - 1);
    ref[sizeof(ref) - 1] = '\0';
    label_capture_close_window();
    label_capture_abort(to, ref);
    send_buffer(to, from, buf, prio, ctx, cache);
    return;
  }

  entry = (struct LabelDeferred *)MyMalloc(sizeof(*entry));
  entry->body = (char *)MyMalloc(buf->length + 1);
  memcpy(entry->body, buf->msg, buf->length);
  entry->body[buf->length] = '\0';
  entry->len = buf->length;
  entry->prio = prio;
  entry->from = from;
  entry->next = NULL;
  if (tctx)
    entry->tagctx = *tctx;
  else
    msgtagctx_init(&entry->tagctx, NULL);

  *lc->tail = entry;
  lc->tail = &entry->next;
  ++lc->count;
  lc->bytes += buf->length;
}

/** Send one server-generated line to \a to with an explicit tag context,
 * bypassing capture (label_capture_close_window() must already have been
 * called if a capture was active for \a to) and bypassing parse_tags()
 * (unlike sendcmdto_one(), which always picks up the *current* input
 * line's tags -- these lines need their own, synthetic tag list instead).
 *
 * \a to may be a genuine local client (the common case) or a *remote*
 * one -- e.g. parse_server()'s labeled-response wrapper finishing a
 * capture kept for a remote requester whose command we answered on its
 * behalf (see hunt_server_cmd()). In the local case the wire form is the
 * plain, unaddressed client-facing one (":<from> BATCH +ref type", one
 * recipient implied by the connection itself). Addressed to a server,
 * BATCH/ACK need an explicit target -- unlike numerics, which always
 * carry one -- so an intermediate hop's ms_batch()/ms_ack() (m_batch.c)
 * knows who to relay it to next. */
static void
label_emit(struct Client *to, struct Client *from, int prio,
          struct MsgTagCtx *tagctx, const char *cmd, const char *tok,
          const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Client *dest = cli_from(to);
  const char *word = (IsServer(dest) || IsMe(dest)) ? tok : cmd;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  if (IsServer(dest))
    mb = msgq_make(dest, "%:#C %s %C %v", from, word, to, &vd);
  else
    mb = msgq_make(dest, "%:#C %s %v", from, word, &vd);
  va_end(vd.vd_args);

  send_buffer(to, from, mb, prio, tagctx, NULL);

  msgq_clean(mb);
}

struct LabelCapture *
label_capture_start(struct Client *cptr, const char *label)
{
  static unsigned int label_ref_seq;
  /* Track the *owning* client consistently with send_buffer()'s own
   * "to == label_capture_active_client" check, which always compares
   * against cli_from(to). For a genuine local client cli_from(cptr) ==
   * cptr, so this changes nothing for the pre-existing (local-only)
   * callers; it matters once parse_server() starts captures for a
   * *remote* requester (cli_connect() aliasing the shared S2S link),
   * where cptr itself would never match what send_buffer() compares. */
  struct Client *owner = cli_from(cptr);
  struct LabelCapture *lc = (struct LabelCapture *)MyMalloc(sizeof(*lc));

  ircd_snprintf(0, lc->ref, sizeof(lc->ref), "%x", ++label_ref_seq);
  ircd_strncpy(lc->value, label, sizeof(lc->value) - 1);
  lc->value[sizeof(lc->value) - 1] = '\0';
  lc->head = NULL;
  lc->tail = &lc->head;
  lc->count = 0;
  lc->bytes = 0;
  lc->streaming = 0;

  lc->next = cli_labelcap(owner);
  cli_labelcap(owner) = lc;

  label_capture_active_client = owner;
  label_capture_active_node = lc;

  return lc;
}

/** Convert the capture currently active for \a cptr into a streaming one
 * and emit its BATCH open line immediately, for a response that's
 * unconditionally multi-line and may span many event-loop ticks (LIST)
 * -- where deferring the ACK/single-line/BATCH decision to the end (the
 * ordinary label_capture_start()/finish() contract) doesn't make sense:
 * there's nothing to decide, and buffering an unbounded number of lines
 * in memory until some eventual finish() is wasteful when they could
 * just go out as they're produced.
 *
 * Must be called with a capture already active for cptr (i.e. after
 * parse.c's normal label_capture_start() for this dispatch) -- LIST
 * doesn't start its own capture, it upgrades the one already there. Any
 * lines already buffered on it (e.g. RPL_LISTSTART, sent before m_list()
 * gets far enough to know it's starting a genuine paginated listing and
 * call this) are flushed in order, tagged batch=ref, right after the
 * open line -- they predate the decision to stream, but the client must
 * still see them inside the batch, not lost.
 *
 * Returns the ref to store (e.g. into ListingArgs.label_ref), or NULL if
 * there was no active capture (the command wasn't labeled). */
const char *
label_capture_stream_active(struct Client *cptr)
{
  struct Client *owner = cli_from(cptr);
  struct LabelCapture *lc;
  struct MsgTag labeltag;
  struct MsgTagCtx opentagctx;
  struct LabelDeferred *entry;

  if (owner != label_capture_active_client || !label_capture_active_node)
    return NULL;

  lc = label_capture_active_node;
  lc->streaming = 1;

  /* Emit the opening line (and any pre-existing buffered entries) un-
   * redirected: suspend the window first so these sends aren't captured
   * by the very capture they belong to. */
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;

  labeltag.next = NULL;
  labeltag.key = "label";
  labeltag.value = lc->value;

  memset(&opentagctx, 0, sizeof(opentagctx));
  opentagctx.tags = &labeltag;
  opentagctx.local_time = CurrentTime;
  opentagctx.tok = TOK_BATCH;

  label_emit(cptr, &me, 0, &opentagctx, CMD_BATCH, "+%s labeled-response", lc->ref);

  entry = lc->head;
  lc->head = NULL;
  lc->tail = &lc->head;
  lc->count = 0;
  lc->bytes = 0;
  while (entry) {
    struct LabelDeferred *next = entry->next;
    struct MsgTag batchtag;
    struct MsgBuf *mb;

    batchtag.next = entry->tagctx.tags;
    batchtag.key = "batch";
    batchtag.value = lc->ref;
    entry->tagctx.tags = &batchtag;

    mb = msgq_raw_alloc(cptr, entry->len + 1);
    memcpy(mb->msg, entry->body, entry->len);
    mb->msg[entry->len] = '\0';
    mb->length = entry->len;

    send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
    msgq_clean(mb);

    MyFree(entry->body);
    MyFree(entry);
    entry = next;
  }

  label_capture_active_client = owner;
  label_capture_active_node = lc;

  return lc->ref;
}

void
label_capture_reopen(struct Client *cptr, const char *ref)
{
  struct Client *owner = cli_from(cptr);
  struct LabelCapture *lc;

  if (!ref || !*ref)
    return;

  for (lc = cli_labelcap(owner); lc; lc = lc->next) {
    if (!strcmp(lc->ref, ref)) {
      label_capture_active_client = owner;
      label_capture_active_node = lc;
      return;
    }
  }
}

void
label_capture_close_window(void)
{
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;
}

/** Snapshot the currently-active window so a caller can temporarily
 * redirect it (e.g. reopen a *different* capture to fold one more line
 * into it) and put the original back afterward with
 * label_capture_restore_active(). Unlike finish()/abort(), which only
 * protect their own internal replay sends, this covers sends a caller
 * makes *before* invoking finish()/abort() -- see m_list.c's superseded-
 * listing handling. */
void
label_capture_save_active(struct Client **client_out, struct LabelCapture **node_out)
{
  *client_out = label_capture_active_client;
  *node_out = label_capture_active_node;
}

/** Restore a window previously captured by label_capture_save_active(). */
void
label_capture_restore_active(struct Client *client, struct LabelCapture *node)
{
  label_capture_active_client = client;
  label_capture_active_node = node;
}

/** If \a ref (belonging to \a cptr) is the currently-active window, close
 * it first -- finish()/abort() must never let their own replay sends
 * re-enter capture for the node they are about to free. Callers are
 * expected to have already called label_capture_close_window()
 * themselves; this is a defensive backstop, not the primary mechanism. */
static void
label_capture_close_if_active(struct Client *cptr, const char *ref)
{
  struct Client *owner = cli_from(cptr);

  if (label_capture_active_client == owner && label_capture_active_node
      && !strcmp(label_capture_active_node->ref, ref))
    label_capture_close_window();
}

void
label_capture_finish(struct Client *cptr, const char *ref)
{
  struct Client *saved_active_client;
  struct LabelCapture *saved_active_node;
  struct LabelCapture *lc;
  unsigned int count;

  label_capture_close_if_active(cptr, ref);

  lc = label_capture_unlink(cptr, ref);
  if (!lc)
    return; /* not outstanding for this client: defensive no-op */

  /* The sends below must never be captured by a *different* window that
   * happens to be active for the same client right now -- e.g. an
   * interrupting command aborting an older parked capture while its own
   * reply is being captured. Suspend whatever's active, restore it once
   * we're done. */
  saved_active_client = label_capture_active_client;
  saved_active_node = label_capture_active_node;
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;

  if (lc->streaming) {
    /* The open line and every body line already went out as they were
     * produced (label_capture_append()); nothing was buffered, so there
     * is nothing to decide or replay -- just close the batch. */
    struct MsgTagCtx closetagctx;

    memset(&closetagctx, 0, sizeof(closetagctx));
    closetagctx.local_time = CurrentTime;
    closetagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &closetagctx, CMD_BATCH, "-%s", lc->ref);

    label_capture_active_client = saved_active_client;
    label_capture_active_node = saved_active_node;

    label_capture_free_node(lc);
    return;
  }

  count = lc->count;

  if (count == 0) {
    struct MsgTag labeltag;
    struct MsgTagCtx tagctx;

    labeltag.next = NULL;
    labeltag.key = "label";
    labeltag.value = lc->value;

    memset(&tagctx, 0, sizeof(tagctx));
    tagctx.tags = &labeltag;
    tagctx.local_time = CurrentTime;
    tagctx.tok = TOK_ACK;

    label_emit(cptr, &me, 0, &tagctx, CMD_ACK, "");
  } else if (count == 1) {
    struct LabelDeferred *entry = lc->head;
    struct MsgTag labeltag;
    struct MsgBuf *mb;

    labeltag.next = entry->tagctx.tags;
    labeltag.key = "label";
    labeltag.value = lc->value;
    entry->tagctx.tags = &labeltag;

    mb = msgq_raw_alloc(cptr, entry->len + 1);
    memcpy(mb->msg, entry->body, entry->len);
    mb->msg[entry->len] = '\0';
    mb->length = entry->len;

    send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
    msgq_clean(mb);
  } else {
    struct MsgTag labeltag;
    struct MsgTagCtx opentagctx, closetagctx;
    struct LabelDeferred *entry;

    labeltag.next = NULL;
    labeltag.key = "label";
    labeltag.value = lc->value;

    memset(&opentagctx, 0, sizeof(opentagctx));
    opentagctx.tags = &labeltag;
    opentagctx.local_time = CurrentTime;
    opentagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &opentagctx, CMD_BATCH,
              "+%s labeled-response", lc->ref);

    for (entry = lc->head; entry; entry = entry->next) {
      struct MsgTag batchtag;
      struct MsgBuf *mb;

      batchtag.next = entry->tagctx.tags;
      batchtag.key = "batch";
      batchtag.value = lc->ref;
      entry->tagctx.tags = &batchtag;

      mb = msgq_raw_alloc(cptr, entry->len + 1);
      memcpy(mb->msg, entry->body, entry->len);
      mb->msg[entry->len] = '\0';
      mb->length = entry->len;

      send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
      msgq_clean(mb);
    }

    memset(&closetagctx, 0, sizeof(closetagctx));
    closetagctx.local_time = CurrentTime;
    closetagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &closetagctx, CMD_BATCH, "-%s", lc->ref);
  }

  label_capture_active_client = saved_active_client;
  label_capture_active_node = saved_active_node;

  label_capture_free_node(lc);
}

void
label_capture_abort(struct Client *cptr, const char *ref)
{
  struct Client *saved_active_client;
  struct LabelCapture *saved_active_node;
  struct LabelCapture *lc;
  struct LabelDeferred *entry;

  label_capture_close_if_active(cptr, ref);

  lc = label_capture_unlink(cptr, ref);
  if (!lc)
    return; /* not outstanding for this client: defensive no-op */

  /* See label_capture_finish(): suspend whatever window is active for
   * this client right now, so the replay below can't be swept into a
   * different, currently-in-progress capture. */
  saved_active_client = label_capture_active_client;
  saved_active_node = label_capture_active_node;
  label_capture_active_client = NULL;
  label_capture_active_node = NULL;

  if (lc->streaming) {
    /* Nothing was buffered (every line already went out live, tagged
     * batch=ref, as it was produced) -- an already-sent line can't be
     * un-sent, so there's nothing to replay unlabeled here the way the
     * buffered path below does. The honest close for a stream that
     * can't honestly continue is the same as a clean finish: just close
     * the batch. (Nothing currently calls abort() on a streaming
     * capture -- LIST always finish()es it, even when superseded, see
     * m_list.c -- this branch is defensive parity only.) */
    struct MsgTagCtx closetagctx;

    memset(&closetagctx, 0, sizeof(closetagctx));
    closetagctx.local_time = CurrentTime;
    closetagctx.tok = TOK_BATCH;

    label_emit(cptr, &me, 0, &closetagctx, CMD_BATCH, "-%s", lc->ref);

    label_capture_active_client = saved_active_client;
    label_capture_active_node = saved_active_node;

    label_capture_free_node(lc);
    return;
  }

  /* Replay exactly what was captured, with no label/batch tag added --
   * i.e. as if capture had never intercepted it. This is the outcome the
   * spec itself sanctions for responses a server cannot honestly finish
   * labeling (e.g. its own WHOIS-through-a-netsplit example): "servers
   * might not produce a labeled response... clients should handle these
   * cases as they would normally for a server without support for
   * labeled responses." */
  for (entry = lc->head; entry; entry = entry->next) {
    struct MsgBuf *mb;

    mb = msgq_raw_alloc(cptr, entry->len + 1);
    memcpy(mb->msg, entry->body, entry->len);
    mb->msg[entry->len] = '\0';
    mb->length = entry->len;

    send_buffer(cptr, entry->from, mb, entry->prio, &entry->tagctx, NULL);
    msgq_clean(mb);
  }

  label_capture_active_client = saved_active_client;
  label_capture_active_node = saved_active_node;

  label_capture_free_node(lc);
}

void
label_capture_client_gone(struct Client *cptr)
{
  struct LabelCapture *lc;

  if (label_capture_active_client == cptr)
    label_capture_close_window();

  while ((lc = cli_labelcap(cptr)) != NULL) {
    cli_labelcap(cptr) = lc->next;
    label_capture_free_node(lc);
  }
}

/*
 * Send a msg to all ppl on servers/hosts that match a specified mask
 * (used for enhanced PRIVMSGs)
 *
 *  addition -- Armin, 8jun90 (gruner@informatik.tu-muenchen.de)
 */

/** Check whether a client matches a target mask.
 * @param[in] from Client trying to send a message (ignored).
 * @param[in] one Client being considered as a target.
 * @param[in] mask Mask for matching against.
 * @param[in] what Type of match (either MATCH_HOST or MATCH_SERVER).
 * @return Non-zero if \a one matches, zero if not.
 */
static int match_it(struct Client *from, struct Client *one, const char *mask, int what)
{
  switch (what)
  {
    case MATCH_HOST:
      return (match(mask, cli_user(one)->host) == 0 ||
        (HasHiddenHost(one) && match(mask, cli_user(one)->realhost) == 0));
    case MATCH_SERVER:
    default:
      return (match(mask, cli_name(cli_user(one)->server)) == 0);
  }
}

/** Send an unprefixed line to a client.
 * @param[in] to Client receiving message.
 * @param[in] pattern Format string of message.
 */
void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  struct MsgBuf *mb;
  va_list vl;

  va_start(vl, pattern);
  mb = msgq_vmake(to, pattern, vl);
  va_end(vl);

  send_buffer(to, NULL, mb, 0, NULL, NULL);

  msgq_clean(mb);
}

/** Send a (prefixed) command to a single client.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
		   struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct MsgTagCtx mctx;

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		 &vd);

  va_end(vd.vd_args);

  msgtagctx_init(&mctx, tok);
  send_buffer(to, from, mb, 0, &mctx, NULL);

  msgq_clean(mb);
}

/** Like sendcmdto_one(), but for hunt_server_cmd()-style forwarding: when
 * \a from has an active labeled-response capture (only possible with
 * FEAT_NETWORK_FEATURES on -- see msg_tag_key_federated()), propagate it
 * as @label= on the forwarded line and silently hand the local capture
 * off instead of leaving it to close as a premature, empty ACK the
 * moment the caller's handler returns with no local output.
 *
 * The remote server -- if it also runs labeled-response and recognizes
 * the inbound label (parse_server()'s wrapper) -- answers *for* this
 * label instead, relayed back through ms_batch()/ms_ack() (m_batch.c).
 * If NETWORK_FEATURES is off, or there is no active capture (an
 * unlabeled command, or one that already produced local output before
 * deciding to forward), this is exactly sendcmdto_one().
 *
 * @param[in] from Client sending the command (the original requester).
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_hunted(struct Client *from, const char *cmd, const char *tok,
			  struct Client *to, const char *pattern, ...)
{
  struct Client *owner = cli_from(from);
  struct VarData vd;
  struct MsgBuf *mb;
  struct MsgTagCtx ctx;
  struct MsgTag labeltag;
  char label[LABEL_VALUE_MAX + 1];
  int labeled = 0;

  if (feature_bool(FEAT_NETWORK_FEATURES) && owner == label_capture_active_client
      && label_capture_active_node) {
    struct LabelCapture *lc = label_capture_active_node;
    struct LabelCapture *unlinked;

    ircd_strncpy(label, lc->value, sizeof(label) - 1);
    label[sizeof(label) - 1] = '\0';

    label_capture_active_client = NULL;
    label_capture_active_node = NULL;
    if ((unlinked = label_capture_unlink(owner, lc->ref)))
      label_capture_free_node(unlinked);

    labeled = 1;
  }

  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		 &vd);
  va_end(vd.vd_args);

  if (labeled) {
    labeltag.next = NULL;
    labeltag.key = "label";
    labeltag.value = label;

    memset(&ctx, 0, sizeof(ctx));
    ctx.tags = &labeltag;
    ctx.local_time = CurrentTime;
    ctx.tok = tok;
    ctx.s2s_needs_time = tok ? msg_tag_s2s_needs_time(tok) : 0;
  } else
    msgtagctx_init(&ctx, tok);

  send_buffer(to, from, mb, 0, &ctx, NULL);

  msgq_clean(mb);
}

/**
 * Send a (prefixed) command to a single client in the priority queue.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_prio_one(struct Client *from, const char *cmd, const char *tok,
			struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct MsgTagCtx mctx;

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		 &vd);

  va_end(vd.vd_args);

  msgtagctx_init(&mctx, tok);
  send_buffer(to, from, mb, 1, &mctx, NULL);

  msgq_clean(mb);
}

/**
 * Send a (prefixed) command to all servers matching or not matching a
 * flag but one.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] require Only send to servers with this Flag bit set.
 * @param[in] forbid Do not send to servers with this Flag bit set.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct DLink *lp;
  struct MsgTagCtx mctx;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* use token */
  mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  msgtagctx_init(&mctx, tok);
  /* send it to our downlinks */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    if ((require < FLAG_LAST_FLAG) && !HasFlag(lp->value.cptr, require))
      continue;
    if ((forbid < FLAG_LAST_FLAG) && HasFlag(lp->value.cptr, forbid))
      continue;
    send_buffer(lp->value.cptr, NULL, mb, 0, &mctx, NULL);
  }

  msgq_clean(mb);
}

/**
 * Send a (prefixed) command to all servers but one.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
			   const char *tok, struct Client *one,
			   const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct DLink *lp;
  struct MsgTagCtx mctx;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* use token */
  mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  msgtagctx_init(&mctx, tok);
  /* send it to our downlinks */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    send_buffer(lp->value.cptr, NULL, mb, 0, &mctx, NULL);
  }

  msgq_clean(mb);
}

/** Safely increment the sentalong marker.
 * This increments the sentalong marker.  Since new connections will
 * have con_sentalong() == 0, and to avoid confusion when the counter
 * wraps, we reset all sentalong markers to zero when the sentalong
 * marker hits zero.
 * @param[in,out] one Client to mark with new sentalong marker (if any).
 */
static void
bump_sentalong(struct Client *one)
{
  if (!++sentalong_marker)
  {
    int ii;
    for (ii = 0; ii < HighestFd; ++ii)
      if (LocalClientArray[ii])
        cli_sentalong(LocalClientArray[ii]) = 0;
    ++sentalong_marker;
  }
  if (one)
    cli_sentalong(one) = sentalong_marker;
}

/** Send a (prefixed) command to all channels that \a from is on.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_common_channels_butone(struct Client *from, const char *cmd,
				      const char *tok, struct Client *one,
				      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Membership *chan;
  struct Membership *member;
  struct TagSendCache tcache;

  assert(0 != from);
  assert(0 != cli_from(from));
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  va_start(vd.vd_args, pattern);

  /* build the buffer */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  tagsendcache_init(&tcache);
  bump_sentalong(from);
  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan) || IsDelayedJoin(chan))
      continue;
    for (member = chan->channel->members; member;
	 member = member->next_member)
      if (MyConnect(member->user)
          && -1 < cli_fd(cli_from(member->user))
          && member->user != one
          && cli_sentalong(member->user) != sentalong_marker) {
	cli_sentalong(member->user) = sentalong_marker;
	send_buffer(member->user, from, mb, 0, NULL, &tcache);
      }
  }

  if (MyConnect(from) && from != one)
    send_buffer(from, from, mb, 0, NULL, &tcache);

  msgq_clean(mb);
}

/** Send a (prefixed) command to all channels that \a from is on
 * matching or not matching a capability flag.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] require Only send to clients with this Flag bit set.
 * @param[in] forbid Do not send to clients with this Flag bit set.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_capflag_common_channels_butone(struct Client *from, const char *cmd,
					      const char *tok, struct Client *one,
					      capset_t require, capset_t forbid, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Membership *chan;
  struct Membership *member;
  struct TagSendCache tcache;

  assert(0 != from);
  assert(0 != cli_from(from));
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  va_start(vd.vd_args, pattern);

  /* build the buffer */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  tagsendcache_init(&tcache);
  bump_sentalong(from);
  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan) || IsDelayedJoin(chan))
      continue;

    for (member = chan->channel->members; member;
	 member = member->next_member)
    {
      if (MyConnect(member->user)
          && -1 < cli_fd(cli_from(member->user))
          && member->user != one
          && cli_sentalong(member->user) != sentalong_marker
          && (require == 0 || CapHas(cli_active(member->user), require))
          && (forbid == 0 || !CapHas(cli_active(member->user), forbid)))
      {
          cli_sentalong(member->user) = sentalong_marker;
          send_buffer(member->user, from, mb, 0, NULL, &tcache);
      }
    }
  }

  if (MyConnect(from)
      && from != one
      && (require == 0 || CapHas(cli_active(from), require))
      && (forbid == 0 || !CapHas(cli_active(from), forbid)))
    send_buffer(from, from, mb, 0, NULL, &tcache);

  msgq_clean(mb);
}

/** Send a (prefixed) command to all local users on a channel matching or not matching a capability flag..
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (ignored).
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_DEAF, SKIP_NONOPS, SKIP_NONVOICES indicating which clients to skip.
 * @param[in] require Only send to clients with this Flag bit set.
 * @param[in] forbid Do not send to clients with this Flag bit set.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_capflag_channel_butserv_butone(struct Client *from, const char *cmd,
					      const char *tok, struct Channel *to,
					      struct Client *one, unsigned int skip,
					      capset_t require, capset_t forbid,
					      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Membership *member;
  struct TagSendCache tcache;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* build the buffer */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  tagsendcache_init(&tcache);
  /* send the buffer to each local channel member */
  for (member = to->members; member; member = member->next_member) {
    if (!MyConnect(member->user)
        || member->user == one
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !HasVoice(member))
        || (require && !CapHas(cli_active(member->user), require))
        || (forbid && CapHas(cli_active(member->user), forbid)))
        continue;

    send_buffer(member->user, from, mb, 0, NULL, &tcache);
  }

  msgq_clean(mb);
}

/* Send JOIN to all local channel users matching or not matching
 * capability flags.
 * @param[in] from Client joining the channel.
 * @param[in] chptr Channel being joined.
 * @param[in] require Capability mask to send this message for.
 * @param[in] forbid Capability mask to block this message for.
 */
void sendjointo_channel_butserv(struct Client *from, struct Channel *chptr,
				capset_t require,
				capset_t forbid)
{
  sendcmdto_capflag_channel_butserv_butone(from, CMD_JOIN, chptr, NULL,
    0, require | CAP_EXTJOIN, forbid, "%H %s :%s", chptr,
    IsAccount(from) ? cli_account(from) : "*", cli_info(from));
  sendcmdto_capflag_channel_butserv_butone(from, CMD_JOIN, chptr, NULL,
    0, require, forbid | CAP_EXTJOIN, "%H", chptr);
}

/* Send JOIN to a single user.
 * @param[in] from Client joining the channel.
 * @param[in] chptr Channel being joined.
 * @param[in] one Client to send the message to.
 */
void sendjointo_one(struct Client *from,
		    struct Channel *chptr,
		    struct Client *one)
{
  if (CapHas(cli_active(one), CAP_EXTJOIN))
    sendcmdto_one(from, CMD_JOIN, one, "%H %s :%s", chptr,
      IsAccount(from) ? cli_account(from) : "*", cli_info(from));
  else
    sendcmdto_one(from, CMD_JOIN, one, "%H", chptr);
}

/** Send a (prefixed) command to all local users on a channel.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (ignored).
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_DEAF, SKIP_NONOPS, SKIP_NONVOICES indicating which clients to skip.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
				      const char *tok, struct Channel *to,
				      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Membership *member;
  struct TagSendCache tcache;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* build the buffer */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  tagsendcache_init(&tcache);
  /* send the buffer to each local channel member */
  for (member = to->members; member; member = member->next_member) {
    if (!MyConnect(member->user)
        || member->user == one 
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !HasVoice(member)))
        continue;
      send_buffer(member->user, from, mb, 0, NULL, &tcache);
  }

  msgq_clean(mb);
}

/** Send a (prefixed) command to all servers with users on \a to.
 * Skip \a from and \a one plus those indicated in \a skip.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_NONOPS and SKIP_NONVOICES indicating which clients to skip.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_servers_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *serv_mb;
  struct Membership *member;
  struct MsgTagCtx mctx;

  /* build the buffer */
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%:#C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  msgtagctx_init(&mctx, tok);
  /* send the buffer to each server */
  bump_sentalong(one);
  cli_sentalong(from) = sentalong_marker;
  for (member = to->members; member; member = member->next_member) {
    if (MyConnect(member->user)
        || IsZombie(member)
        || cli_fd(cli_from(member->user)) < 0
        || cli_sentalong(member->user) == sentalong_marker
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !HasVoice(member)))
      continue;
    cli_sentalong(member->user) = sentalong_marker;
    send_buffer(member->user, NULL, serv_mb, 0, &mctx, NULL);
  }
  msgq_clean(serv_mb);
}


/** Send a (prefixed) command to all users on this channel, except for
 * \a one and those matching \a skip.
 * @warning \a pattern must not contain %v.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_NONOPS, SKIP_NONVOICES, SKIP_DEAF, SKIP_BURST.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_butone(struct Client *from, const char *cmd,
			      const char *tok, struct Channel *to,
			      struct Client *one, unsigned int skip,
			      const char *pattern, ...)
{
  struct Membership *member;
  struct VarData vd;
  struct MsgBuf *user_mb;
  struct MsgBuf *serv_mb;
  struct TagSendCache tcache;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  user_mb = msgq_make(0, skip & (SKIP_NONOPS | SKIP_NONVOICES) ? "%:#C %s @%v" : "%:#C %s %v",
                      from, skip & (SKIP_NONOPS | SKIP_NONVOICES) ? MSG_NOTICE : cmd, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  tagsendcache_init_cmd(&tcache, tok);
  /* send buffer along! */
  bump_sentalong(one);
  for (member = to->members; member; member = member->next_member) {
    /* skip one, zombies, and deaf users... */
    if (IsZombie(member) ||
        (skip & SKIP_DEAF && IsDeaf(member->user)) ||
        (skip & SKIP_NONOPS && !IsChanOp(member)) ||
        (skip & SKIP_NONVOICES && !IsChanOp(member) && !HasVoice(member)) ||
        (skip & SKIP_BURST && IsBurstOrBurstAck(cli_from(member->user))) ||
        cli_fd(cli_from(member->user)) < 0 ||
        cli_sentalong(member->user) == sentalong_marker)
      continue;
    cli_sentalong(member->user) = sentalong_marker;

    if (MyConnect(member->user)) /* pick right buffer to send */
      send_buffer(member->user, from, user_mb, 0, NULL, &tcache);
    else
      send_buffer(member->user, NULL, serv_mb, 0, NULL, &tcache);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
}

/** Send a (prefixed) WALL of type \a type to all users except \a one.
 * @warning \a pattern must not contain %v.
 * @param[in] from Source of the command.
 * @param[in] type One of WALL_DESYNCH, WALL_WALLOPS or WALL_WALLUSERS.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
 */
void sendwallto_group_butone(struct Client *from, int type, struct Client *one,
			     const char *pattern, ...)
{
  struct VarData vd;
  struct Client *cptr;
  struct MsgBuf *mb;
  struct DLink *lp;
  struct MsgTagCtx mctx;
  char *prefix=NULL;
  char *tok=NULL;
  int his_wallops;
  int i;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  switch (type) {
    	case WALL_DESYNCH:
	  	prefix="";
		tok=TOK_DESYNCH;
		break;
    	case WALL_WALLOPS:
	  	prefix="* ";
		tok=TOK_WALLOPS;
		break;
    	case WALL_WALLUSERS:
	  	prefix="$ ";
		tok=TOK_WALLUSERS;
		break;
	default:
		assert(0);
  }
  mb = msgq_make(0, "%:#C " MSG_WALLOPS " :%s%v", from, prefix,&vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  his_wallops = feature_bool(FEAT_HIS_WALLOPS);
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(cptr = LocalClientArray[i]) ||
	(cli_fd(cli_from(cptr)) < 0) ||
	(type == WALL_DESYNCH && !SendDebug(cptr)) ||
	(type == WALL_WALLOPS &&
         (!SendWallops(cptr) || (his_wallops && !IsAnOper(cptr)))) ||
        (type == WALL_WALLUSERS && !SendWallops(cptr)))
      continue; /* skip it */
    send_buffer(cptr, from, mb, 1, NULL, NULL);
  }

  msgq_clean(mb);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  mb = msgq_make(&me, "%C %s :%v", from, tok, &vd);
  va_end(vd.vd_args);

  msgtagctx_init(&mctx, tok);
  /* send buffer along! */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    send_buffer(lp->value.cptr, NULL, mb, 1, &mctx, NULL);
  }

  msgq_clean(mb);
}

/** Send a (prefixed) command to all users matching \a to as \a who.
 * @warning \a pattern must not contain %v.
 * @param[in] from Source of the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] to Destination host/server mask.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] who Type of match for \a to (either MATCH_HOST or MATCH_SERVER).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_match_butone(struct Client *from, const char *cmd,
			    const char *tok, const char *to,
			    struct Client *one, unsigned int who,
			    const char *pattern, ...)
{
  struct VarData vd;
  struct Client *cptr;
  struct MsgBuf *user_mb;
  struct MsgBuf *serv_mb;
  struct TagSendCache tcache;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  user_mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  tagsendcache_init_cmd(&tcache, tok);
  /* send buffer along */
  bump_sentalong(one);
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!IsRegistered(cptr) || IsServer(cptr) || cli_fd(cli_from(cptr)) < 0 ||
        cli_sentalong(cptr) == sentalong_marker ||
        !match_it(from, cptr, to, who))
      continue; /* skip it */
    cli_sentalong(cptr) = sentalong_marker;

    if (MyConnect(cptr)) /* send right buffer */
      send_buffer(cptr, from, user_mb, 0, NULL, &tcache);
    else
      send_buffer(cptr, NULL, serv_mb, 0, NULL, &tcache);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
}

/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 */
void sendto_opmask_butone(struct Client *one, unsigned int mask,
			  const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendto_opmask_butone(one, mask, pattern, vl);
  va_end(vl);
}

/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one, rate-limited to once per 30 seconds.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in,out] rate Pointer to the last time the message was sent.
 * @param[in] pattern Format string for server notice.
 */
void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
				      time_t *rate, const char *pattern, ...)
{
  va_list vl;

  if ((CurrentTime - *rate) < 30)
    return;
  else
    *rate = CurrentTime;

  va_start(vl, pattern);
  vsendto_opmask_butone(one, mask, pattern, vl);
  va_end(vl);
}


/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 * @param[in] vl Argument list for format string.
 */
void vsendto_opmask_butone(struct Client *one, unsigned int mask,
			   const char *pattern, va_list vl)
{
  struct VarData vd;
  struct MsgBuf *mb;
  int i = 0; /* so that 1 points to opsarray[0] */
  struct SLink *opslist;

  while ((mask >>= 1))
    i++;

  if (!(opslist = opsarray[i]))
    return;

  /*
   * build string; I don't want to bother with client nicknames, so I hope
   * this is ok...
   */
  vd.vd_format = pattern;
  va_copy(vd.vd_args, vl);
  mb = msgq_make(0, ":%s " MSG_NOTICE " * :*** Notice -- %v", cli_name(&me),
		 &vd);
  va_end(vd.vd_args);

  for (; opslist; opslist = opslist->next)
    if (opslist->value.cptr != one)
      send_buffer(opslist->value.cptr, NULL, mb, 0, NULL, NULL);

  msgq_clean(mb);
}
