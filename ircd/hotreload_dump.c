/*
 * IRC - Internet Relay Chat, ircd/hotreload_dump.c
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
 * @brief Serialization of server state for a hot reload.
 *
 * hotreload_dump() writes every record the new image needs to rebuild the
 * state of the old one.  Nothing here may change server state: no dbuf is
 * consumed, no message queue is touched, no flag is cleared and no expired
 * record is reaped, because the exec() that follows may still fail and leave
 * this process running.  That rules out the reaping iterators the rest of the
 * daemon uses (gliter() in gline.c frees expired G-lines as it walks), so the
 * lists are walked with plain for loops here.
 *
 * By the time this runs the orchestration in hotreload.c has already squit
 * the server links, closed every unregistered connection and closed every
 * TLS connection that is not kernel-offloaded.  The client loop below still
 * filters on IsUser() && MyConnect() && cli_fd() >= 0 so that the dump is
 * correct even if that ever changes; servers are deliberately not handled.
 *
 * @section wireformat Record table
 *
 * Records are written in exactly this order.  Keys marked (opt) are omitted
 * when empty; every other key is always present.  The loader in
 * hotreload_load.c is written against this table.
 *
 * @verbatim
 * HOTRELOAD  version server numeric pid time tsoffset start
 *
 * LISTENER   fd family addr port flags
 *            One record per bound family of each active listener: fd_v4 >= 0
 *            yields family=4, fd_v6 >= 0 yields family=6.  Listeners that
 *            mark_listeners_closing() has deactivated are skipped.
 *
 * CLIENT     fd numnick index nick user host realhost sockhost sockip ip
 *            info firsttime lastnick since lasttime nextnick nexttarget
 *            umodes snomask account(opt) acc_id acc_flags away(opt) caps
 *            active privs oper tls raw tlsfp(opt) ws port sendM receiveM
 *            sendB receiveB joined invites targets flags
 * LINEBUF    fd data                (only when con_count > 0)
 * RECVQ      fd data                (only when the recvQ is not empty)
 * SENDQ      fd data                (only when there are unsent bytes)
 * WS         fd mode buf skip keepalive     (WebSocket clients only)
 * SILENCE    fd mask flags when     (one per cli_user()->silence entry)
 * INVITE     fd chan                (one per cli_user()->invited entry)
 *
 * CHANNEL    name creationtime modes limit key upass apass topic topic_nick
 *            topic_time users
 * MEMBER     chan fd status oplevel   (one per LOCAL member, in list order)
 * BAN        chan mask who when flags (one per banlist entry, in list order)
 *
 * GLINE      mask expire lastmod lifetime reason flags state
 * JUPE       server expire lastmod reason active local
 *            expire is absolute, as stored; jupe_add() in the loader takes a
 *            relative one, so hotreload_load.c converts it.
 * SLINE      pattern lastmod expire msgtype flags local
 * CONFIG     key value timestamp
 * STATS      max_clients max_connections <one key per ServerStatistics field>
 * END        (no keys)
 * @endverbatim
 *
 * @section listenerflags LISTENER flags= letters
 *
 * One letter per bit of enum ListenerFlag in include/listener.h:
 *
 * @verbatim
 *   h  LISTEN_HIDDEN      hidden from /STATS P
 *   s  LISTEN_SERVER      server-only port
 *   4  LISTEN_IPV4        listens on IPv4
 *   6  LISTEN_IPV6        listens on IPv6
 *   i  LISTEN_WEBIRC      webirc-only port
 *   t  LISTEN_TLS         native TLS port
 *   w  LISTEN_WEBSOCKET   accepts websocket connections
 *   c  LISTEN_CLOUDFLARE  trusts CF-Connecting-IP on websocket handshakes
 * @endverbatim
 *
 * LISTEN_ACTIVE is not dumped: an inactive listener is not dumped at all.
 * There is no exempt flag in this tree, so no 'x' letter is ever emitted;
 * the letter is reserved should one be added.  Letters are emitted in the
 * order above, which is enum order.
 *
 * @section memberflags MEMBER status= letters
 *
 * One letter per persistent CHFL_* member state in include/channel.h:
 *
 * @verbatim
 *   o  CHFL_CHANOP            channel operator
 *   v  CHFL_VOICE             voiced
 *   d  CHFL_DEOPPED           de-opped by a server
 *   s  CHFL_SERVOPOK          server op allowed
 *   z  CHFL_ZOMBIE            kicked, awaiting cleanup
 *   b  CHFL_BURST_JOINED      joined by a net.junction burst
 *   m  CHFL_CHANNEL_MANAGER   created the channel / used the apass
 *   j  CHFL_DELAYED           join not yet announced (+D)
 *   n  CHFL_DELAYED_TARGET    has not used a target on this channel
 * @endverbatim
 *
 * Deliberately not dumped, because they are caches or single-command
 * markers that the new image recomputes or does not want:
 *
 * @verbatim
 *   CHFL_BANVALID / CHFL_BANNED        cached ban-match result, recomputed
 *   CHFL_SILENCE_IPMASK                a struct Ban flag, not a member state
 *   CHFL_BURST_ALREADY_OPPED           burst-only bookkeeping
 *   CHFL_BURST_ALREADY_VOICED          burst-only bookkeeping
 *   CHFL_USER_PARTING                  re-entrancy guard within one PART
 * @endverbatim
 *
 * @section clientflags CLIENT flags= encoding
 *
 * The raw words of the struct Flags bitset behind cli_flags(), most
 * significant nibble first within a word, word 0 (which holds FLAG_PINGSENT
 * and friends) first, each word zero-padded to 16 lowercase hex digits
 * regardless of how wide unsigned long is on this host.  The loader must
 * pick out only the bits it understands and rebuild everything else from the
 * typed keys: the bit numbering is enum Flag order and is not stable across
 * versions of the daemon, and several flags (FLAG_DEADSOCKET, FLAG_CLOSING,
 * FLAG_NEGOTIATING_TLS, ...) describe connection state that does not survive
 * the exec at all.  It is dumped because it is the only place the local-only
 * user modes survive: umode_str() emits global modes only.
 *
 * @section umodes CLIENT umodes= encoding
 *
 * Exactly what umode_str() returns, which is the P10 burst form ms_nick()
 * parses: the global mode letters, then " <account>[:<id>[:<flags>]]" for
 * +r users and then " <fingerprint>" (or " _") for TLS users.  It carries no
 * leading '+'; a leading '+' is stripped defensively in case that changes.
 */
#include "config.h"

#include "hotreload.h"

#include "capab.h"
#include "channel.h"
#include "cidr_lookups.h"
#include "client.h"
#include "dbuf.h"
#include "gline.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_netconf.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "jupe.h"
#include "list.h"
#include "listener.h"
#include "msgq.h"
#include "numnicks.h"
#include "res.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_serv.h"
#include "s_user.h"
#include "sline.h"
#include "struct.h"

#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/** Head of the global listener list (ircd/listener.c). */
extern struct Listener *ListenerPollList;
/** Head of the linear global G-line list (ircd/gline.c). */
extern struct Gline *GlobalGlineList;
/** Head of the BADCHAN G-line list (ircd/gline.c). */
extern struct Gline *BadChanGlineList;
/** CIDR tree holding the single-family IP-mask G-lines (ircd/gline.c). */
extern cidr_root_node *GlobalIpMaskPTree;
/** Head of the global S-line list (ircd/sline.c). */
extern struct Sline *GlobalSlineList;

/** Buffer size for the privilege name list of one client. */
#define HR_PRIVBUFLEN 1024
/** Buffer size for the capability name list of one client. */
#define HR_CAPBUFLEN 512

/** Append an unsigned 64 bit key, which hr_rec_add_int() cannot represent.
 * @param[in] out Stream to write to.
 * @param[in] key Key name.
 * @param[in] value Value for \a key.
 */
static void hr_add_u64(FILE *out, const char *key, uint64_t value)
{
  char buf[32];

  snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
  hr_rec_add(out, key, buf);
}

/** Write the HOTRELOAD header record.
 * @param[in] out Stream to write to.
 */
static void hr_dump_header(FILE *out)
{
  hr_rec_begin(out, "HOTRELOAD");
  hr_rec_add_int(out, "version", 1);
  hr_rec_add(out, "server", cli_name(&me));
  hr_rec_add(out, "numeric", cli_yxx(&me));
  hr_rec_add_int(out, "pid", (long long)getpid());
  hr_rec_add_int(out, "time", (long long)CurrentTime);
  hr_rec_add_int(out, "tsoffset", (long long)TSoffset);
  hr_rec_add_int(out, "start",
                 cli_serv(&me) ? (long long)cli_serv(&me)->timestamp : 0);
  hr_rec_end(out);
}

/** Render a listener's flag bits as letters.
 * @param[in] listener Listener to describe.
 * @param[out] buf Buffer for the letters.
 * @param[in] len Size of \a buf.
 */
static void hr_listener_flags(const struct Listener *listener, char *buf,
                              size_t len)
{
  size_t pos = 0;

  /* Keep this in step with the letter table at the top of the file. */
#define HR_LFLAG(bit, letter)                                           \
  do {                                                                  \
    if (FlagHas(&(listener)->flags, (bit)) && pos + 1 < len)            \
      buf[pos++] = (letter);                                            \
  } while (0)

  HR_LFLAG(LISTEN_HIDDEN, 'h');
  HR_LFLAG(LISTEN_SERVER, 's');
  HR_LFLAG(LISTEN_IPV4, '4');
  HR_LFLAG(LISTEN_IPV6, '6');
  HR_LFLAG(LISTEN_WEBIRC, 'i');
  HR_LFLAG(LISTEN_TLS, 't');
  HR_LFLAG(LISTEN_WEBSOCKET, 'w');
  HR_LFLAG(LISTEN_CLOUDFLARE, 'c');
#undef HR_LFLAG

  buf[pos] = '\0';
}

/** Write one LISTENER record.
 * @param[in] out Stream to write to.
 * @param[in] listener Listener being dumped.
 * @param[in] fd Descriptor of the bound socket.
 * @param[in] family 4 or 6.
 * @param[in] flags Letters from hr_listener_flags().
 */
static void hr_dump_one_listener(FILE *out, const struct Listener *listener,
                                 int fd, int family, const char *flags)
{
  hr_rec_begin(out, "LISTENER");
  hr_rec_add_int(out, "fd", fd);
  hr_rec_add_int(out, "family", family);
  hr_rec_add(out, "addr", ircd_ntoa(&listener->addr.addr));
  hr_rec_add_int(out, "port", listener->addr.port);
  hr_rec_add(out, "flags", flags);
  hr_rec_end(out);
}

/** Write a LISTENER record per bound family of every active listener.
 * @param[in] out Stream to write to.
 */
static void hr_dump_listeners(FILE *out)
{
  struct Listener *listener;
  char flags[LISTEN_LAST_FLAG + 1];

  for (listener = ListenerPollList; listener; listener = listener->next) {
    if (!listener_active(listener))
      continue;                 /* mark_listeners_closing() got to it */

    hr_listener_flags(listener, flags, sizeof(flags));

    if (listener->fd_v4 >= 0)
      hr_dump_one_listener(out, listener, listener->fd_v4, 4, flags);
    if (listener->fd_v6 >= 0)
      hr_dump_one_listener(out, listener, listener->fd_v6, 6, flags);
  }
}

/** Write the raw words of a client's flag bitset as hex.
 * @param[in] cptr Client to describe.
 * @param[out] buf Buffer for the hex digits.
 * @param[in] len Size of \a buf.
 */
static void hr_client_flags(struct Client *cptr, char *buf, size_t len)
{
  struct Flags flags = cli_flags(cptr);
  unsigned int nwords = sizeof(flags.bits) / sizeof(flags.bits[0]);
  unsigned int i;
  size_t pos = 0;

  buf[0] = '\0';
  for (i = 0; i < nwords && pos + 16 < len; i++) {
    /* The loader parses this as space separated hexadecimal words; without
     * the separator two adjacent words would run together into one 32 digit
     * number that strtoul() would saturate.  struct Flags is one word wide in
     * this tree, so today nothing is ever appended and the output is
     * unchanged. */
    if (i > 0) {
      if (pos + 17 >= len)
        break;
      buf[pos++] = ' ';
      buf[pos] = '\0';
    }
    snprintf(buf + pos, len - pos, "%016llx",
             (unsigned long long)flags.bits[i]);
    pos += 16;
  }
}

/** Write a client's target hash array as hex.
 * @param[in] cptr Client to describe.
 * @param[out] buf Buffer for the hex digits, at least 2*MAXTARGETS+1 bytes.
 * @param[in] len Size of \a buf.
 */
static void hr_client_targets(struct Client *cptr, char *buf, size_t len)
{
  const unsigned char *targets = con_targets(cli_connect(cptr));
  unsigned int i;
  size_t pos = 0;

  buf[0] = '\0';
  for (i = 0; i < MAXTARGETS && pos + 2 < len; i++) {
    snprintf(buf + pos, len - pos, "%02x", targets[i]);
    pos += 2;
  }
}

/** Name the WebSocket framing mode of a connection.
 * @param[in] cptr Client to describe.
 * @return "none", "text" or "binary".
 */
static const char *hr_ws_mode_name(struct Client *cptr)
{
  if (!IsWebsocket(cptr))
    return "none";
  return (cli_ws_mode(cptr) == WS_BINARY) ? "binary" : "text";
}

/** Write the CLIENT record for one local user.
 * @param[in] out Stream to write to.
 * @param[in] cptr Client to dump.
 */
static void hr_dump_client(FILE *out, struct Client *cptr)
{
  struct User *user = cli_user(cptr);
  char privs[HR_PRIVBUFLEN];
  char caps[HR_CAPBUFLEN];
  char active[HR_CAPBUFLEN];
  char targets[2 * MAXTARGETS + 1];
  /* 16 hex digits plus a separating space per word of the flagset. */
  char flags[17 * (sizeof(struct Flags) / sizeof(unsigned long)) + 1];
  char *umodes;

  client_privs_to_string(cptr, privs, sizeof(privs));
  cap_set_to_string(cli_capab(cptr), caps, sizeof(caps));
  cap_set_to_string(cli_active(cptr), active, sizeof(active));
  hr_client_targets(cptr, targets, sizeof(targets));
  hr_client_flags(cptr, flags, sizeof(flags));

  /* umode_str() hands back a static buffer in P10 burst form and does not
   * prefix a '+'; strip one anyway so a future change cannot corrupt this. */
  umodes = umode_str(cptr);
  if (umodes && *umodes == '+')
    umodes++;

  hr_rec_begin(out, "CLIENT");
  hr_rec_add_int(out, "fd", cli_fd(cptr));
  hr_rec_add(out, "numnick", cli_yxx(cptr));
  hr_rec_add_int(out, "index", LocalNumNickIndex(cptr));
  hr_rec_add(out, "nick", cli_name(cptr));
  hr_rec_add(out, "user", user->username);
  hr_rec_add(out, "host", user->host);
  hr_rec_add(out, "realhost", user->realhost);
  hr_rec_add(out, "sockhost", cli_sockhost(cptr));
  hr_rec_add(out, "sockip", cli_sock_ip(cptr));
  hr_rec_add(out, "ip", ircd_ntoa(&cli_ip(cptr)));
  hr_rec_add(out, "info", cli_info(cptr));
  hr_rec_add_int(out, "firsttime", (long long)cli_firsttime(cptr));
  hr_rec_add_int(out, "lastnick", (long long)cli_lastnick(cptr));
  hr_rec_add_int(out, "since", (long long)cli_since(cptr));
  hr_rec_add_int(out, "lasttime", (long long)cli_lasttime(cptr));
  hr_rec_add_int(out, "nextnick", (long long)cli_nextnick(cptr));
  hr_rec_add_int(out, "nexttarget", (long long)cli_nexttarget(cptr));
  hr_rec_add(out, "umodes", umodes);
  hr_rec_add_int(out, "snomask", cli_snomask(cptr));
  if (user->account[0])
    hr_rec_add(out, "account", user->account);
  hr_add_u64(out, "acc_id", user->acc_id);
  hr_add_u64(out, "acc_flags", user->acc_flags);
  if (user->away)
    hr_rec_add(out, "away", user->away);
  hr_rec_add(out, "caps", caps);
  hr_rec_add(out, "active", active);
  hr_rec_add(out, "privs", privs);
  hr_rec_add_int(out, "oper", IsAnOper(cptr) ? 1 : 0);
  hr_rec_add_int(out, "tls", IsTLS(cptr) ? 1 : 0);
  /* Every TLS connection still here has been kernel-offloaded by the
   * orchestration, so it is driven raw (IsTLSRaw) after the exec. */
  hr_rec_add_int(out, "raw", IsTLS(cptr) ? 1 : 0);
  if (cli_tls_fingerprint(cptr)[0])
    hr_rec_add(out, "tlsfp", cli_tls_fingerprint(cptr));
  hr_rec_add(out, "ws", hr_ws_mode_name(cptr));
  hr_rec_add_int(out, "port",
                 cli_listener(cptr) ? cli_listener(cptr)->addr.port : 0);
  hr_rec_add_int(out, "sendM", cli_sendM(cptr));
  hr_rec_add_int(out, "receiveM", cli_receiveM(cptr));
  hr_add_u64(out, "sendB", cli_sendB(cptr));
  hr_add_u64(out, "receiveB", cli_receiveB(cptr));
  hr_rec_add_int(out, "joined", user->joined);
  hr_rec_add_int(out, "invites", user->invites);
  hr_rec_add(out, "targets", targets);
  hr_rec_add(out, "flags", flags);
  hr_rec_end(out);
}

/** Write the LINEBUF record holding a client's half assembled input line.
 * @param[in] out Stream to write to.
 * @param[in] cptr Client to dump.
 */
static void hr_dump_linebuf(FILE *out, struct Client *cptr)
{
  struct Connection *con = cli_connect(cptr);

  if (con->con_count == 0)
    return;

  hr_rec_begin(out, "LINEBUF");
  hr_rec_add_int(out, "fd", cli_fd(cptr));
  hr_rec_add_b64(out, "data", con->con_buffer, con->con_count);
  hr_rec_end(out);
}

/** Write the RECVQ record holding a client's unparsed input.
 * @param[in] out Stream to write to.
 * @param[in] cptr Client to dump.
 */
static void hr_dump_recvq(FILE *out, struct Client *cptr)
{
  struct DBuf *recvq = &cli_recvQ(cptr);
  unsigned int length = DBufLength(recvq);
  char *buf;

  if (length == 0)
    return;

  /* dbuf_copyout() leaves the queue untouched; dbuf_get() would drain it. */
  buf = (char *)MyMalloc(length);
  length = dbuf_copyout(recvq, buf, length);

  hr_rec_begin(out, "RECVQ");
  hr_rec_add_int(out, "fd", cli_fd(cptr));
  hr_rec_add_b64(out, "data", buf, length);
  hr_rec_end(out);

  MyFree(buf);
}

/** Write the SENDQ record holding a client's unsent output.
 *
 * The byte stream written here is exactly what tls_io_sendv() would put on
 * the wire next, which takes a little care to reproduce.
 *
 * con_rexmit is not a copy: it is a raw pointer into the head MsgBuf of one
 * of the two message queues, left over from a partial TLS write, with
 * con_rexmit_len counting the bytes of that message the session has not yet
 * accepted.  The queue's own accounting (Msg::sent) is deliberately not
 * advanced for those bytes -- msgq_delete() deletes in (partial-normal,
 * prio, normal) order and would misattribute them -- so msgq_mapiov() still
 * maps that head message in full, including the prefix already handed to the
 * TLS session.  Emitting con_rexmit and then the mapped queue verbatim would
 * therefore send that prefix twice.
 *
 * tls_io_sendv() resolves this by draining con_rexmit first, then removing
 * that one message by identity with msgq_excise(), and only then mapping the
 * queue.  This function mirrors that: it emits con_rexmit first, then every
 * mapped iovec except the one that contains con_rexmit -- that iovec is the
 * head message the rexmit points into, and msgq_excise() would drop it.
 * Detection is by pointer containment, which is exact: the iovec for that
 * head spans [msg + sent, msg + length) and con_rexmit lies inside it.
 *
 * Ordering matches too.  tls_io_sendv() puts the rexmit bytes ahead of
 * everything else regardless of which queue owns them, and the remaining
 * messages keep their msgq_mapiov() order either way.
 *
 * @param[in] out Stream to write to.
 * @param[in] cptr Client to dump.
 */
static void hr_dump_sendq(FILE *out, struct Client *cptr)
{
  struct Connection *con = cli_connect(cptr);
  struct MsgQ *sendq = &cli_sendQ(cptr);
  struct iovec *iov = 0;
  unsigned int mapped = 0;
  unsigned int total;
  size_t pos = 0;
  char *buf;
  int count = 0;
  int i;

  if (con->con_rexmit == 0 && MsgQLength(sendq) == 0)
    return;

  /* One iovec per queued message covers every case msgq_mapiov() can
   * produce: each message yields exactly one entry, partial heads included. */
  if (MsgQCount(sendq) > 0) {
    iov = (struct iovec *)MyMalloc(MsgQCount(sendq) * sizeof(*iov));
    count = msgq_mapiov(sendq, iov, (int)MsgQCount(sendq), &mapped);
  }

  total = (unsigned int)(con->con_rexmit ? con->con_rexmit_len : 0);
  for (i = 0; i < count; i++) {
    const char *base = (const char *)iov[i].iov_base;

    if (con->con_rexmit && con->con_rexmit >= base &&
        con->con_rexmit < base + iov[i].iov_len)
      continue;                 /* the message con_rexmit owns */
    total += (unsigned int)iov[i].iov_len;
  }

  buf = (char *)MyMalloc(total ? total : 1);

  if (con->con_rexmit) {
    memcpy(buf, con->con_rexmit, con->con_rexmit_len);
    pos = con->con_rexmit_len;
  }
  for (i = 0; i < count; i++) {
    const char *base = (const char *)iov[i].iov_base;

    if (con->con_rexmit && con->con_rexmit >= base &&
        con->con_rexmit < base + iov[i].iov_len)
      continue;
    memcpy(buf + pos, base, iov[i].iov_len);
    pos += iov[i].iov_len;
  }

  hr_rec_begin(out, "SENDQ");
  hr_rec_add_int(out, "fd", cli_fd(cptr));
  hr_rec_add_b64(out, "data", buf, pos);
  hr_rec_end(out);

  MyFree(buf);
  if (iov)
    MyFree(iov);
}

/** Write the WS record for a WebSocket client.
 * @param[in] out Stream to write to.
 * @param[in] cptr Client to dump.
 */
static void hr_dump_ws(FILE *out, struct Client *cptr)
{
  struct Connection *con = cli_connect(cptr);

  if (!IsWebsocket(cptr))
    return;

  hr_rec_begin(out, "WS");
  hr_rec_add_int(out, "fd", cli_fd(cptr));
  hr_rec_add(out, "mode", hr_ws_mode_name(cptr));
  hr_rec_add_b64(out, "buf", con->con_ws_handshake,
                 con->con_ws_handshake_len);
  hr_rec_add_int(out, "skip", (long long)con->con_ws_skip);
  hr_rec_add_int(out, "keepalive", (long long)con->con_ws_last_keepalive);
  hr_rec_end(out);
}

/** Write one SILENCE record per silence list entry, in list order.
 * @param[in] out Stream to write to.
 * @param[in] cptr Client to dump.
 */
static void hr_dump_silences(FILE *out, struct Client *cptr)
{
  struct Ban *ban;

  for (ban = cli_user(cptr)->silence; ban; ban = ban->next) {
    hr_rec_begin(out, "SILENCE");
    hr_rec_add_int(out, "fd", cli_fd(cptr));
    hr_rec_add(out, "mask", ban->banstr);
    hr_rec_add_int(out, "flags", ban->flags);
    hr_rec_add_int(out, "when", (long long)ban->when);
    hr_rec_end(out);
  }
}

/** Write one INVITE record per outstanding invite, in list order.
 * @param[in] out Stream to write to.
 * @param[in] cptr Client to dump.
 */
static void hr_dump_invites(FILE *out, struct Client *cptr)
{
  struct SLink *lp;

  for (lp = cli_user(cptr)->invited; lp; lp = lp->next) {
    hr_rec_begin(out, "INVITE");
    hr_rec_add_int(out, "fd", cli_fd(cptr));
    hr_rec_add(out, "chan", lp->value.chptr->chname);
    hr_rec_end(out);
  }
}

/** Write a CLIENT record and its dependent records for every local user.
 * @param[in] out Stream to write to.
 */
static void hr_dump_clients(FILE *out)
{
  struct Client *cptr;
  int fd;

  for (fd = 0; fd <= HighestFd; fd++) {
    if (!(cptr = LocalClientArray[fd]))
      continue;
    if (!IsUser(cptr) || !MyConnect(cptr) || cli_fd(cptr) < 0)
      continue;
    if (!cli_user(cptr))
      continue;

    hr_dump_client(out, cptr);
    hr_dump_linebuf(out, cptr);
    hr_dump_recvq(out, cptr);
    hr_dump_sendq(out, cptr);
    hr_dump_ws(out, cptr);
    hr_dump_silences(out, cptr);
    hr_dump_invites(out, cptr);
  }
}

/** Render a membership's persistent status bits as letters.
 * @param[in] member Membership to describe.
 * @param[out] buf Buffer for the letters.
 * @param[in] len Size of \a buf.
 */
static void hr_member_status(const struct Membership *member, char *buf,
                             size_t len)
{
  size_t pos = 0;

  /* Keep this in step with the letter table at the top of the file, and with
   * hr_memberflags[] in ircd/hotreload_load.c, which decodes these letters. */
#define HR_MFLAG(bit, letter)                                           \
  do {                                                                  \
    if ((member->status & (bit)) && pos + 1 < len)                      \
      buf[pos++] = (letter);                                            \
  } while (0)

  HR_MFLAG(CHFL_CHANOP, 'o');
  HR_MFLAG(CHFL_VOICE, 'v');
  HR_MFLAG(CHFL_DEOPPED, 'd');
  HR_MFLAG(CHFL_SERVOPOK, 's');
  HR_MFLAG(CHFL_ZOMBIE, 'z');
  HR_MFLAG(CHFL_BURST_JOINED, 'b');
  HR_MFLAG(CHFL_CHANNEL_MANAGER, 'm');
  HR_MFLAG(CHFL_DELAYED, 'j');
  HR_MFLAG(CHFL_DELAYED_TARGET, 'n');
#undef HR_MFLAG

  buf[pos] = '\0';
}

/** Write the CHANNEL, MEMBER and BAN records for one channel.
 * @param[in] out Stream to write to.
 * @param[in] chptr Channel to dump.
 */
static void hr_dump_channel(FILE *out, struct Channel *chptr)
{
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  char status[16];
  struct Membership *member;
  struct Ban *ban;
  const char *modes;

  /* Ask as the server, which is what the burst form uses: that gives the
   * k/l/A/U letters with their real parameters and the P10 spellings of the
   * delayed-join and TLS modes.  Only the letters are kept; every parameter
   * has its own key below. */
  *modebuf = *parabuf = '\0';
  channel_modes(&me, modebuf, parabuf, sizeof(parabuf), chptr, 0);
  modes = (*modebuf == '+') ? modebuf + 1 : modebuf;

  hr_rec_begin(out, "CHANNEL");
  hr_rec_add(out, "name", chptr->chname);
  hr_rec_add_int(out, "creationtime", (long long)chptr->creationtime);
  hr_rec_add(out, "modes", modes);
  hr_rec_add_int(out, "limit", chptr->mode.limit);
  hr_rec_add(out, "key", chptr->mode.key);
  hr_rec_add(out, "upass", chptr->mode.upass);
  hr_rec_add(out, "apass", chptr->mode.apass);
  hr_rec_add(out, "topic", chptr->topic);
  hr_rec_add(out, "topic_nick", chptr->topic_nick);
  hr_rec_add_int(out, "topic_time", (long long)chptr->topic_time);
  hr_rec_add_int(out, "users", chptr->users);
  hr_rec_end(out);

  for (member = chptr->members; member; member = member->next_member) {
    if (!MyUser(member->user))
      continue;

    hr_member_status(member, status, sizeof(status));

    hr_rec_begin(out, "MEMBER");
    hr_rec_add(out, "chan", chptr->chname);
    hr_rec_add_int(out, "fd", cli_fd(member->user));
    hr_rec_add(out, "status", status);
    hr_rec_add_int(out, "oplevel", member->oplevel);
    hr_rec_end(out);
  }

  for (ban = chptr->banlist; ban; ban = ban->next) {
    hr_rec_begin(out, "BAN");
    hr_rec_add(out, "chan", chptr->chname);
    hr_rec_add(out, "mask", ban->banstr);
    hr_rec_add(out, "who", ban->who);
    hr_rec_add_int(out, "when", (long long)ban->when);
    hr_rec_add_int(out, "flags", ban->flags);
    hr_rec_end(out);
  }
}

/** Write every channel that has at least one local member.
 * @param[in] out Stream to write to.
 */
static void hr_dump_channels(FILE *out)
{
  struct Channel *chptr;
  struct Membership *member;

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    for (member = chptr->members; member; member = member->next_member)
      if (MyUser(member->user))
        break;
    if (!member)
      continue;                 /* nothing local here; the net keeps it */

    hr_dump_channel(out, chptr);
  }
}

/** Write one GLINE record.
 *
 * The mask is spelled exactly as gline_burst() spells it: the user part,
 * then "@" and the host part when there is one.  BADCHAN and $R realname
 * G-lines carry the whole mask in gl_user and have a NULL gl_host, and
 * IP-mask G-lines keep the textual host they were set with, so this one
 * rule covers every kind.
 *
 * @param[in] out Stream to write to.
 * @param[in] gline G-line to dump.
 */
static void hr_dump_gline(FILE *out, struct Gline *gline)
{
  size_t len = strlen(gline->gl_user) +
               (gline->gl_host ? strlen(gline->gl_host) + 1 : 0) + 1;
  char *mask = (char *)MyMalloc(len);

  if (gline->gl_host)
    snprintf(mask, len, "%s@%s", gline->gl_user, gline->gl_host);
  else
    snprintf(mask, len, "%s", gline->gl_user);

  hr_rec_begin(out, "GLINE");
  hr_rec_add(out, "mask", mask);
  hr_rec_add_int(out, "expire", (long long)gline->gl_expire);
  hr_rec_add_int(out, "lastmod", (long long)gline->gl_lastmod);
  hr_rec_add_int(out, "lifetime", (long long)gline->gl_lifetime);
  hr_rec_add(out, "reason", gline->gl_reason);
  hr_rec_add_int(out, "flags",
                 gline->gl_flags & (GLINE_ACTIVE | GLINE_LOCAL |
                                    GLINE_BADCHAN | GLINE_REALNAME |
                                    GLINE_LDEACT | GLINE_IPMASK));
  hr_rec_add_int(out, "state", (int)gline->gl_state);
  hr_rec_end(out);

  MyFree(mask);
}

/** Write every G-line, local ones included.
 *
 * Three lists have to be walked, not two: gline_add() files a single-family
 * IP-mask G-line under a node of GlobalIpMaskPTree instead of
 * GlobalGlineList, so the CIDR tree is walked first, exactly as
 * gline_burst() does.  Plain for loops are used rather than gliter(), which
 * would free expired records as a side effect of walking.
 *
 * @param[in] out Stream to write to.
 */
static void hr_dump_glines(FILE *out)
{
  struct Gline *gline;
  cidr_node *tnode = 0;

  if (GlobalIpMaskPTree) {
    CIDR_ITER(GlobalIpMaskPTree, tnode) {
      for (gline = (struct Gline *)tnode->data; gline; gline = gline->gl_next)
        hr_dump_gline(out, gline);
    } CIDR_ITER_END;
  }

  for (gline = GlobalGlineList; gline; gline = gline->gl_next)
    hr_dump_gline(out, gline);

  for (gline = BadChanGlineList; gline; gline = gline->gl_next)
    hr_dump_gline(out, gline);
}

/** Write every jupe.
 *
 * GlobalJupeList is walked directly, through the extern in include/jupe.h.
 * expire= is the stored absolute ju_expire; the loader turns it back into the
 * relative lifetime jupe_add() wants.
 *
 * @param[in] out Stream to write to.
 */
static void hr_dump_jupes(FILE *out)
{
  struct Jupe *jupe;

  for (jupe = GlobalJupeList; jupe; jupe = jupe->ju_next) {
    hr_rec_begin(out, "JUPE");
    hr_rec_add(out, "server", jupe->ju_server);
    hr_rec_add_int(out, "expire", (long long)jupe->ju_expire);
    hr_rec_add_int(out, "lastmod", (long long)jupe->ju_lastmod);
    hr_rec_add(out, "reason", jupe->ju_reason);
    hr_rec_add_int(out, "active", JupeIsActive(jupe) ? 1 : 0);
    hr_rec_add_int(out, "local", JupeIsLocal(jupe) ? 1 : 0);
    hr_rec_end(out);
  }
}

/** Write every S-line.
 *
 * The keys are the struct Sline fields sline_burst() sends, named without
 * their sl_ prefix.  msgtype goes out as the numeric bit set rather than the
 * sline_flags_to_string() spelling the burst uses, so the loader can restore
 * sl_msgtype without reparsing.  There is no local/global distinction in
 * this tree, so local= is always 0.
 *
 * @param[in] out Stream to write to.
 */
static void hr_dump_slines(FILE *out)
{
  struct Sline *sline;

  for (sline = GlobalSlineList; sline; sline = sline->sl_next) {
    hr_rec_begin(out, "SLINE");
    hr_rec_add(out, "pattern", sline->sl_pattern);
    hr_rec_add_int(out, "lastmod", (long long)sline->sl_lastmod);
    hr_rec_add_int(out, "expire", (long long)sline->sl_expire);
    hr_rec_add_int(out, "msgtype", sline->sl_msgtype);
    hr_rec_add_int(out, "flags", sline->sl_flags);
    hr_rec_add_int(out, "local", 0);
    hr_rec_end(out);
  }
}

/** Write one CONFIG record; a config_foreach() callback.
 * @param[in] key Configuration key.
 * @param[in] value Configuration value.
 * @param[in] ts Timestamp the value was set at.
 * @param[in] ctx The FILE the dump is being written to.
 */
static void hr_dump_config_entry(const char *key, const char *value, time_t ts,
                                 void *ctx)
{
  FILE *out = (FILE *)ctx;

  hr_rec_begin(out, "CONFIG");
  hr_rec_add(out, "key", key);
  hr_rec_add(out, "value", value);
  hr_rec_add_int(out, "timestamp", (long long)ts);
  hr_rec_end(out);
}

/** Write the STATS record.
 * @param[in] out Stream to write to.
 */
static void hr_dump_stats(FILE *out)
{
  hr_rec_begin(out, "STATS");
  hr_rec_add_int(out, "max_clients", max_client_count);
  hr_rec_add_int(out, "max_connections", max_connection_count);

  /* One key per struct ServerStatistics field, named for the C field. */
#define HR_STAT(field) hr_rec_add_int(out, #field, ServerStats->field)
#define HR_STAT64(field) hr_add_u64(out, #field, ServerStats->field)
  HR_STAT(is_cl);
  HR_STAT(is_sv);
  HR_STAT(is_ni);
  HR_STAT64(is_cbs);
  HR_STAT64(is_cbr);
  HR_STAT64(is_sbs);
  HR_STAT64(is_sbr);
  HR_STAT64(is_cti);
  HR_STAT64(is_sti);
  HR_STAT(is_ac);
  HR_STAT(is_inactive);
  HR_STAT(is_all_inuse);
  HR_STAT(is_bad_ip);
  HR_STAT(is_reg_collided);
  HR_STAT(is_bad_username);
  HR_STAT(is_k_lined);
  HR_STAT(is_bad_password);
  HR_STAT(is_no_client);
  HR_STAT(is_class_full);
  HR_STAT(is_ip_full);
  HR_STAT(is_bad_socket);
  HR_STAT(is_throttled);
  HR_STAT(is_bad_fingerprint);
  HR_STAT(is_not_hub);
  HR_STAT(is_crule_fail);
  HR_STAT(is_not_server);
  HR_STAT(is_bad_server);
  HR_STAT(is_wrong_server);
  HR_STAT(is_unco);
  HR_STAT(is_wrdi);
  HR_STAT(is_unpf);
  HR_STAT(is_empt);
  HR_STAT(is_num);
  HR_STAT(is_kill);
  HR_STAT(is_fake);
  HR_STAT(is_asuc);
  HR_STAT(is_abad);
  HR_STAT(is_loc);
  HR_STAT(uping_recv);
#undef HR_STAT64
#undef HR_STAT

  hr_rec_end(out);
}

/** Write the whole of the server state to \a out.
 * @param[in] out Stream to write the dump to.
 * @return Non-zero on success, zero on write error.
 */
int hotreload_dump(FILE *out)
{
  if (!out)
    return 0;

  hr_dump_header(out);
  hr_dump_listeners(out);
  hr_dump_clients(out);
  hr_dump_channels(out);
  hr_dump_glines(out);
  hr_dump_jupes(out);
  hr_dump_slines(out);
  config_foreach(hr_dump_config_entry, out);
  hr_dump_stats(out);

  hr_rec_begin(out, "END");
  hr_rec_end(out);

  return ferror(out) ? 0 : 1;
}
