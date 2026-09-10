/*
 * IRC - Internet Relay Chat, ircd/hotreload_load.c
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
 * @brief Reading and applying a hot reload state dump.
 *
 * The dump is read once, early in boot (before the configuration is parsed,
 * so hotreload_claim_listener() can answer inetport()), and applied once,
 * just before the event loop starts.  Between those two points the parsed
 * records are held here: hr_parse_line() parses in place and leaves the
 * record pointers aliasing the line buffer, so the lines must stay alive
 * until the apply is finished.
 *
 * Records are applied in dependency order rather than file order -- config
 * and network bans first, then channels, then clients, then the memberships
 * and invites that join the two -- so the dumper is free to emit them in
 * whatever order suits it.  Unknown record types and unknown keys are
 * ignored, which is what lets a dump written by a slightly different build
 * still load.
 */
#include "config.h"

#include "hotreload.h"

#include "IPcheck.h"
#include "capab.h"
#include "channel.h"
#include "client.h"
#include "dbuf.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_handler.h"
#include "ircd_log.h"
#include "ircd_netconf.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_tls.h"
#include "jupe.h"
#include "list.h"
#include "listener.h"
#include "msgq.h"
#include "numnicks.h"
#include "querycmds.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h"
#include "s_user.h"
#include "match.h"
#include "send.h"
#include "sline.h"
#include "struct.h"
#include "sys.h"
#include "userload.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** Largest value con_ws_skip can legitimately hold: websocket_parse_frame()
 * keeps only the low 32 bits of a frame's length, so no oversized frame it
 * reports can leave more than this behind to drain. */
#define HR_WS_SKIP_MAX 0xffffffffLL

/** Lines of the dump, kept alive because the records alias them. */
static struct hr_lines lines;
/** One parsed record per line of #lines. */
static struct hr_record *records;
/** One flag per record: non-zero once a LISTENER record has been claimed. */
static unsigned char *claimed;
/** Non-zero once a dump has been read and not yet applied. */
static int pending;

/** List of listening sockets, defined in listener.c.
 *
 * Declared here rather than pulled from listener.h, which does not export it:
 * matching a dumped client's port back to a listener needs the list, and
 * find_listener() is file static there. */
extern struct Listener *ListenerPollList;

/** Map from the dump's descriptor numbers to the clients adopted for them. */
static struct Client **fdmap;

/** One bit per descriptor: set when the descriptor is not a client socket.
 *
 * Built once per apply by hr_build_reserved_fds() from the LISTENER records
 * and #hotreload_fd, so that the per-client test is a bit lookup rather than
 * a scan of every record for every client. */
static unsigned char *reserved_fds;

/** A client that must be exited once the rest of its records are applied. */
struct hr_pending_exit {
  struct Client *cptr;          /**< Client to exit. */
  const char *reason;           /**< Static reason string. */
};

/** Local mirror of s_user.c's userModeList[], which is file static there.
 *
 * It carries the *local* modes as well as the global ones: umode_str() emits
 * only the global half, but +s (server notices) and +O (local operator) are
 * part of a local client's state and would be silently dropped if only the
 * global letters were understood here.  Unknown letters are ignored, so a
 * dumper that emits either set works.
 */
static const struct hr_umode {
  unsigned int flag;            /**< User mode constant. */
  char c;                       /**< Character corresponding to the mode. */
} hr_umodes[] = {
  { FLAG_OPER,               'o' },
  { FLAG_LOCOP,              'O' },
  { FLAG_INVISIBLE,          'i' },
  { FLAG_WALLOP,             'w' },
  { FLAG_SERVNOTICE,         's' },
  { FLAG_DEAF,               'd' },
  { FLAG_CHSERV,             'k' },
  { FLAG_DEBUG,              'g' },
  { FLAG_ACCOUNT,            'r' },
  { FLAG_BLOCK_UNAUTH_USERS, 'R' },
  { FLAG_HIDDENHOST,         'x' },
  { FLAG_TLS,                'z' },
  { FLAG_HIDEIDLE,           'I' },
  { FLAG_COMMONCHANS,        'c' }
};

/** Channel modes that carry no parameter, by letter.
 *
 * The authoritative letter set is channel_modes() in channel.c; the modes
 * that do take a parameter (+l +k +A +U) are restored from the limit, key,
 * apass and upass keys instead of from this table.
 */
static const struct hr_chanmode {
  unsigned int mode;            /**< MODE_* constant. */
  char c;                       /**< Character corresponding to the mode. */
} hr_chanmodes[] = {
  { MODE_PRIVATE,        'p' },
  { MODE_SECRET,         's' },
  { MODE_MODERATED,      'm' },
  { MODE_TOPICLIMIT,     't' },
  { MODE_INVITEONLY,     'i' },
  { MODE_NOPRIVMSGS,     'n' },
  { MODE_REGONLY,        'r' },
  { MODE_DELJOINS,       'D' },
  { MODE_WASDELJOINS,    'd' },
  { MODE_REGISTERED,     'R' },
  { MODE_NOCOLOR,        'c' },
  { MODE_NOCTCP,         'C' },
  { MODE_NOPARTMSGS,     'u' },
  { MODE_MODERATENOREG,  'M' },
  { MODE_TLSONLY,        'Z' },
  { MODE_TLSINSECURE,    'z' }
};

/** Channel member status bits, by letter.
 *
 * This table must stay in sync with hr_member_status() in
 * ircd/hotreload_dump.c, and with the "MEMBER status= letters" table at the
 * top of that file, which is the canonical list: the letters are o v d s z b
 * m j n.  They are deliberately not the /MODE letters -- 'd' is DEOPPED and
 * 'j' is the delayed (+D) join -- so a letter changed on one side and not the
 * other silently drops a member's status across the reload.
 */
static const struct hr_memberflag {
  unsigned int flag;            /**< CHFL_* constant. */
  char c;                       /**< Character corresponding to the flag. */
} hr_memberflags[] = {
  { CHFL_CHANOP,          'o' },
  { CHFL_VOICE,           'v' },
  { CHFL_DEOPPED,         'd' },
  { CHFL_ZOMBIE,          'z' },
  { CHFL_BURST_JOINED,    'b' },
  { CHFL_SERVOPOK,        's' },
  { CHFL_CHANNEL_MANAGER, 'm' },
  { CHFL_DELAYED,         'j' },
  { CHFL_DELAYED_TARGET,  'n' }
};

/** Width of a #ServerStatistics field, for #hr_statfields. */
enum hr_statwidth { HR_STAT_UINT, HR_STAT_U64 };

/** Every field of struct ServerStatistics, by its C name. */
static const struct hr_statfield {
  const char *name;             /**< Key in the STATS record. */
  size_t offset;                /**< Byte offset within the structure. */
  enum hr_statwidth width;      /**< Width of the field. */
} hr_statfields[] = {
  { "is_cl",              offsetof(struct ServerStatistics, is_cl),              HR_STAT_UINT },
  { "is_sv",              offsetof(struct ServerStatistics, is_sv),              HR_STAT_UINT },
  { "is_ni",              offsetof(struct ServerStatistics, is_ni),              HR_STAT_UINT },
  { "is_cbs",             offsetof(struct ServerStatistics, is_cbs),             HR_STAT_U64  },
  { "is_cbr",             offsetof(struct ServerStatistics, is_cbr),             HR_STAT_U64  },
  { "is_sbs",             offsetof(struct ServerStatistics, is_sbs),             HR_STAT_U64  },
  { "is_sbr",             offsetof(struct ServerStatistics, is_sbr),             HR_STAT_U64  },
  { "is_cti",             offsetof(struct ServerStatistics, is_cti),             HR_STAT_U64  },
  { "is_sti",             offsetof(struct ServerStatistics, is_sti),             HR_STAT_U64  },
  { "is_ac",              offsetof(struct ServerStatistics, is_ac),              HR_STAT_UINT },
  { "is_inactive",        offsetof(struct ServerStatistics, is_inactive),        HR_STAT_UINT },
  { "is_all_inuse",       offsetof(struct ServerStatistics, is_all_inuse),       HR_STAT_UINT },
  { "is_bad_ip",          offsetof(struct ServerStatistics, is_bad_ip),          HR_STAT_UINT },
  { "is_reg_collided",    offsetof(struct ServerStatistics, is_reg_collided),    HR_STAT_UINT },
  { "is_bad_username",    offsetof(struct ServerStatistics, is_bad_username),    HR_STAT_UINT },
  { "is_k_lined",         offsetof(struct ServerStatistics, is_k_lined),         HR_STAT_UINT },
  { "is_bad_password",    offsetof(struct ServerStatistics, is_bad_password),    HR_STAT_UINT },
  { "is_no_client",       offsetof(struct ServerStatistics, is_no_client),       HR_STAT_UINT },
  { "is_class_full",      offsetof(struct ServerStatistics, is_class_full),      HR_STAT_UINT },
  { "is_ip_full",         offsetof(struct ServerStatistics, is_ip_full),         HR_STAT_UINT },
  { "is_bad_socket",      offsetof(struct ServerStatistics, is_bad_socket),      HR_STAT_UINT },
  { "is_throttled",       offsetof(struct ServerStatistics, is_throttled),       HR_STAT_UINT },
  { "is_bad_fingerprint", offsetof(struct ServerStatistics, is_bad_fingerprint), HR_STAT_UINT },
  { "is_not_hub",         offsetof(struct ServerStatistics, is_not_hub),         HR_STAT_UINT },
  { "is_crule_fail",      offsetof(struct ServerStatistics, is_crule_fail),      HR_STAT_UINT },
  { "is_not_server",      offsetof(struct ServerStatistics, is_not_server),      HR_STAT_UINT },
  { "is_bad_server",      offsetof(struct ServerStatistics, is_bad_server),      HR_STAT_UINT },
  { "is_wrong_server",    offsetof(struct ServerStatistics, is_wrong_server),    HR_STAT_UINT },
  { "is_unco",            offsetof(struct ServerStatistics, is_unco),            HR_STAT_UINT },
  { "is_wrdi",            offsetof(struct ServerStatistics, is_wrdi),            HR_STAT_UINT },
  { "is_unpf",            offsetof(struct ServerStatistics, is_unpf),            HR_STAT_UINT },
  { "is_empt",            offsetof(struct ServerStatistics, is_empt),            HR_STAT_UINT },
  { "is_num",             offsetof(struct ServerStatistics, is_num),             HR_STAT_UINT },
  { "is_kill",            offsetof(struct ServerStatistics, is_kill),            HR_STAT_UINT },
  { "is_fake",            offsetof(struct ServerStatistics, is_fake),            HR_STAT_UINT },
  { "is_asuc",            offsetof(struct ServerStatistics, is_asuc),            HR_STAT_UINT },
  { "is_abad",            offsetof(struct ServerStatistics, is_abad),            HR_STAT_UINT },
  { "is_loc",             offsetof(struct ServerStatistics, is_loc),             HR_STAT_UINT },
  { "uping_recv",         offsetof(struct ServerStatistics, uping_recv),         HR_STAT_UINT }
};

/** Client flags taken verbatim from the dumped cli_flags word.
 *
 * Everything else is either derived from a dedicated key (the user modes,
 * tls, raw, IPcheck) or is per-connection state that must start clean in the
 * new process (DEADSOCKET, BLOCKED, CLOSING, KILLED, PINGSENT and, above all,
 * NEGOTIATING_TLS -- the handshake finished in the process we replaced).
 *
 * The local-only user modes ride here too.  umode_str() emits only the flags
 * at or above FLAG_GLOBAL_UMODES, so +O (FLAG_LOCOP) and +s (FLAG_SERVNOTICE)
 * never reach the umodes= key and would be lost; the flags= word written by
 * hr_client_flags() in ircd/hotreload_dump.c does carry them.  Those two are
 * the only flags between FLAG_LOCAL_UMODES and FLAG_GLOBAL_UMODES in
 * include/client.h -- FLAG_DEBUG (+g) sits above FLAG_GLOBAL_UMODES and so
 * arrives through umodes= like any other global mode.
 */
static const unsigned int hr_carried_flags[] = {
  FLAG_GOTID,
  FLAG_NONL,
  FLAG_TS8,
  FLAG_SASL,
  FLAG_CAP302,
  FLAG_LOCOP,
  FLAG_SERVNOTICE
};

/** Number of entries in the array \a a. */
#define HR_COUNT(a) ((unsigned int)(sizeof(a) / sizeof((a)[0])))

/** Test whether \a rec is of type \a type.
 * @param[in] rec Record to test.
 * @param[in] type Type name to compare against.
 * @return Non-zero when the types match.
 */
static int hr_is(const struct hr_record *rec, const char *type)
{
  return rec->type && !strcmp(rec->type, type);
}

/** Look up a key, substituting "" for an absent one.
 * @param[in] rec Record to search.
 * @param[in] key Key to look for.
 * @return Value for \a key, never NULL.
 */
static const char *hr_str(const struct hr_record *rec, const char *key)
{
  const char *value = hr_get(rec, key);
  return value ? value : "";
}

/** Release everything held between hotreload_read() and hotreload_apply(). */
static void hr_reset(void)
{
  hr_free_lines(&lines);
  MyFree(records);
  records = 0;
  MyFree(claimed);
  claimed = 0;
  MyFree(fdmap);
  fdmap = 0;
  MyFree(reserved_fds);
  reserved_fds = 0;
  pending = 0;
}

/** Close every descriptor named by the first \a upto records.
 *
 * Used when a dump is rejected: the inherited sockets are ours and nothing
 * else will ever close them, so they would otherwise leak for the lifetime
 * of the server.
 *
 * @param[in] upto Number of records that parsed successfully.
 */
static void hr_close_named_fds(unsigned int upto)
{
  unsigned int i;

  for (i = 0; i < upto; i++) {
    if (!hr_is(&records[i], "LISTENER") && !hr_is(&records[i], "CLIENT"))
      continue;
    if (hr_get(&records[i], "fd"))
      close((int)hr_get_int(&records[i], "fd", -1));
  }
}

/** Read a state dump from \a fd.
 * @param[in] fd Descriptor holding the dump.
 * @return Non-zero on success; zero means the caller must cold boot.
 */
int hotreload_read(int fd)
{
  unsigned int i;

  if (pending)
    hr_reset();

  if (!hr_read_all(fd, &lines)) {
    log_write(LS_SYSTEM, L_ERROR, 0, "hot reload: cannot read dump");
    hr_reset();
    return 0;
  }

  /* One spare entry so an empty dump still gets a non-zero allocation; the
   * header check below rejects it either way. */
  records = (struct hr_record *)MyCalloc(lines.count + 1, sizeof(*records));
  claimed = (unsigned char *)MyCalloc(lines.count + 1, 1);

  for (i = 0; i < lines.count; i++) {
    if (!hr_parse_line(lines.line[i], &records[i])) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "hot reload: malformed dump record at line %u", i + 1);
      hr_close_named_fds(i);
      hr_reset();
      return 0;
    }
  }

  if (lines.count < 1 || !hr_is(&records[0], "HOTRELOAD")
      || hr_get_int(&records[0], "version", 0) != 1) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "hot reload: dump is not a version 1 HOTRELOAD dump");
    hr_close_named_fds(lines.count);
    hr_reset();
    return 0;
  }

  pending = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "hot reload: read %u records", lines.count);
  return 1;
}

/** Test whether a dump has been read but not yet applied.
 * @return Non-zero while a read dump awaits hotreload_apply().
 */
int hotreload_pending(void)
{
  return pending;
}

/** Test whether \a text names the same address as \a addr.
 *
 * A wildcard vhost leaves the listener's configured address all zeros, which
 * ircd_ntoa() prints as "::" whatever the socket family; accept the other
 * spellings of "any address" for it so a dumper that wrote the configured
 * vhost text rather than the parsed address still matches.
 *
 * @param[in] text Address text from the dump.
 * @param[in] addr Address the listener is configured for.
 * @return Non-zero when they name the same address.
 */
static int hr_addr_matches(const char *text, const struct irc_in_addr *addr)
{
  char buf[SOCKIPLEN + 1];

  ircd_ntoa_r(buf, addr);
  if (!strcmp(text, buf))
    return 1;

  if (irc_in_addr_unspec(addr))
    return !*text || !strcmp(text, "*") || !strcmp(text, "::")
        || !strcmp(text, "0.0.0.0");

  return 0;
}

/** Claim the inherited listening socket for an address.
 * @param[in] family Address family of the listener, as 4 or 6.
 * @param[in] addr Address the listener is bound to.
 * @param[in] port Port the listener is bound to.
 * @return Inherited descriptor, or -1 when there is none.
 */
int hotreload_claim_listener(int family, const struct irc_in_addr *addr, int port)
{
  unsigned int i;

  if (!pending)
    return -1;

  for (i = 0; i < lines.count; i++) {
    if (!hr_is(&records[i], "LISTENER") || claimed[i])
      continue;
    if ((int)hr_get_int(&records[i], "family", 0) != family)
      continue;
    if ((int)hr_get_int(&records[i], "port", -1) != port)
      continue;
    if (!hr_addr_matches(hr_str(&records[i], "addr"), addr))
      continue;

    claimed[i] = 1;
    return (int)hr_get_int(&records[i], "fd", -1);
  }

  return -1;
}

/** Decode the base64 value of \a key into a freshly allocated buffer.
 *
 * hr_b64_decode() needs the destination sized up front; four base64
 * characters never decode to more than three bytes, so strlen/4*3 (rounded
 * up) always fits.
 *
 * @param[in] rec Record holding the value.
 * @param[in] key Key whose value to decode.
 * @param[out] len_out Receives the decoded length.
 * @return Allocated buffer (release with MyFree), or NULL on a decode error.
 *   A key that is absent or empty yields a buffer and a zero length.
 */
static unsigned char *hr_decode(const struct hr_record *rec, const char *key,
                                size_t *len_out)
{
  const char *src = hr_str(rec, key);
  size_t dstlen = (strlen(src) / 4 + 1) * 3;
  unsigned char *dst = (unsigned char *)MyMalloc(dstlen + 1);
  size_t len = hr_b64_decode(src, dst, dstlen);

  if (len == (size_t)-1) {
    MyFree(dst);
    return 0;
  }
  *len_out = len;
  return dst;
}

/** Apply the CONFIG, GLINE, JUPE and SLINE records.
 *
 * No server is linked at this point, so the propagation these functions do
 * unconditionally (gline_propagate() and its counterparts) reaches nobody;
 * likewise the do_gline() sweep finds no clients, because the clients are
 * adopted afterwards -- which is also why the bans have to go in first.
 */
static void hr_apply_network_state(void)
{
  unsigned int i;

  for (i = 0; i < lines.count; i++) {
    struct hr_record *rec = &records[i];

    if (hr_is(rec, "CONFIG")) {
      config_set(hr_str(rec, "key"), hr_str(rec, "value"),
                 (time_t)hr_get_int(rec, "timestamp", 0));
    } else if (hr_is(rec, "GLINE")) {
      /* gline_add() canonicalises the mask in place, so hand it a copy
       * rather than the line buffer the record still points into. */
      /* Big enough for every mask form gline_add() accepts: a BADCHAN mask
       * runs to CHANNELLEN + 6 (gline.c), which is longer than the
       * USERLEN + HOSTLEN user@host form and the REALLEN realname form. */
      char mask[CHANNELLEN + 8];
      char reason[TOPICLEN + 1];
      time_t expire = (time_t)hr_get_int(rec, "expire", 0);
      unsigned int flags = (unsigned int)hr_get_int(rec, "flags", 0);
      struct Gline *gline;

      if (expire <= TStime()) {
        Debug((DEBUG_DEBUG, "hot reload: dropping expired G-line %s",
               hr_str(rec, "mask")));
        continue;
      }

      ircd_strncpy(mask, hr_str(rec, "mask"), sizeof(mask) - 1);
      ircd_strncpy(reason, hr_str(rec, "reason"), sizeof(reason) - 1);

      flags &= GLINE_ACTIVE | GLINE_LOCAL | GLINE_BADCHAN | GLINE_REALNAME
             | GLINE_IPMASK;
      /* gline_add() asserts exactly one of GLINE_GLOBAL / GLINE_LOCAL, and
       * GLINE_FORCE skips the operator-facing expiry limits: this is a
       * restore of a G-line that was already accepted, not a new one. */
      flags |= GLINE_FORCE;
      if (!(flags & GLINE_LOCAL))
        flags |= GLINE_GLOBAL;

      /* gline_add() takes an absolute expiration, exactly as dumped. */
      gline_add(&me, &me, mask, reason, expire,
                (time_t)hr_get_int(rec, "lastmod", 0),
                (time_t)hr_get_int(rec, "lifetime", 0), flags);

      if (hr_get_int(rec, "state", 0)) {
        /* gline_find() canonicalises too, so re-copy the mask; GLINE_EXACT is
         * required, and GLINE_ANY makes it look past the BADCHAN list. */
        unsigned int find = GLINE_EXACT | GLINE_ANY
          | (flags & (GLINE_LOCAL | GLINE_GLOBAL | GLINE_BADCHAN));

        ircd_strncpy(mask, hr_str(rec, "mask"), sizeof(mask) - 1);
        if ((gline = gline_find(mask, find)))
          gline->gl_state =
            (enum GlineLocalState)hr_get_int(rec, "state", GLOCAL_GLOBAL);
      }
    } else if (hr_is(rec, "JUPE")) {
      char server[HOSTLEN + 1];
      char reason[TOPICLEN + 1];
      time_t expire = (time_t)hr_get_int(rec, "expire", 0);
      unsigned int flags = 0;

      ircd_strncpy(server, hr_str(rec, "server"), sizeof(server) - 1);
      ircd_strncpy(reason, hr_str(rec, "reason"), sizeof(reason) - 1);

      if (hr_get_int(rec, "active", 0))
        flags |= JUPE_ACTIVE;
      if (hr_get_int(rec, "local", 0))
        flags |= JUPE_LOCAL;

      /* The dump writes ju_expire, which is absolute, but jupe_add() takes a
       * lifetime relative to now: it adds CurrentTime itself and rejects
       * anything above JUPE_MAX_EXPIRE.  Convert, drop what has already
       * expired, and clamp the rest -- a jupe whose remaining life somehow
       * exceeds the maximum is better shortened than refused outright. */
      expire -= CurrentTime;
      if (expire <= 0) {
        Debug((DEBUG_DEBUG, "hot reload: dropping expired jupe %s", server));
        continue;
      }
      if (expire > JUPE_MAX_EXPIRE)
        expire = JUPE_MAX_EXPIRE;

      jupe_add(&me, &me, server, reason, expire,
               (time_t)hr_get_int(rec, "lastmod", 0), flags);
    } else if (hr_is(rec, "SLINE")) {
      char pattern[BUFSIZE];

      ircd_strncpy(pattern, hr_str(rec, "pattern"), sizeof(pattern) - 1);

      /* struct Sline has no reason and no local flag; the reason and local
       * keys of the record, if the dumper writes them, are ignored. */
      sline_add(&me, &me, pattern,
                (time_t)hr_get_int(rec, "lastmod", 0),
                (time_t)hr_get_int(rec, "expire", 0),
                (sl_msgtype_t)hr_get_int(rec, "msgtype", SLINE_ALL),
                (sl_flagtype_t)hr_get_int(rec, "flags", SLINE_ACTIVE));
    }
  }
}

/** Rebuild the channels named by the CHANNEL records.
 * @return Number of channels rebuilt.
 */
static unsigned int hr_apply_channels(void)
{
  unsigned int i;
  unsigned int count = 0;

  for (i = 0; i < lines.count; i++) {
    struct hr_record *rec = &records[i];
    char name[CHANNELLEN + 1];
    struct Channel *chptr;
    const char *modes;
    const char *value;
    unsigned int j;

    if (!hr_is(rec, "CHANNEL"))
      continue;

    ircd_strncpy(name, hr_str(rec, "name"), sizeof(name) - 1);
    if (!*name)
      continue;

    if (!(chptr = get_channel(&me, name, CGT_CREATE)))
      continue;
    count++;

    chptr->creationtime = (time_t)hr_get_int(rec, "creationtime", 0);

    for (modes = hr_str(rec, "modes"); *modes; modes++)
      for (j = 0; j < HR_COUNT(hr_chanmodes); j++)
        if (hr_chanmodes[j].c == *modes) {
          chptr->mode.mode |= hr_chanmodes[j].mode;
          break;
        }

    if ((chptr->mode.limit = (unsigned int)hr_get_int(rec, "limit", 0)))
      chptr->mode.mode |= MODE_LIMIT;

    value = hr_str(rec, "key");
    if (*value) {
      ircd_strncpy(chptr->mode.key, value, sizeof(chptr->mode.key) - 1);
      chptr->mode.mode |= MODE_KEY;
    }
    value = hr_str(rec, "upass");
    if (*value) {
      ircd_strncpy(chptr->mode.upass, value, sizeof(chptr->mode.upass) - 1);
      chptr->mode.mode |= MODE_UPASS;
    }
    value = hr_str(rec, "apass");
    if (*value) {
      ircd_strncpy(chptr->mode.apass, value, sizeof(chptr->mode.apass) - 1);
      chptr->mode.mode |= MODE_APASS;
    }

    ircd_strncpy(chptr->topic, hr_str(rec, "topic"), sizeof(chptr->topic) - 1);
    ircd_strncpy(chptr->topic_nick, hr_str(rec, "topic_nick"),
                 sizeof(chptr->topic_nick) - 1);
    chptr->topic_time = (time_t)hr_get_int(rec, "topic_time", 0);
  }

  return count;
}

/** Append \a ban to the end of \a chptr's ban list.
 *
 * Deliberately not add_banid(): its overlap and bounce logic exists to merge
 * a newly set ban into an existing list, and running it here would silently
 * drop bans that the old process was quite happily holding side by side.
 * Appending preserves the dumped order as well.
 *
 * @param[in,out] chptr Channel to append to.
 * @param[in] ban Ban to append.
 */
static void channel_append_ban(struct Channel *chptr, struct Ban *ban)
{
  struct Ban **tail;

  ban->next = 0;
  for (tail = &chptr->banlist; *tail; tail = &(*tail)->next)
    ;
  *tail = ban;
}

/** Set the user modes named by \a modes on \a cptr.
 *
 * The letters are those of a P10 burst: a run of mode characters, optionally
 * followed by a space and the account token that goes with +r (and, from
 * umode_str(), possibly a TLS fingerprint after that, which is ignored here
 * because the tlsfp key is authoritative).
 *
 * @param[in,out] cptr Client to set modes on.
 * @param[in] modes Mode letters and trailing tokens.
 * @param[out] is_oper_out Set non-zero if an operator mode was seen.
 */
static void hr_set_umodes(struct Client *cptr, const char *modes,
                          int *is_oper_out)
{
  unsigned int i;

  for (; *modes && *modes != ' '; modes++) {
    if (*modes == '+')
      continue;
    for (i = 0; i < HR_COUNT(hr_umodes); i++)
      if (hr_umodes[i].c == *modes) {
        SetFlag(cptr, hr_umodes[i].flag);
        if (hr_umodes[i].flag == FLAG_OPER || hr_umodes[i].flag == FLAG_LOCOP)
          *is_oper_out = 1;
        break;
      }
  }

  /* The account token, when the dumper wrote it P10 style.  The explicit
   * account/acc_id/acc_flags keys are applied afterwards and win. */
  if (*modes == ' ' && IsAccount(cptr)) {
    char token[ACCOUNTLEN + 64];
    char *sep;

    ircd_strncpy(token, modes + 1, sizeof(token) - 1);
    if ((sep = strchr(token, ' ')))
      *sep = '\0';              /* stop before the fingerprint, if any */

    if ((sep = strchr(token, ':'))) {
      *sep++ = '\0';
      cli_user(cptr)->acc_id = (uint64_t)strtoull(sep, &sep, 10);
      if (*sep == ':')
        cli_user(cptr)->acc_flags = (uint64_t)strtoull(sep + 1, NULL, 10);
    }
    ircd_strncpy(cli_user(cptr)->account, token, ACCOUNTLEN);
  }
}

/** Copy the carried subset of the dumped cli_flags word onto \a cptr.
 * @param[in,out] cptr Client to set flags on.
 * @param[in] text Space separated hexadecimal words of the dumped flagset.
 */
static void hr_set_flags(struct Client *cptr, const char *text)
{
  struct Flags dumped;
  unsigned int i;
  char *end;

  memset(&dumped, 0, sizeof(dumped));
  for (i = 0; i < HR_COUNT(dumped.bits) && *text; i++) {
    dumped.bits[i] = strtoul(text, &end, 16);
    if (end == text)
      break;
    text = end;
    while (*text == ' ')
      text++;
  }

  for (i = 0; i < HR_COUNT(hr_carried_flags); i++)
    if (FlagHas(&dumped, hr_carried_flags[i]))
      SetFlag(cptr, hr_carried_flags[i]);
}

/** Restore the recent-target hash values of \a cptr from hex text.
 * @param[in,out] cptr Client to restore targets for.
 * @param[in] text Hexadecimal digits, two per target slot.
 */
static void hr_set_targets(struct Client *cptr, const char *text)
{
  unsigned char *targets = cli_targets(cptr);
  int i;

  for (i = 0; i < MAXTARGETS && text[0] && text[1]; i++, text += 2) {
    char pair[3];

    pair[0] = text[0];
    pair[1] = text[1];
    pair[2] = '\0';
    targets[i] = (unsigned char)strtoul(pair, NULL, 16);
  }
}

/** Find the listener a dumped client arrived on.
 * @param[in] port Port from the CLIENT record.
 * @return Matching listener, or NULL when the port is no longer configured.
 */
static struct Listener *hr_find_listener(int port)
{
  struct Listener *listener;

  for (listener = ListenerPollList; listener; listener = listener->next)
    if (listener->addr.port == port)
      return listener;

  /* The port is no longer configured, so no listener describes where this
   * client came from.  Handing it an arbitrary one would misreport its
   * provenance in /STATS and, worse, feed the wrong port to attach_iline()'s
   * Client-block port= match, letting a client in on a rule written for a
   * port it never used.  NULL is the honest answer: adoption tolerates it and
   * attach_iline() is NULL-safe. */
  return 0;
}

/** Apply one of the per-client records that follow a CLIENT record.
 * @param[in] rec Record to apply.
 * @param[in,out] cptr Client the record belongs to.
 * @param[in] check_only Non-zero to validate without changing the client.
 * @return Non-zero on success, zero when a value would not decode.
 */
static int hr_apply_client_sub(struct hr_record *rec, struct Client *cptr,
                               int check_only)
{
  unsigned char *data;
  const char *value;
  long long ws_skip;
  size_t len = 0;

  if (hr_is(rec, "LINEBUF")) {
    if (!(data = hr_decode(rec, "data", &len)))
      return 0;
    if (!check_only) {
      if (len > sizeof(cli_buffer(cptr)) - 1)
        len = sizeof(cli_buffer(cptr)) - 1;
      memcpy(cli_buffer(cptr), data, len);
      cli_buffer(cptr)[len] = '\0';
      cli_count(cptr) = (unsigned int)len;
    }
    MyFree(data);
  } else if (hr_is(rec, "RECVQ")) {
    if (!(data = hr_decode(rec, "data", &len)))
      return 0;
    if (!check_only && len)
      dbuf_put(&cli_recvQ(cptr), (const char *)data, (unsigned int)len);
    MyFree(data);
  } else if (hr_is(rec, "SENDQ")) {
    if (!(data = hr_decode(rec, "data", &len)))
      return 0;
    /* A failure here is the buffer pool refusing to grow, not a bad record:
     * the client keeps its connection and loses whatever output was still
     * queued for it, which is worth a log line and nothing more. */
    if (!check_only && len && !msgq_append_raw(&cli_sendQ(cptr), data, len))
      log_write(LS_SYSTEM, L_ERROR, 0,
                "hot reload: cannot restore %lu queued bytes for %s",
                (unsigned long)len, cli_name(cptr));
    MyFree(data);
  } else if (hr_is(rec, "WS")) {
    if (!(data = hr_decode(rec, "buf", &len)))
      return 0;
    if (!check_only) {
      struct Connection *con = cli_connect(cptr);

      if (len > sizeof(con->con_ws_handshake) - 1)
        len = sizeof(con->con_ws_handshake) - 1;
      memcpy(con->con_ws_handshake, data, len);
      con->con_ws_handshake[len] = '\0';
      con->con_ws_handshake_len = len;
      /* skip is what is left of an oversized frame's payload, so it is
       * bounded by the largest payload websocket_parse_frame() will report:
       * that parser reads the 64 bit length form but only keeps its low 32
       * bits (see ircd/websocket.c), so nothing it produces exceeds
       * HR_WS_SKIP_MAX.  Clamping to it stops a dump from parking the reader
       * in the drain loop, throwing away real traffic, for a count no frame
       * could ever have set.  handshake_len is bounded by the memcpy clamp
       * just above, which is the buffer's own size. */
      ws_skip = hr_get_int(rec, "skip", 0);
      if (ws_skip < 0)
        ws_skip = 0;
      if (ws_skip > HR_WS_SKIP_MAX)
        ws_skip = HR_WS_SKIP_MAX;
      con->con_ws_skip = (size_t)ws_skip;
      con->con_ws_last_keepalive = (time_t)hr_get_int(rec, "keepalive", 0);
      /* Accept the mode as either the enum value or the same words the
       * CLIENT record's ws key uses; an absent or unrecognised mode leaves
       * what the CLIENT record already established. */
      value = hr_str(rec, "mode");
      if (!strcmp(value, "text"))
        con_ws_mode(con) = WS_TEXT;
      else if (!strcmp(value, "binary"))
        con_ws_mode(con) = WS_BINARY;
      else if (!strcmp(value, "none"))
        con_ws_mode(con) = WS_NONE;
      else if (hr_get(rec, "mode") && *value)
        con_ws_mode(con) = (enum ws_mode_t)hr_get_int(rec, "mode",
                                                     con_ws_mode(con));
    }
    MyFree(data);
  } else if (hr_is(rec, "SILENCE")) {
    if (!check_only) {
      struct Ban *ban = make_ban(hr_str(rec, "mask"));
      struct Ban **tail;

      if (!ban)
        return 1;
      ban->flags |= (unsigned short)hr_get_int(rec, "flags", 0);
      ban->when = (time_t)hr_get_int(rec, "when", 0);
      ban->next = 0;
      for (tail = &cli_user(cptr)->silence; *tail; tail = &(*tail)->next)
        ;
      *tail = ban;
    }
  }

  return 1;
}

/** Rebuild one local client from a CLIENT record.
 *
 * The bookkeeping order mirrors register_user()'s MyConnect() branch, with
 * the pieces that only make sense for a connection registering for the first
 * time (default umodes, the welcome burst, IPcheck_connect_succeeded(), the
 * NICK propagation) left out.
 *
 * @param[in] rec CLIENT record to apply.
 * @param[in] check_only Non-zero to build the client without touching the
 *   descriptor, the event engine, IPcheck or the connection classes.
 * @return New client, or NULL when the record could not be applied.
 */
static struct Client *hr_apply_client(struct hr_record *rec, int check_only)
{
  struct Client *cptr;
  struct Listener *listener;
  const char *value;
  const char *ws = hr_str(rec, "ws");
  int fd = (int)hr_get_int(rec, "fd", -1);
  int is_ws = *ws && strcmp(ws, "none");
  int is_oper = 0;
  unsigned int index;

  if (check_only) {
    cptr = make_client(0, is_ws ? STAT_WEBSOCKET : STAT_UNKNOWN_USER);
    cli_fd(cptr) = -1;
    /* The pre-flight child runs the same conf_check_client() as the real
     * path, and attach_iline() reads the listener's port to match a Client
     * block's port= against it.  Without this the child would test a
     * different question than the one the real load will ask -- and used to
     * dereference a NULL listener outright.  No ref-count is taken: nothing
     * in check mode ever calls close_connection() to release one, and the
     * child exits without unwinding anything it built.  The check-mode
     * teardown below therefore clears cli_listener() before free_client(),
     * which would otherwise release a reference that was never taken. */
    cli_listener(cptr) = hr_find_listener((int)hr_get_int(rec, "port", 0));
  } else {
    listener = hr_find_listener((int)hr_get_int(rec, "port", 0));
    if (!(cptr = adopt_connection(fd, listener, is_ws))) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "hot reload: cannot adopt fd %d for %s", fd,
                hr_str(rec, "nick"));
      close(fd);
      return 0;
    }
    if (fd > HighestFd)
      HighestFd = fd;
    LocalClientArray[fd] = cptr;
  }

  make_user(cptr);

  ircd_strncpy(cli_username(cptr), hr_str(rec, "user"), USERLEN);
  ircd_strncpy(cli_user(cptr)->username, hr_str(rec, "user"), USERLEN);
  ircd_strncpy(cli_user(cptr)->host, hr_str(rec, "host"), HOSTLEN);
  ircd_strncpy(cli_user(cptr)->realhost, hr_str(rec, "realhost"), HOSTLEN);
  ircd_strncpy(cli_info(cptr), hr_str(rec, "info"), REALLEN);

  /* The dumped values win over what adopt_connection() read off the socket.
   * They are not the same thing: for a WEBIRC or Cloudflare-proxied client
   * the socket's peer is the proxy, while sockhost/sockip/ip hold the real
   * client's address that the old image had already substituted, and that is
   * what every ban, G-line and /WHOIS in the new image must see.  For an
   * ordinary client the two agree, so nothing is lost by preferring the
   * dump.  In check mode there is no socket and the dump is all there is. */
  value = hr_str(rec, "sockhost");
  if (*value)
    ircd_strncpy(cli_sockhost(cptr), value, HOSTLEN);
  value = hr_str(rec, "sockip");
  if (*value)
    ircd_strncpy(cli_sock_ip(cptr), value, SOCKIPLEN);
  value = hr_str(rec, "ip");
  if (*value)
    ircd_aton(&cli_ip(cptr), value);

  ircd_strncpy(cli_name(cptr), hr_str(rec, "nick"), NICKLEN);
  cli_firsttime(cptr) = (time_t)hr_get_int(rec, "firsttime", CurrentTime);
  cli_lastnick(cptr) = (time_t)hr_get_int(rec, "lastnick", TStime());

  cli_user(cptr)->server = &me;

  index = (unsigned int)hr_get_int(rec, "index", 0);
  if (!SetLocalNumNickAt(cptr, index)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "hot reload: numnick slot %u for %s busy", index,
              cli_name(cptr));
    if (check_only) {
      free_user(cli_user(cptr));
      cli_user(cptr) = 0;
      /* Balances the borrowed, un-refcounted listener set above: free_client()
       * calls release_listener() for a non-NULL cli_listener(). */
      cli_listener(cptr) = 0;
      free_client(cptr);
      return 0;
    }
    add_client_to_list(cptr);
    exit_client(cptr, cptr, &me, "Reload failed");
    return 0;
  }

  hAddClient(cptr);
  /* make_client() does not link the client itself.  On the connection path
   * start_auth() would have done this; here nothing else will. */
  add_client_to_list(cptr);

  Count_unknownbecomesclient(cptr, UserStats);
  SetUser(cptr);
  cli_handler(cptr) = CLIENT_HANDLER;

  hr_set_umodes(cptr, hr_str(rec, "umodes"), &is_oper);
  if (!is_oper && hr_get_int(rec, "oper", 0)) {
    SetFlag(cptr, FLAG_OPER);
    is_oper = 1;
  }
  hr_set_flags(cptr, hr_str(rec, "flags"));

  /* The account keys are authoritative over the P10 token in umodes. */
  value = hr_str(rec, "account");
  if (*value)
    ircd_strncpy(cli_user(cptr)->account, value, ACCOUNTLEN);
  if (hr_get(rec, "acc_id"))
    cli_user(cptr)->acc_id = (uint64_t)hr_get_int(rec, "acc_id", 0);
  if (hr_get(rec, "acc_flags"))
    cli_user(cptr)->acc_flags = (uint64_t)hr_get_int(rec, "acc_flags", 0);

  /* +x: the dumped host key already holds the hidden host, copied verbatim
   * above, so only the flag needs restoring.  hide_hostmask() would send the
   * client a spurious mode change and rebuild the host from the account. */
  if (IsInvisible(cptr))
    ++UserStats.inv_clients;
  if (is_oper) {
    ++UserStats.opers;
    cli_handler(cptr) = OPER_HANDLER;
  }

  /* set_snomask() masks the value by IsAnOper(), so it has to follow the
   * operator flags. */
  set_snomask(cptr, (unsigned int)hr_get_int(rec, "snomask", 0), SNO_SET);
  client_privs_from_string(cptr, hr_str(rec, "privs"));
  cli_capab(cptr) = cap_set_from_string(hr_str(rec, "caps"));
  cli_active(cptr) = cap_set_from_string(hr_str(rec, "active"));

  ircd_strncpy(cli_tls_fingerprint(cptr), hr_str(rec, "tlsfp"),
               sizeof(cli_tls_fingerprint(cptr)) - 1);

  if (hr_get_int(rec, "tls", 0))
    SetTLS(cptr);
  /* Only a kernel-offloaded session is driven raw.  This flag is what makes
   * close_connection() write a close_notify straight into the kernel record
   * layer, so a raw flag on a connection that is not TLS at all would push a
   * TLS alert down a plaintext socket; raw is meaningless without tls, and a
   * dump that claims one without the other is ignored rather than trusted. */
  if (hr_get_int(rec, "raw", 0) && IsTLS(cptr))
    SetTLSRaw(cptr);

  /* The TLS backend did not survive the exec: whatever blocked-direction and
   * retransmission state the old process held is gone, and the connection is
   * driven raw (kTLS) or plaintext from here. */
  s_tls(&cli_socket(cptr)) = NULL;
  cli_tls_want_rd(cptr) = IRCD_TLS_WANT_NONE;
  cli_tls_want_wr(cptr) = IRCD_TLS_WANT_NONE;
  cli_connect(cptr)->con_rexmit = NULL;
  cli_connect(cptr)->con_rexmit_len = 0;
  ClrFlag(cptr, FLAG_NEGOTIATING_TLS);

  if (is_ws)
    cli_ws_mode(cptr) = !strcmp(ws, "binary") ? WS_BINARY : WS_TEXT;

  value = hr_str(rec, "away");
  if (*value)
    DupString(cli_user(cptr)->away, value);

  cli_since(cptr) = cli_lasttime(cptr) = CurrentTime;
  cli_user(cptr)->last = CurrentTime;
  cli_nextnick(cptr) = (time_t)hr_get_int(rec, "nextnick", CurrentTime);
  cli_nexttarget(cptr) = (time_t)hr_get_int(rec, "nexttarget", CurrentTime);
  cli_sendM(cptr) = (unsigned int)hr_get_int(rec, "sendM", 0);
  cli_receiveM(cptr) = (unsigned int)hr_get_int(rec, "receiveM", 0);
  cli_sendB(cptr) = (uint64_t)hr_get_int(rec, "sendB", 0);
  cli_receiveB(cptr) = (uint64_t)hr_get_int(rec, "receiveB", 0);
  hr_set_targets(cptr, hr_str(rec, "targets"));

  ClrFlag(cptr, FLAG_PINGSENT);

  return cptr;
}

/** Test whether a descriptor belongs to something that is not a client.
 *
 * Every LISTENER record names an inherited listening socket, claimed or not,
 * and hotreload_fd names the dump this process is reading.  A CLIENT record
 * naming one of those describes a socket it does not own, and adopting it
 * would hand a listening socket or the dump file to the client read path.
 * Closing it would be worse: the listener or the dump would vanish from under
 * the code that does own it, so the caller only ever skips such a record.
 *
 * @param[in] fd Descriptor a CLIENT record claims.
 * @return Non-zero when \a fd is a listener's or the dump's.
 */
static int hr_fd_is_reserved(int fd)
{
  if (fd < 0 || fd >= MAXCONNECTIONS || !reserved_fds)
    return 0;

  return (reserved_fds[fd / 8] >> (fd % 8)) & 1;
}

/** Build the reserved descriptor bitmap for #reserved_fds.
 *
 * One pass over the records rather than one per client: the test above used
 * to walk every record for every CLIENT record, which is O(clients x records)
 * on a dump whose two dimensions grow together.  Descriptors outside
 * [0, MAXCONNECTIONS) are ignored because no CLIENT record with such an fd
 * ever reaches the test -- hr_apply_clients() has already rejected it.
 */
static void hr_build_reserved_fds(void)
{
  unsigned int i;
  int fd;

  MyFree(reserved_fds);
  reserved_fds = (unsigned char *)MyCalloc((MAXCONNECTIONS + 7) / 8, 1);

  for (i = 0; i < lines.count; i++) {
    if (!hr_is(&records[i], "LISTENER"))
      continue;
    fd = (int)hr_get_int(&records[i], "fd", -1);
    if (fd >= 0 && fd < MAXCONNECTIONS)
      reserved_fds[fd / 8] |= (unsigned char)(1 << (fd % 8));
  }

  if (hotreload_fd >= 0 && hotreload_fd < MAXCONNECTIONS)
    reserved_fds[hotreload_fd / 8] |=
      (unsigned char)(1 << (hotreload_fd % 8));
}

/** Rebuild every client in the dump, then its trailing per-client records.
 * @param[in] check_only Non-zero for a dry run.
 * @param[out] nclients Receives the number of clients rebuilt.
 * @param[out] nrejected Receives the number that failed re-authorisation.
 * @param[out] exits Receives the clients to exit once the rest of their
 *   records are in; the array is allocated here and owned by the caller.
 * @param[out] nexits Receives the number of entries in \a exits.
 */
static void hr_apply_clients(int check_only, unsigned int *nclients,
                             unsigned int *nrejected,
                             struct hr_pending_exit **exits,
                             unsigned int *nexits)
{
  unsigned int i;

  *nclients = 0;
  *nrejected = 0;
  *nexits = 0;
  *exits = (struct hr_pending_exit *)
    MyCalloc(lines.count + 1, sizeof(**exits));

  hr_build_reserved_fds();

  for (i = 0; i < lines.count; i++) {
    struct hr_record *rec = &records[i];
    struct Client *cptr;
    const char *reason = 0;
    int found_g;
    int fd;

    if (!hr_is(rec, "CLIENT"))
      continue;

    fd = (int)hr_get_int(rec, "fd", -1);
    if (fd < 0 || fd >= MAXCONNECTIONS) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "hot reload: client %s has out of range fd %d, skipping",
                hr_str(rec, "nick"), fd);
      continue;
    }

    /* Two CLIENT records naming the same descriptor: the second would adopt
     * a socket the first is already serving, so both clients would read and
     * write the same connection and the first would be dropped from
     * LocalClientArray without ever being freed.  The first record wins;
     * the descriptor is emphatically not closed, because it belongs to it. */
    if (fdmap[fd]) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "hot reload: client %s claims fd %d, already held by %s; "
                "skipping", hr_str(rec, "nick"), fd, cli_name(fdmap[fd]));
      continue;
    }

    /* A descriptor that is also named by a LISTENER record, or that is the
     * dump we are reading from, is not a client socket at all.  Adopting it
     * would put a listening socket or the dump file into LocalClientArray;
     * closing it would take the listener or the dump out from under the code
     * that owns it, so this only skips. */
    if (hr_fd_is_reserved(fd)) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "hot reload: client %s claims fd %d, which is a listener or "
                "the dump itself; skipping", hr_str(rec, "nick"), fd);
      continue;
    }

    if (!(cptr = hr_apply_client(rec, check_only)))
      continue;

    fdmap[fd] = cptr;
    (*nclients)++;

    /* Replaces the IPcheck_local_connect() that add_connection() does for a
     * new connection: the address is already counted against its registry
     * entry, so adopt it rather than charge for it twice.  Once per client,
     * and *before* the checks below, exactly as add_connection() counts the
     * client before register_user() reaches conf_check_client(): attach_iline()
     * compares IPcheck_nr() against the Client block's maximum, and that
     * count has to include this client or every host sits one connection
     * under its real load and the last permitted client is let in twice.
     * The rejection path below balances it -- exit_client() on a client with
     * a registered IPcheck entry runs IPcheck_disconnect(). */
    if (!check_only)
      IPcheck_adopt(cptr);

    /* Re-check the client against the configuration we have just parsed, the
     * way rehash() re-checks every local client after a config reload. */
    if (conf_check_client(cptr) != ACR_OK) {
      reason = "No longer authorized";
      (*nrejected)++;
    } else if ((found_g = find_kill(cptr))) {
      reason = (found_g == -2) ? "G-lined" : "K-lined";
      (*nrejected)++;
    }

    if (reason && !check_only) {
      (*exits)[*nexits].cptr = cptr;
      (*exits)[*nexits].reason = reason;
      (*nexits)++;
    }
  }

  /* The per-client records are keyed by descriptor, so a client that was
   * skipped simply has no entry and its records fall away with it. */
  for (i = 0; i < lines.count; i++) {
    struct hr_record *rec = &records[i];
    int fd;

    if (hr_is(rec, "CLIENT") || hr_is(rec, "INVITE") || !hr_get(rec, "fd"))
      continue;
    fd = (int)hr_get_int(rec, "fd", -1);
    if (fd < 0 || fd >= MAXCONNECTIONS || !fdmap[fd])
      continue;

    if (!hr_apply_client_sub(rec, fdmap[fd], check_only))
      log_write(LS_SYSTEM, L_ERROR, 0,
                "hot reload: undecodable %s record at line %u, dropping",
                rec->type, i + 1);
  }

  /* The send queues are complete now; tell the engine there is output, and
   * schedule a parse of any input the dump carried in the recvQ.
   *
   * A command the previous image had already read off the socket but not yet
   * parsed -- typically one pipelined behind the RELOAD itself, e.g. a PING
   * whose PONG the client is now waiting for -- rides across in the RECVQ
   * record and is restored into cli_recvQ() above.  adopt_connection() arms
   * readable interest, but a level-triggered engine only reports readable when
   * the *socket* has new bytes; this input sits in the userspace recvQ with an
   * empty socket behind it, so nothing would ever wake read_packet() to drain
   * it and the connection would go silent from the handoff onward.  Arming the
   * per-connection process timer makes read_packet() run once from the event
   * loop and consume it, exactly as the deferred-input path in read_packet()
   * itself does. */
  if (!check_only)
    for (i = 0; i < MAXCONNECTIONS; i++)
      if (fdmap[i]) {
        if (MsgQLength(&cli_sendQ(fdmap[i])))
          update_write(fdmap[i]);
        if (DBufLength(&cli_recvQ(fdmap[i])))
          schedule_recvq_process(fdmap[i]);
      }
}

/** Apply the MEMBER and BAN records, then the INVITE records. */
static void hr_apply_memberships(void)
{
  unsigned int i;
  unsigned int j;

  for (i = 0; i < lines.count; i++) {
    struct hr_record *rec = &records[i];
    struct Channel *chptr;

    if (hr_is(rec, "MEMBER")) {
      const char *status;
      unsigned int flags = 0;
      int fd = (int)hr_get_int(rec, "fd", -1);

      if (fd < 0 || fd >= MAXCONNECTIONS || !fdmap[fd])
        continue;
      if (!(chptr = FindChannel(hr_str(rec, "chan"))))
        continue;

      for (status = hr_str(rec, "status"); *status; status++)
        for (j = 0; j < HR_COUNT(hr_memberflags); j++)
          if (hr_memberflags[j].c == *status) {
            flags |= hr_memberflags[j].flag;
            break;
          }

      add_user_to_channel(chptr, fdmap[fd], flags,
                          (int)hr_get_int(rec, "oplevel", MAXOPLEVEL));
    } else if (hr_is(rec, "BAN")) {
      struct Ban *ban;

      if (!(chptr = FindChannel(hr_str(rec, "chan"))))
        continue;
      if (!(ban = make_ban(hr_str(rec, "mask"))))
        continue;

      ircd_strncpy(ban->who, hr_str(rec, "who"), NICKLEN);
      ban->when = (time_t)hr_get_int(rec, "when", 0);
      /* set_ban_mask() already decided BAN_IPMASK from the mask itself. */
      ban->flags = (unsigned short)hr_get_int(rec, "flags", 0)
                 | (ban->flags & BAN_IPMASK);
      channel_append_ban(chptr, ban);
    }
  }

  /* Invites last: every channel and every client now exists. */
  for (i = 0; i < lines.count; i++) {
    struct hr_record *rec = &records[i];
    struct Channel *chptr;
    int fd;

    if (!hr_is(rec, "INVITE"))
      continue;
    fd = (int)hr_get_int(rec, "fd", -1);
    if (fd < 0 || fd >= MAXCONNECTIONS || !fdmap[fd])
      continue;
    if (!(chptr = FindChannel(hr_str(rec, "chan"))))
      continue;
    add_invite(fdmap[fd], chptr);
  }
}

/** Apply the STATS record.
 * @param[in] rec STATS record to apply.
 */
static void hr_apply_stats(struct hr_record *rec)
{
  unsigned int i;

  max_client_count = (unsigned int)hr_get_int(rec, "max_clients",
                                              max_client_count);
  max_connection_count = (unsigned int)hr_get_int(rec, "max_connections",
                                                  max_connection_count);

  for (i = 0; i < HR_COUNT(hr_statfields); i++) {
    char *field = (char *)ServerStats + hr_statfields[i].offset;

    if (!hr_get(rec, hr_statfields[i].name))
      continue;
    if (hr_statfields[i].width == HR_STAT_U64)
      *(uint64_t *)field = (uint64_t)hr_get_int(rec, hr_statfields[i].name, 0);
    else
      *(unsigned int *)field =
        (unsigned int)hr_get_int(rec, hr_statfields[i].name, 0);
  }
}

/** Apply the dump that was read.
 * @param[in] check_only If non-zero, only check that the dump could be applied.
 * @return Non-zero on success, zero on failure.
 */
int hotreload_apply(int check_only)
{
  struct hr_pending_exit *exits = 0;
  struct Channel *chptr;
  unsigned int nexits = 0;
  unsigned int nclients = 0;
  unsigned int nchannels = 0;
  unsigned int nrejected = 0;
  unsigned int i;

  if (!pending)
    return 1;

  /* 1. Header.  A dump only ever describes the server that wrote it: loading
   * it into a differently named or numbered server would hand every client a
   * numeric belonging to somebody else. */
  if (strcmp(hr_str(&records[0], "server"), cli_name(&me))
      || strcmp(hr_str(&records[0], "numeric"), cli_yxx(&me))) {
    log_write(LS_SYSTEM, L_CRIT, 0,
              "hot reload: server identity changed (%s/%s vs %s/%s), refusing",
              hr_str(&records[0], "server"), hr_str(&records[0], "numeric"),
              cli_name(&me), cli_yxx(&me));
    if (!check_only) {
      /* Real successor image: close the inherited client and unclaimed
       * listener sockets this dump named before discarding the records, so
       * they do not leak for the life of the process (main() skips
       * close_connections() whenever hotreload_fd >= 0).  The pre-flight
       * child shares these fds with the live parent and must not touch
       * them; it just _exit()s. */
      hr_close_named_fds(lines.count);
      hr_reset();
    }
    return 0;
  }

  TSoffset = (time_t)hr_get_int(&records[0], "tsoffset", TSoffset);
  cli_serv(&me)->timestamp =
    (time_t)hr_get_int(&records[0], "start", cli_serv(&me)->timestamp);

  fdmap = (struct Client **)MyCalloc(MAXCONNECTIONS, sizeof(*fdmap));

  /* 2. Inherited listeners that nobody claimed while the config was parsed. */
  for (i = 0; i < lines.count; i++) {
    if (!hr_is(&records[i], "LISTENER") || claimed[i])
      continue;
    log_write(LS_SYSTEM, L_INFO, 0,
              "hot reload: closing inherited listener %s:%d "
              "(no longer configured)", hr_str(&records[i], "addr"),
              (int)hr_get_int(&records[i], "port", 0));
    if (!check_only)
      close((int)hr_get_int(&records[i], "fd", -1));
  }

  /* 3. Config, G-lines, jupes and S-lines, before any client can match one. */
  hr_apply_network_state();

  /* 4. Channels, before the memberships that point at them. */
  nchannels = hr_apply_channels();

  /* 5. Clients, and the per-client records that follow each of them. */
  hr_apply_clients(check_only, &nclients, &nrejected, &exits, &nexits);

  /* 6 and 7. Memberships, bans and then invites. */
  hr_apply_memberships();

  /* 8. Statistics last, so the counters the steps above bumped do not
   * outlive the dumped values. */
  for (i = 0; i < lines.count; i++)
    if (hr_is(&records[i], "STATS")) {
      hr_apply_stats(&records[i]);
      break;
    }

  /* 9. UserStats.channels is maintained by get_channel(), but recount it
   * from the list rather than trust an increment we did not make. */
  UserStats.channels = 0;
  for (chptr = GlobalChannelList; chptr; chptr = chptr->next)
    ++UserStats.channels;

  /* The clients that lost their authorisation go now, once their queues and
   * memberships are in place, so the ERROR line reaches them. */
  for (i = 0; i < nexits; i++) {
    int fd = cli_fd(exits[i].cptr);

    if (fd >= 0 && fd < MAXCONNECTIONS)
      fdmap[fd] = 0;
    exit_client(exits[i].cptr, exits[i].cptr, &me, exits[i].reason);
  }
  MyFree(exits);

  if (check_only) {
    /* Nothing built in check mode is ever served, and unwinding it would
     * mean re-implementing every teardown path; the caller is a forked child
     * that exits immediately afterwards. */
    log_write(LS_SYSTEM, L_INFO, 0,
              "hot reload: pre-flight ok: %u clients, %u channels",
              nclients, nchannels);
    MyFree(fdmap);
    fdmap = 0;
    MyFree(reserved_fds);
    reserved_fds = 0;
    return 1;
  }

  log_write(LS_SYSTEM, L_INFO, 0,
            "hot reload: applied: %u clients, %u channels, "
            "%u authorisation failures", nclients, nchannels, nrejected);
  hr_reset();
  return 1;
}
