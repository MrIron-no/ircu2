/*
 * IRC - Internet Relay Chat, ircd/m_burst.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 *
 * $Id$
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "ircd_snprintf.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int
netride_modes(int parc, char **parv, const char *curr_key)
{
  char *modes = parv[0];
  int result = 0;

  assert(modes && modes[0] == '+');
  while (*modes) {
    switch (*modes++) {
    case '-':
      return -1;
    case 'i':
      result |= MODE_INVITEONLY;
      break;
    case 'k':
      if (strcmp(curr_key, *++parv))
        result |= MODE_KEY;
      break;
    case 'l':
      ++parv;
      break;
    case 'r':
      result |= MODE_REGONLY;
      break;
    case 'Z':
      result |= MODE_TLSONLY;
      break;
    }
  }
  return result;
}

/** Decide whether ban metadata offered by a BURST beats what we store.
 *
 * Both sides of a heal run this over the same two pairs and must pick the
 * same winner, or the ban's setter and set time would keep flapping.  The
 * order is the one in doc/P11.md 8.1: a known setter beats an unknown one,
 * then the lower set time wins, then the strcmp()-smaller setter.
 *
 * @param[in] who_new Setter offered by the burst; "*" when unknown.
 * @param[in] when_new Set time offered by the burst.
 * @param[in] who_old Setter we currently store.
 * @param[in] when_old Set time we currently store.
 * @return Non-zero when the new metadata wins; zero when ours stands, which
 * includes the case of the two being identical.
 */
static int ban_meta_wins(const char *who_new, time_t when_new,
                         const char *who_old, time_t when_old)
{
  int new_known = (strcmp(who_new, "*") != 0);
  int old_known = (strcmp(who_old, "*") != 0);

  if (new_known != old_known)
    return new_known;
  if (when_new != when_old)
    return when_new < when_old;
  return strcmp(who_new, who_old) < 0;
}

/** Members of one BURST we can record for the relay.
 *
 * An incoming BURST line is at most BUFSIZE bytes and every member costs a
 * token plus a separator, i.e. at least two bytes: a short numnick resolves
 * just as well as a full one, so the bound must count the smallest token a
 * member can occupy, not the largest.  A well-formed line can never reach
 * this; it bounds a hostile one.
 */
#define BURST_RELAY_MEMBERS (BUFSIZE / 2 + 1)

/** Bans of one BURST we can record for the relay.
 *
 * The ban section is tokenised into at most BUFSIZE / 2 tokens and every
 * ban costs at least one of them; see #BURST_RELAY_MEMBERS.
 */
#define BURST_RELAY_BANS (BUFSIZE / 2 + 1)

/** One member accepted from an incoming BURST, held for the relay. */
struct BurstRelayMember {
  struct Client *user;		/**< The member itself. */
  unsigned int mode;		/**< Membership flags parsed for it. */
  int oplevel;			/**< Op level parsed for it. */
};

/** One ban accepted from an incoming BURST, held for the relay.
 *
 * The mask and setter are copied inline rather than aliased into the
 * channel's ban list: a later '+' parameter of the SAME BURST can free a
 * ban we recorded (mode_parse() -> mode_process_bans() -> free_ban() for a
 * ban staged ADD then DEL), and free_ban() recycles the slot onto a static
 * free-list, so a surviving pointer would be a use-after-free the relay
 * then formats to every downlink.  Owning the bytes keeps the relay correct
 * no matter what the rest of the parse does to the ban list.  The inline
 * arrays cost ~126 bytes each; see #BURST_RELAY_BANS for the array size.
 */
struct BurstRelayBan {
  char mask[NICKLEN + USERLEN + HOSTLEN + 4];	/**< Canonicalised mask. */
  time_t when;			/**< Set time we stored for it. */
  char who[NICKLEN + 1];	/**< Setter we stored for it; "" relays as "*". */
  int p11_only;			/**< Metadata-only update: P11 links only. */
};

/** Record one accepted ban for the relay, if there is room for it.
 *
 * @param[out] rbans Bans recorded so far.
 * @param[in,out] nrbans Number of entries in \a rbans.
 * @param[in] mask Canonicalised mask; copied, not aliased.
 * @param[in] when Set time we stored for the ban.
 * @param[in] who Setter we stored for the ban; copied, not aliased.
 * @param[in] p11_only Non-zero for a metadata-only update, which is
 * relayed to P11 downlinks only because a P10 one cannot express it.
 */
static void burst_record_ban(struct BurstRelayBan *rbans, int *nrbans,
                             const char *mask, time_t when, const char *who,
                             int p11_only)
{
  if (*nrbans >= BURST_RELAY_BANS)
    return; /* unreachable for a BUFSIZE line; see BURST_RELAY_BANS */

  /* Copy the strings: the channel's ban list can be reshaped or freed by a
   * later parameter of this same BURST before the relay runs. */
  ircd_strncpy(rbans[*nrbans].mask, mask, sizeof(rbans[*nrbans].mask) - 1);
  rbans[*nrbans].when = when;
  ircd_strncpy(rbans[*nrbans].who, who, sizeof(rbans[*nrbans].who) - 1);
  rbans[*nrbans].p11_only = p11_only;
  (*nrbans)++;
}

/** Parse the ban section of a BURST message and apply it to \a chptr.
 *
 * On a P10 link the section is a list of masks and the receiver invents the
 * metadata: an unknown setter and its own current time.  On a P11 link it is
 * a list of \<mask\> \<ts\> \<who\> triples (doc/P11.md 8.1); a framing error
 * there rejects the whole section, while a ts out of range or an overlong
 * setter is repaired, because a ban is never dropped over its metadata.
 *
 * Each ban that is genuinely new to the channel is appended to the channel's
 * ban list and recorded for the relay.  A mask we already knew is recorded
 * too, but only when its metadata changed here and only for P11 downlinks,
 * which are the only ones that can express the change, so that they
 * converge.  Nothing is encoded here: burst_relay() does that once per link
 * layout, when the whole message has been parsed and its size is known.
 *
 * @param[in] cptr Local server connection the BURST arrived on.
 * @param[in] sptr Server that sent the BURST.
 * @param[in,out] chptr Channel the bans belong to.
 * @param[in] section Ban section of the BURST, i.e. the text after the '%'.
 * @param[in] parse_flags Mode parser flags for this BURST; the bans are only
 * applied when MODE_PARSE_SET is set.
 * @param[out] rbans Bans accepted so far, for the relay.
 * @param[in,out] nrbans Number of entries in \a rbans.
 * @return Number of new bans added to the channel.
 */
static int burst_parse_bans(struct Client *cptr, struct Client *sptr,
                            struct Channel *chptr, char *section,
                            unsigned int parse_flags,
                            struct BurstRelayBan *rbans, int *nrbans)
{
  char *p = 0, *ban, *ptr;
  char *tok[BUFSIZE / 2];
  struct Ban *lp, *newban;
  int new_bans = 0;
  int p11 = (Protocol(cptr) >= 11);
  int ntok = 0, i, step;

  if (!(parse_flags & MODE_PARSE_SET))
    return 0;

  for (ptr = ircd_strtok(&p, section, " "); ptr;
       ptr = ircd_strtok(&p, 0, " ")) {
    if (ntok >= (int)(sizeof(tok) / sizeof(tok[0]))) {
      /* Running out of token slots means the section is not what it claims
       * to be; applying the part that fitted would leave the ban list in a
       * state neither side agreed on. */
      protocol_violation(sptr, "BURST ban section has too many tokens");
      return 0;
    }
    tok[ntok++] = ptr;
  }

  if (p11) {
    /* Validate the framing of the whole section before applying any of it,
     * so that a rejected section leaves the ban list untouched. */
    if (ntok % 3 != 0) {
      protocol_violation(sptr, "BURST ban section has %d tokens, not a "
			 "multiple of 3", ntok);
      return 0;
    }

    for (i = 0; i < ntok; i += 3) {
      /* strIsDigit() is vacuously true for the empty string. */
      if (!tok[i + 1][0] || !strIsDigit(tok[i + 1])) {
	/* protocol_violation() wallops the whole network, so report the
	 * shape of the offending field, never its bytes. */
	protocol_violation(sptr, "Invalid ban timestamp (%u bytes, not "
			   "numeric) in BURST",
			   (unsigned int)strlen(tok[i + 1]));
	return 0;
      }
    }
  }

  step = p11 ? 3 : 1;
  for (i = 0; i < ntok; i += step) {
    char whobuf[NICKLEN + 1];
    const char *who;
    time_t when;

    ban = collapse(pretty_mask(tok[i]));

    if (p11) {
      when = atotime(tok[i + 1]);
      /* Repair rather than reject: a ban is never dropped over its
       * metadata (doc/P11.md 8.1). */
      if (when < OLDEST_TS || when > TStime() + 60)
	when = TStime();
      /* who[] is NICKLEN+1 bytes, so this truncates and stays terminated. */
      ircd_strncpy(whobuf, tok[i + 2], NICKLEN);
      /* The setter is echoed in RPL_BANLIST and relayed onward verbatim, so
       * a peer must not be able to park arbitrary bytes in it.  Anything
       * that is not a nick (and not the "*" that means "unknown", which is
       * not one either) degrades to "*"; the ban itself is still kept. */
      if (strcmp(whobuf, "*")) {
	const char *q;
	for (q = whobuf; *q; q++)
	  if (!IsNickChar(*q))
	    break;
	if (*q || !whobuf[0])
	  strcpy(whobuf, "*");
      }
      who = whobuf;
    } else {
      /* A P10 peer has nothing to say about a ban but its mask. */
      when = TStime();
      who = "*";
    }

      /*
       * Yeah, we should probably do this elsewhere, and make it better
       * and more general; this will hold until we get there, though.
       * I dislike the current add_banid API... -Kev
       *
       * I wish there were a better algo. for this than the n^2 one
       * shown below *sigh*
       */
    for (lp = chptr->banlist; lp; lp = lp->next) {
      if (!ircd_strcmp(lp->banstr, ban)) {
	/* The mask already exists, but its metadata may still be wrong
	 * here.  Overwriting it is silent: no MODE is shown to local
	 * clients, who see the new values on their next ban-list request.
	 * The change does go to P11 downlinks, so that they converge. */
	if (ban_meta_wins(who, when, lp->who, lp->when)) {
	  ircd_strncpy(lp->who, who, NICKLEN);
	  lp->when = when;
	  burst_record_ban(rbans, nrbans, lp->banstr, lp->when, lp->who, 1);
	}
	ban = 0; /* don't add ban */
	lp->flags &= ~BAN_BURST_WIPEOUT; /* not wiping out */
	break; /* new ban already existed; don't even repropagate */
      } else if (!(lp->flags & BAN_BURST_WIPEOUT) &&
		 !mmatch(lp->banstr, ban)) {
	ban = 0; /* don't add ban unless wiping out bans */
	break; /* new ban is encompassed by an existing one; drop */
      } else if (!mmatch(ban, lp->banstr))
	lp->flags |= BAN_OVERLAPPED; /* remove overlapping ban */

      if (!lp->next)
	break;
    }

    if (ban) { /* add the new ban to the end of the list */
      newban = make_ban(ban); /* create new ban */
      ircd_strncpy(newban->who, who, NICKLEN);
      newban->when = when;
      newban->flags |= BAN_BURSTED;
      newban->next = 0;
      /* burst_record_ban() takes its own copy of the mask and setter, so it
       * is safe to hand it the ban-list entry that a later '+' parameter of
       * this BURST may go on to free. */
      burst_record_ban(rbans, nrbans, newban->banstr, newban->when,
		       newban->who, 0);
      if (lp)
	lp->next = newban; /* link it in */
      else
	chptr->banlist = newban;
      new_bans++;
    }
  }

  return new_bans;
}

/** Build the status specifier for one member of a relayed BURST line.
 *
 * Two transitions cannot be expressed in the middle of a line and need a
 * continuation line, which starts over in the "no status" state
 * (doc/P11.md 8.1):
 *
 *  - Returning to "no status" after a status group.  A bare ':' does not
 *    say it: a receiver parsing \<numeric\>':' runs no specifier iteration
 *    at all and carries the previous status forward, silently opping a
 *    member that has none.
 *  - An op level lower than the previous one.  The grammar only has
 *    increments, and a decrement printed unsigned becomes a ten-digit
 *    level that no receiver can parse back.
 *
 * @param[out] spec Buffer for the specifier; set to "" when none is needed.
 * @param[in] speclen Size of \a spec.
 * @param[in] mode Status of this member, already masked for the link.
 * @param[in] oplevel Op level of this member.
 * @param[in] last_mode Status the current line is in; 0 is "no status".
 * @param[in] last_oplevel Op level the current line is at.
 * @return Non-zero when \a spec holds the specifier to use, zero when this
 * member cannot be expressed on the current line at all.
 */
static int burst_relay_spec(char *spec, size_t speclen, unsigned int mode,
                            int oplevel, unsigned int last_mode,
                            int last_oplevel)
{
  size_t loc = 0;

  assert(speclen > 3 + MAXOPLEVELDIGITS);
  /* An op level outside this range would print more digits than the buffer
   * and spec[loc] below would write past its end.  It is only ever printed
   * for an opped member -- a member without status carries the -1 sentinel
   * -- so the invariant is guarded on CHFL_CHANOP.  The parse-time clamp in
   * ms_burst() keeps an opped level in range; this catches a future caller
   * that does not.  ircd_snprintf() returns the WOULD-BE length, not what it
   * wrote, so loc is taken from strlen() after every format, never from it. */
  assert(!(mode & CHFL_CHANOP) || (oplevel >= 0 && oplevel <= MAXOPLEVEL));

  if (mode != last_mode) {
    if (!mode)
      return 0; /* "no status" after a status group */

    spec[loc++] = ':';
    if (mode & CHFL_DELAYED)
      spec[loc++] = 'd';
    if (mode & CHFL_VOICE)
      spec[loc++] = 'v';
    if (mode & CHFL_CHANOP) {
      /* A group change always restates the *absolute* level. */
      if (oplevel == MAXOPLEVEL)
        spec[loc++] = 'o';
      else {
        ircd_snprintf(0, spec + loc, speclen - loc, "%u",
                      (unsigned int)oplevel);
        loc = strlen(spec);
      }
    }
  } else if ((mode & CHFL_CHANOP) && oplevel != last_oplevel) {
    if (oplevel < last_oplevel)
      return 0; /* a decrement is not an increment */

    spec[loc++] = ':';
    ircd_snprintf(0, spec + loc, speclen - loc, "%u",
                  (unsigned int)(oplevel - last_oplevel));
    loc = strlen(spec);
  }

  spec[loc] = '\0';
  return 1;
}

/** Start a (continuation) BURST line: "\<\#channel\> \<TS\>".
 *
 * @param[out] buf Line buffer.
 * @param[in] buflen Size of \a buf.
 * @param[in] chptr Channel being burst.
 * @return Number of bytes now in \a buf.
 */
static int burst_relay_head(char *buf, size_t buflen, struct Channel *chptr)
{
  ircd_snprintf(&me, buf, buflen, "%H %Tu", chptr, chptr->creationtime);
  return (int)strlen(buf);
}

/** Relay one accepted BURST onward, in one link layout.
 *
 * The line is rebuilt from what we accepted rather than forwarded verbatim,
 * and the rebuilt form is not bounded by the incoming one: the P11 layout
 * of a P10 ban list gains a "\<ts\> \<who\>" per mask, and a status change
 * re-emits an absolute op level where the input had a two-byte increment.
 * Whatever does not fit therefore continues on a further BURST line for the
 * same channel and timestamp (doc/P11.md 8.1):
 *
 *  - Only the first line carries the mode block; it cannot be split.
 *  - A continuation line starts in the "no status" state, so its first
 *    member restates the absolute status of its group.
 *  - Two transitions are inexpressible mid-line and start a continuation
 *    line on their own account, see burst_relay_spec().
 *  - The ban list rides on whichever line has room after the last member
 *    and spills onto further lines by itself; ":%" opens the section on
 *    each of them, and such a bans-only line is still parc > 3.
 *
 * sendcmdto_prot_serv_butone() prefixes "\<numeric\> \<token\> " itself and
 * msgq_vmake() silently truncates whatever does not fit BUFSIZE, so the
 * budget here counts that prefix and the CRLF and no line we build can be
 * cut on the wire.  Truncation would not merely lose a tail: a P11 receiver
 * rejects a ban section whose token count is not a multiple of three, which
 * would strip every ban of the channel from the subtree below us.
 *
 * At least one line is always sent, even when nothing at all was accepted.
 *
 * @param[in] sptr Server the BURST came from; also the source of the relay.
 * @param[in] cptr Local link it arrived on, which is skipped.
 * @param[in] chptr Channel being burst.
 * @param[in] modestr Mode block, already leading with a space, or "".
 * @param[in] members Members we accepted, in the order they arrived.
 * @param[in] nmembers Number of entries in \a members.
 * @param[in] bans Bans we accepted, in the order they arrived.
 * @param[in] nbans Number of entries in \a bans.
 * @param[in] min_prot Lowest link protocol to send to, or 0 for no bound.
 * @param[in] max_prot One past the highest link protocol, or 0 for none.
 * @param[in] p11 Non-zero to build the P11 layout (the hidden-member 'd'
 * specifier and ban triples), zero for the P10 one.
 */
static void burst_relay(struct Client *sptr, struct Client *cptr,
                        struct Channel *chptr, const char *modestr,
                        const struct BurstRelayMember *members, int nmembers,
                        const struct BurstRelayBan *bans, int nbans,
                        unsigned short min_prot, unsigned short max_prot,
                        int p11)
{
  char line[BUFSIZE];
  char entry[BUFSIZE];
  char spec[4 + MAXOPLEVELDIGITS];
  char scratch[NUMNICKLEN + 8];
  unsigned int last_mode = 0;
  int last_oplevel = 0;
  int first_entry = 1, first_ban = 1;
  int prefix_len, budget, len, elen;
  int i, attempt;

  /* A server numeric is two characters, but read the real width off the
   * formatter rather than assume it.  %C only renders a numeric when the
   * destination is a server, so every formatter here addresses &me. */
  prefix_len = ircd_snprintf(&me, scratch, sizeof(scratch),
                             "%C " TOK_BURST " ", sptr);
  budget = BUFSIZE - 2 - prefix_len; /* the 2 is the CRLF */

  len = burst_relay_head(line, sizeof(line), chptr);
  /* The mode block cannot be split: a continuation line never carries one.
   * It is bounded by the channel name and the simple modes with their
   * arguments (limit, key, Apass, Upass), which together stay well inside
   * the budget, so the first line never overflows it. */
  ircd_snprintf(&me, line + len, sizeof(line) - len, "%s", modestr);
  len = (int)strlen(line);

  for (i = 0; i < nmembers; i++) {
    unsigned int mode = members[i].mode
                        & (CHFL_VOICED_OR_OPPED | (p11 ? CHFL_DELAYED : 0));
    int oplevel = members[i].oplevel;

    /* A hidden member never has status (doc/P11.md 8.1). */
    if (mode & CHFL_VOICED_OR_OPPED)
      mode &= ~CHFL_DELAYED;

    for (attempt = 0; attempt < 2; attempt++) {
      if (burst_relay_spec(spec, sizeof(spec), mode, oplevel, last_mode,
                           last_oplevel)) {
        ircd_snprintf(&me, entry, sizeof(entry), "%c%C%s",
                      first_entry ? ' ' : ',', members[i].user, spec);
        elen = (int)strlen(entry);
        if (len + elen <= budget) {
          strcpy(line + len, entry); /* checked against the budget above */
          len += elen;
          first_entry = 0;
          last_mode = mode;
          if (mode & CHFL_CHANOP)
            last_oplevel = oplevel;
          break;
        }
      }

      /* Either the transition or the room ran out; continue on a fresh
       * line, where the status starts over at "none", and encode this
       * member again as its first entry. */
      if (attempt) {
        /* Unreachable: an entry is at most twelve bytes and a fresh line
         * has the whole budget.  Report rather than drop silently, so a
         * future budget miss is visible instead of losing channel state. */
        protocol_violation(sptr, "BURST relay entry does not fit any line");
        break;
      }
      sendcmdto_prot_serv_butone(sptr, CMD_BURST, cptr, min_prot, max_prot,
                                 "%s", line);
      len = burst_relay_head(line, sizeof(line), chptr);
      first_entry = 1;
      last_mode = 0;
      last_oplevel = 0;
    }
  }

  for (i = 0; i < nbans; i++) {
    const char *who;

    if (bans[i].p11_only && !p11)
      continue; /* a metadata-only update says nothing to a P10 peer */

    /* mode_parse_ban() always leaves a nick or a "*" behind, but a ban that
     * somehow lost its setter would put an empty field on the wire. */
    who = (bans[i].who && bans[i].who[0]) ? bans[i].who : "*";

    for (attempt = 0; attempt < 2; attempt++) {
      if (p11)
        ircd_snprintf(&me, entry, sizeof(entry), "%s%s %Tu %s",
                      first_ban ? " :%" : " ", bans[i].mask, bans[i].when,
                      who);
      else
        ircd_snprintf(&me, entry, sizeof(entry), "%s%s",
                      first_ban ? " :%" : " ", bans[i].mask);
      elen = (int)strlen(entry);
      if (len + elen <= budget) {
        strcpy(line + len, entry); /* checked against the budget above */
        len += elen;
        first_ban = 0;
        break;
      }

      if (attempt) {
        /* Unreachable: a ban entry is at most ~131 bytes and a fresh line
         * has the whole budget.  Report rather than drop silently. */
        protocol_violation(sptr, "BURST relay entry does not fit any line");
        break;
      }
      sendcmdto_prot_serv_butone(sptr, CMD_BURST, cptr, min_prot, max_prot,
                                 "%s", line);
      len = burst_relay_head(line, sizeof(line), chptr);
      first_ban = 1;
    }
  }

  sendcmdto_prot_serv_butone(sptr, CMD_BURST, cptr, min_prot, max_prot,
                             "%s", line);
}

/*
 * ms_burst - server message handler
 *
 * --  by Run carlo@runaway.xs4all.nl  december 1995 till march 1997
 *
 * parv[0] = sender prefix
 * parv[1] = channel name
 * parv[2] = channel timestamp
 * The meaning of the following parv[]'s depend on their first character:
 * If parv[n] starts with a '+':
 * Net burst, additive modes
 *   parv[n] = <mode>
 *   parv[n+1] = <param> (optional)
 *   parv[n+2] = <param> (optional)
 * If parv[n] starts with a '%', then n will be parc-1:
 *   parv[n] = %<ban> <ban> <ban> ...
 * If parv[n] starts with another character:
 *   parv[n] = <nick>[:<mode>],<nick>[:<mode>],...
 *   where <mode> defines the mode and op-level
 *   for nick and all following nicks until the
 *   next <mode> field.
 *   Digits in the <mode> field have of two meanings:
 *   1) if it is the first field in this BURST message
 *      that contains digits, and/or when a 'v' is
 *      present in the <mode>:
 *      The absolute value of the op-level.
 *   2) if there are only digits in this field and
 *      it is not the first field with digits:
 *      An op-level increment relative to the previous
 *      op-level.
 *   First all modeless nicks must be emmitted,
 *   then all combinations of modes without ops
 *   (currently that is only 'v') followed by the same
 *   series but then with ops (currently 'o','ov').
 *
 * Example:
 * "A8 B #test 87654321 +ntkAl key secret 123 A8AAG,A8AAC:v,A8AAA:0,A8AAF:2,A8AAD,A8AAB:v1,A8AAE:1 :%ban1 ban2"
 *
 * <mode> list example:
 *
 * "xxx,sss:v,ttt,aaa:123,bbb,ccc:2,ddd,kkk:v2,lll:2,mmm"
 *
 * means
 *
 *  xxx		// first modeless nicks
 *  sss +v	// then opless nicks
 *  ttt +v	// no ":<mode>": everything stays the same
 *  aaa -123	// first field with digit: absolute value
 *  bbb -123
 *  ccc -125	// only digits, not first field: increment
 *  ddd -125
 *  kkk -2 +v	// field with a 'v': absolute value
 *  lll -4 +v	// only digits: increment
 *  mmm -4 +v
 *
 * Anti net.ride code.
 *
 * When the channel already exist, and its TS is larger than
 * the TS in the BURST message, then we cancel all existing modes.
 * If its is smaller then the received BURST message is ignored.
 * If it's equal, then the received modes are just added.
 *
 * BURST is also accepted outside a netburst now because it
 * is sent upstream as reaction to a DESTRUCT message.  For
 * these BURST messages it is possible that the listed channel
 * members are already joined.
 *
 * The relayed BURST is built in two variants: the P10 variant must stay
 * byte-identical to the 2.10.12 form; the P11 variant may add per-link
 * extensions (see doc/P11.md 8.1).  Either variant can come out longer than
 * what we received (an absolute op level printed for a peer's increment, a
 * P10 ban list gaining "<ts> <who>" on a P11 downlink), so the relay is not
 * bounded by the incoming line: it emits further BURST lines under the wire
 * budget instead of truncating or dropping anything (see burst_relay()).
 */
int ms_burst(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct ModeBuf modebuf, *mbuf = 0;
  struct Channel *chptr;
  time_t timestamp;
  struct Membership *member, *nmember;
  struct Ban *lp, **lp_p;
  unsigned int parse_flags = (MODE_PARSE_FORCE | MODE_PARSE_BURST);
  int param;
  int new_bans = 0;
  int p11 = (Protocol(cptr) >= 11);
  char modestr[BUFSIZE];
  /* What we accept is recorded here and encoded afterwards, once per link
   * layout: the relayed line is not bounded by the incoming one and may
   * need continuation lines, which cannot be decided while parsing. */
  struct BurstRelayMember rmembers[BURST_RELAY_MEMBERS];
  struct BurstRelayBan rbans[BURST_RELAY_BANS];
  int nrmembers = 0, nrbans = 0, rmembers_full = 0;

  if (parc < 3)
    return protocol_violation(sptr,"Too few parameters for BURST");
  
  /* A server-sourced BURST is not subject to get_channel()'s CHANNELLEN
   * truncation (that is gated on MyUser), so a peer could otherwise create a
   * name long enough to leave the relay head no room and silently drop
   * entries.  Reject it here instead. */
  if (!IsChannelName(parv[1]) || strlen(parv[1]) > CHANNELLEN)
    return protocol_violation(sptr, "Invalid channel name in BURST");

  if (!(chptr = get_channel(sptr, parv[1], CGT_CREATE)))
    return 0; /* can't create the channel? */

  timestamp = atotime(parv[2]);

  if (chptr->creationtime)	/* 0 for new (empty) channels,
                                   i.e. when this server just restarted. */
  {
    if (parc == 3)		/* Zannel BURST? */
    {
      /* An empty channel without +A set, will cause a BURST message
	 with exactly 3 parameters (because all modes have been reset).
	 If the timestamp on such channels is only a few seconds older
	 from our own, then we ignore this burst: we do not deop our
	 own side.
	 Likewise, we expect the other (empty) side to copy our timestamp
	 from our own BURST message, even though it is slightly larger.

	 The reason for this is to allow people to join an empty
	 non-A channel (a zannel) during a net.split, and not be
	 deopped when the net reconnects (with another zannel). When
	 someone joins a split zannel, their side increments the TS by one.
	 If they cycle a few times then we still don't have a reason to
	 deop them. Theoretically I see no reason not to accept ANY timestamp,
	 but to be sure, we only accept timestamps that are just a few
	 seconds off (one second for each time they cycled the channel). */

      /* Don't even deop users who cycled four times during the net.break. */
      if (timestamp < chptr->creationtime &&
          chptr->creationtime <= timestamp + 4 &&
	  chptr->users != 0)	/* Only do this when WE have users, so that
	  			   if we do this the BURST that we sent has
				   parc > 3 and the other side will use the
				   test below: */
	timestamp = chptr->creationtime; /* Do not deop our side. */
    }
    else if (chptr->creationtime < timestamp &&
             timestamp <= chptr->creationtime + 4 &&
	     chptr->users == 0)
    {
      /* If one side of the net.junction does the above
         timestamp = chptr->creationtime, then the other
	 side must do this: */
      chptr->creationtime = timestamp;	/* Use the same TS on both sides. */
    }
    /* In more complex cases, we might still end up with a
       creationtime desync of a few seconds, but that should
       be synced automatically rather quickly (every JOIN
       caries a timestamp and will sync it; modes by users do
       not carry timestamps and are accepted regardless).
       Only when nobody joins the channel on the side with
       the oldest timestamp before a new net.break occurs
       precisely inbetween the desync, an unexpected bounce
       might happen on reconnect. */
  }

  if (!chptr->creationtime || chptr->creationtime > timestamp) {
    /*
     * Kick local members if channel is +i or +k and our TS was larger
     * than the burst TS (anti net.ride). The modes hack is here because
     * we have to do this before mode_parse, as chptr may go away.
     */
    for (param = 3; param < parc; param++)
    {
      int check_modes;
      if (parv[param][0] != '+')
        continue;
      check_modes = netride_modes(parc - param, parv + param, chptr->mode.key);
      if (check_modes < 0)
      {
        if (chptr->users == 0)
          sub1_from_channel(chptr);
        return protocol_violation(sptr, "Invalid mode string in BURST");
      }
      else if (check_modes)
      {
        /* Clear any outstanding rogue invites */
        mode_invite_clear(chptr);
        for (member = chptr->members; member; member = nmember)
        {
          nmember = member->next_member;
          if (!MyUser(member->user) || IsZombie(member))
            continue;
          /* Kick as netrider if key mismatch *or* remote channel is
           * +i (unless user is an oper) *or* remote channel is +r
           * (unless user has an account).
           */
          if (!(check_modes & MODE_KEY)
              && (!(check_modes & MODE_INVITEONLY) || IsAnOper(member->user))
              && (!(check_modes & MODE_REGONLY) || IsAccount(member->user))
              && (!(check_modes & MODE_TLSONLY) || IsTLS(member->user)))
            continue;
          sendcmdto_serv_butone(&me, CMD_KICK, NULL, "%H %C :Net Rider", chptr, member->user);
          sendcmdto_channel_butserv_butone(&his, CMD_KICK, chptr, NULL, 0, "%H %C :Net Rider", chptr, member->user);
          make_zombie(member, member->user, &me, &me, chptr);
        }
      }
      break;
    }

    /* If the channel had only locals, it went away by now. */
    if (!(chptr = get_channel(sptr, parv[1], CGT_CREATE)))
      return 0; /* can't create the channel? */
  }

  /* turn off burst joined flag */
  for (member = chptr->members; member; member = member->next_member)
    member->status &= ~(CHFL_BURST_JOINED|CHFL_BURST_ALREADY_OPPED|CHFL_BURST_ALREADY_VOICED);

  if (!chptr->creationtime) /* mark channel as created during BURST */
    chptr->mode.mode |= MODE_BURSTADDED;

  /* new channel or an older one */
  if (!chptr->creationtime || chptr->creationtime > timestamp) {
    chptr->creationtime = timestamp;

    modebuf_init(mbuf = &modebuf, &me, cptr, chptr,
		 MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);
    modebuf_mode(mbuf, MODE_DEL | chptr->mode.mode); /* wipeout modes */
    chptr->mode.mode &= MODE_BURSTADDED | MODE_WASDELJOINS;

    /* wipeout any limit and keys that are set */
    parse_flags |= (MODE_PARSE_SET | MODE_PARSE_WIPEOUT);

    /* mark bans for wipeout */
    for (lp = chptr->banlist; lp; lp = lp->next)
      lp->flags |= BAN_BURST_WIPEOUT;

    /* clear topic set by netrider (if set) */
    if (*chptr->topic) {
      *chptr->topic = '\0';
      *chptr->topic_nick = '\0';
      chptr->topic_time = 0;
      sendcmdto_channel_butserv_butone(&his, CMD_TOPIC, chptr, NULL, 0,
                                       "%H :%s", chptr, chptr->topic);
    }
  } else if (chptr->creationtime == timestamp) {
    modebuf_init(mbuf = &modebuf, &me, cptr, chptr,
		 MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);

    parse_flags |= MODE_PARSE_SET; /* set new modes */
  }

  param = 3; /* parse parameters */
  while (param < parc) {
    switch (*parv[param]) {
    case '+': /* parameter introduces a mode string */
      param += mode_parse(mbuf, cptr, sptr, chptr, parc - param,
			  parv + param, parse_flags, NULL);
      break;

    case '%': /* parameter contains bans */
      new_bans += burst_parse_bans(cptr, sptr, chptr, parv[param] + 1,
				   parse_flags, rbans, &nrbans);
      param++; /* look at next param */
      break;

    default: /* parameter contains clients */
      {
	struct Client *acptr;
	char *nicklist = parv[param], *p = 0, *nick, *ptr;
	unsigned int current_mode, base_mode;
	int oplevel = -1;	/* Mark first field with digits: means the same as 'o' (but with level). */
	struct Membership* member;

        /* Whether a status-less member is hidden is inferred from +D, except
         * on a P11 link that we are actually taking modes from: there the
         * sender says so with 'd' and nothing is inferred (doc/P11.md 8.1).
         *   - P11, our TS equal or older (MODE_PARSE_SET): hidden iff 'd'.
         *   - P11, our TS newer: the incoming channel lost and its members
         *     are fresh joins to ours, so 'd' is ignored just like o/v and
         *     our own +D decides.
         *   - P10: no 'd' exists, so +D always decides.
         */
        base_mode = CHFL_DEOPPED | CHFL_BURST_JOINED;
        if (!(p11 && (parse_flags & MODE_PARSE_SET))
            && (chptr->mode.mode & MODE_DELJOINS))
            base_mode |= CHFL_DELAYED;
        current_mode = base_mode;

	for (nick = ircd_strtok(&p, nicklist, ","); nick;
	     nick = ircd_strtok(&p, 0, ",")) {

	  if ((ptr = strchr(nick, ':'))) { /* new flags; deal */
	    *ptr++ = '\0';

	    if (parse_flags & MODE_PARSE_SET) {
	      int current_mode_needs_reset;
	      for (current_mode_needs_reset = 1; *ptr; ptr++) {
		if (*ptr == 'o') { /* has oper status */
		  /*
		   * An 'o' is pre-oplevel protocol, so this is only for
		   * backwards compatibility.  Give them an op-level of
		   * MAXOPLEVEL so everyone can deop them.
		   */
		  oplevel = MAXOPLEVEL;
		  if (current_mode_needs_reset) {
		    current_mode = base_mode;
		    current_mode_needs_reset = 0;
		  }
		  current_mode = (current_mode & ~(CHFL_DEOPPED | CHFL_DELAYED
                                  | CHFL_DELAYED_TARGET)) | CHFL_CHANOP;
                  /*
                   * Older servers may send XXYYY:ov, in which case we
                   * do not want to use the code for 'v' below.
                   */
                  if (ptr[1] == 'v') {
                    current_mode |= CHFL_VOICE;
                    ptr++;
                  }
		}
		else if (*ptr == 'v') { /* has voice status */
		  if (current_mode_needs_reset) {
                    current_mode = base_mode;
		    current_mode_needs_reset = 0;
		  }
		  current_mode = (current_mode & ~(CHFL_DELAYED | CHFL_DELAYED_TARGET)) | CHFL_VOICE;
		  oplevel = -1;	/* subsequent digits are an absolute op-level value. */
                }
		else if (*ptr == 'd' && p11) { /* hidden (delayed join) */
		  if (current_mode_needs_reset) {
		    current_mode = base_mode;
		    current_mode_needs_reset = 0;
		  }
		  current_mode |= CHFL_DELAYED;
		}
		else if (IsDigit(*ptr)) {
		  int level_increment = 0;
		  if (oplevel == -1) { /* op-level is absolute value? */
		    if (current_mode_needs_reset) {
		      current_mode = base_mode;
		      current_mode_needs_reset = 0;
		    }
		    oplevel = 0;
		  }
		  current_mode = (current_mode & ~(CHFL_DEOPPED | CHFL_DELAYED | CHFL_DELAYED_TARGET)) | CHFL_CHANOP;
		  do {
		    level_increment = 10 * level_increment + (*ptr++ - '0');
		    if (level_increment > MAXOPLEVEL) {
		      /* Stop before the accumulator overflows int and wraps
		       * negative: a negative oplevel printed with "%u" in the
		       * relay is ten digits and overruns its buffer.  Pin it
		       * just past the limit so the clamp below always fires. */
		      while (IsDigit(*ptr))
			ptr++;
		      level_increment = MAXOPLEVEL + 1;
		      break;
		    }
		  } while (IsDigit(*ptr));
		  --ptr;
		  oplevel += level_increment;
                  if (oplevel > MAXOPLEVEL) {
                    protocol_violation(sptr, "Invalid cumulative oplevel %u during burst", oplevel);
                    oplevel = MAXOPLEVEL;
                    break;
                  }
		}
		else { /* I don't recognize that flag */
		  protocol_violation(sptr, "Invalid flag '%c' in nick part of burst", *ptr);
		  break; /* so stop processing */
		}
	      }

	      /* A hidden member never has status, so ':od', ':dv' and ':3d'
	       * all mean the status without the 'd'. */
	      if (current_mode & CHFL_VOICED_OR_OPPED)
		current_mode &= ~(CHFL_DELAYED | CHFL_DELAYED_TARGET);
	    }
	  }

	  if (!(acptr = findNUser(nick)) || cli_from(acptr) != cptr)
	    continue; /* ignore this client */

	  /* Record what we accepted, for burst_relay() to encode later. */
	  if (nrmembers < BURST_RELAY_MEMBERS) {
	    rmembers[nrmembers].user = acptr;
	    rmembers[nrmembers].mode = current_mode;
	    rmembers[nrmembers].oplevel = oplevel;
	    nrmembers++;
	  } else if (!rmembers_full) {
	    /* Unreachable for a BUFSIZE line, see BURST_RELAY_MEMBERS.  Say
	     * so once only: protocol_violation() wallops the whole network,
	     * so one per member would be a flood of its own. */
	    rmembers_full = 1;
	    protocol_violation(sptr, "Too many members in one BURST line");
	  }

	  if (!(member = find_member_link(chptr, acptr)))
	  {
	    add_user_to_channel(chptr, acptr, current_mode, oplevel);
	    /* A hidden member on a channel that is not +D still needs the
	     * local "has hidden members" flag, so that it is cleared as
	     * usual when the last of them speaks or leaves.  The flag is
	     * local and silent: no modebuf entry. */
	    if ((current_mode & CHFL_DELAYED) && !(chptr->mode.mode & MODE_DELJOINS))
	      chptr->mode.mode |= MODE_WASDELJOINS;
	    if (!(current_mode & CHFL_DELAYED)) {
	      sendjointo_channel_butserv(acptr, chptr, 0, 0);
              if (cli_user(acptr)->away)
                sendcmdto_capflag_channel_butserv_butone(acptr, CMD_AWAY, chptr,
                  NULL, 0, CAP_AWAYNOTIFY, 0, ":%s", cli_user(acptr)->away);
              }
	  }
	  else
	  {
	    /* The member was already joined (either by CREATE or JOIN).
	       Remember the current mode. */
	    if (member->status & CHFL_CHANOP)
	      member->status |= CHFL_BURST_ALREADY_OPPED;
	    if (member->status & CHFL_VOICE)
	      member->status |= CHFL_BURST_ALREADY_VOICED;
	    /* A hidden member never has status, so reveal it before granting
	     * any, as mode_process_clients() does.  Otherwise the member
	     * carries both and every encoder that groups by status has to
	     * guess which group it belongs to.  A zombie (kicked behind us but
	     * still listed by a peer that has not seen the KICK) is never
	     * revealed: that would send a JOIN for a gone user to local
	     * clients.  Clear the delayed-target flag too, for parity with
	     * mode_process_clients(). */
	    if ((current_mode & (CHFL_CHANOP | CHFL_VOICE))
		&& IsDelayedJoin(member) && !IsZombie(member))
	      RevealDelayedJoin(member);
	    if (current_mode & (CHFL_CHANOP | CHFL_VOICE))
	      ClearDelayedTarget(member);
	    /* Synchronize with the burst. */
	    member->status |= CHFL_BURST_JOINED | (current_mode & (CHFL_CHANOP|CHFL_VOICE));
	    SetOpLevel(member, oplevel);
	  }
	}
      }
      param++;
      break;
    } /* switch (*parv[param]) */
  } /* while (param < parc) */

  if (parse_flags & MODE_PARSE_SET) {
    modebuf_extract(mbuf, modestr + 1); /* for sending BURST onward */
    modestr[0] = modestr[1] ? ' ' : '\0';
  } else
    modestr[0] = '\0';

  /* Relay each layout to the downlinks that speak it; the two calls
   * partition the downlinks at protocol 11.  The recorded bans hold their
   * own copies of the mask and setter (see struct BurstRelayBan), so the
   * relay is unaffected by the ban loop below freeing entries. */
  burst_relay(sptr, cptr, chptr, modestr, rmembers, nrmembers,
	      rbans, nrbans, 11, 0, 1);
  burst_relay(sptr, cptr, chptr, modestr, rmembers, nrmembers,
	      rbans, nrbans, 0, 11, 0);

  if (parse_flags & MODE_PARSE_WIPEOUT || new_bans)
    mode_ban_invalidate(chptr);

  if (parse_flags & MODE_PARSE_SET) { /* any modes changed? */
    /* first deal with channel members */
    for (member = chptr->members; member; member = member->next_member) {
      if (member->status & CHFL_BURST_JOINED) { /* joined during burst */
	if ((member->status & CHFL_CHANOP) && !(member->status & CHFL_BURST_ALREADY_OPPED))
	  modebuf_mode_client(mbuf, MODE_ADD | CHFL_CHANOP, member->user, OpLevel(member));
	if ((member->status & CHFL_VOICE) && !(member->status & CHFL_BURST_ALREADY_VOICED))
	  modebuf_mode_client(mbuf, MODE_ADD | CHFL_VOICE, member->user, OpLevel(member));
      } else if (parse_flags & MODE_PARSE_WIPEOUT) { /* wipeout old ops */
	if (member->status & CHFL_CHANOP)
	  modebuf_mode_client(mbuf, MODE_DEL | CHFL_CHANOP, member->user, OpLevel(member));
	if (member->status & CHFL_VOICE)
	  modebuf_mode_client(mbuf, MODE_DEL | CHFL_VOICE, member->user, OpLevel(member));
	member->status = (member->status
                          & ~(CHFL_CHANNEL_MANAGER | CHFL_CHANOP | CHFL_VOICE))
			 | CHFL_DEOPPED;
      }
    }

    /* Now deal with channel bans */
    lp_p = &chptr->banlist;
    while (*lp_p) {
      lp = *lp_p;

      /* remove ban from channel */
      if (lp->flags & (BAN_OVERLAPPED | BAN_BURST_WIPEOUT)) {
        char *bandup;
        DupString(bandup, lp->banstr);
	modebuf_mode_string(mbuf, MODE_DEL | MODE_BAN,
			    bandup, 1);
	*lp_p = lp->next; /* clip out of list */
        free_ban(lp);
	continue;
      } else if (lp->flags & BAN_BURSTED) /* add ban to channel */
	modebuf_mode_string(mbuf, MODE_ADD | MODE_BAN,
			    lp->banstr, 0); /* don't free banstr */

      lp->flags &= BAN_IPMASK; /* reset the flag */
      lp_p = &(*lp_p)->next;
    }
  }

  return mbuf ? modebuf_flush(mbuf) : 0;
}
