/*
 * IRC - Internet Relay Chat, ircd/m_sline.c
 * Copyright (C) 2025 MrIron <mriron@undernet.org>
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

#include "client.h"
#include "sline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/*
 * ms_sline - server message handler
 *
 * SLINE_ACTIVATE or SLINE_BURST:
 * * parv[0] = Sender prefix
 * * parv[1] = (* or +) (burst or activate)
 * * parv[2] = last modified timestamp
 * * parv[3] = type (A/P/C/L/Q)
 * * parv[4] = pattern
 *
 * SLINE_DEACTIVATE:
 * * parv[0] = Sender prefix
 * * parv[1] = - (deactivate)
 * * parv[2] = pattern
 * 
 * SLINE_ACTIVATE and SLINE_DECTIVATE is only accepted from U:lined servers (IsSpamfilter()).
 * SLINE_BURST is only accepted from a server currently bursting.
 * 
 */
int
ms_sline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Sline *asline = 0;
  unsigned int flags = 0, action = 0;
  time_t lastmod = 0;
  char *action_str = parv[1], *pattern = NULL, *type = NULL;

  Debug((DEBUG_DEBUG, "ms_sline called: parc=%d, action_str=%s", 
         parc, action_str ? action_str : "NULL"));

  if (parc < 3)
    return need_more_params(sptr, "SLINE");

  /* Parse action (+, -, or *) */
  switch (*action_str) {
    case '+':
      /* Adding S-line */
      if (parc < 5)
        return need_more_params(sptr, "SLINE");
      action = SLINE_ACTIVATE; /* Normal add */
      pattern = parv[4];
      type = parv[3];
      break;
    case '-':
      /* Removing S-line */
      if (parc < 3)
        return need_more_params(sptr, "SLINE");
      action = SLINE_DEACTIVATE; /* Remove */
      pattern = parv[2]; /* For removal, pattern is in parv[2] */
      break;
    case '*':
      /* Burst mode - adding S-line during burst */
      if (parc < 5)
        return need_more_params(sptr, "SLINE");
      action = SLINE_BURST; /* Burst add */
      pattern = parv[4];
      type = parv[3];
      break;
    default:
      return protocol_violation(sptr, "Invalid SLINE action '%c', expected '+', '-', or '*'", *action_str);
  }

  Debug((DEBUG_DEBUG, "ms_sline: pattern=%s, type=%s", 
         pattern ? pattern : "NULL", type ? type : "NULL"));

  /* Is the server bursting? */
  if (action == SLINE_BURST && !IsBurst(sptr)) {
    Debug((DEBUG_DEBUG, "ms_sline: Not in burst mode, denying SLINE burst"));
    return send_reply(sptr, ERR_NOPRIVILEGES, parv[1]);
  }

  /* We only accept SLINE_ACTIVATE and SLINE_DEACTIVATE from U:lined servers (IsSpamfilter()). */
  if ((action == SLINE_ACTIVATE || action == SLINE_DEACTIVATE) 
      && (!IsSpamfilter(sptr))) {
    Debug((DEBUG_DEBUG, "ms_sline: No U:lined server, denying SLINE command"));
    return send_reply(sptr, ERR_NOPRIVILEGES, parv[1]);
  }

  /* Check if the pattern is valid */
  if (!pattern || strlen(pattern) == 0)
    return protocol_violation(sptr, "Invalid SLINE pattern: cannot be empty");
    
  /* Parse timestamps - only for add/burst operations */
  if (action == SLINE_ACTIVATE || action == SLINE_BURST) {
    lastmod = atoi(parv[2]) == 0 ? TStime() : atoi(parv[2]);
 
    /* Parse type flags */
    for (int i = 0; type[i] != '\0'; i++) {
      if (type[i] == 'A') {
        flags |= SLINE_ALL;
        break; /* A overrides everything */
      } else if (type[i] == 'P') {
        flags |= SLINE_PRIVATE;
      } else if (type[i] == 'C') {
        flags |= SLINE_CHANNEL;
      } else if (type[i] == 'L') {
        flags |= SLINE_PART;
      } else if (type[i] == 'Q') {
        flags |= SLINE_QUIT;
      } else {
        // If we are adding other types later, we could perhaps propagate unknown types but avoid adding them ourself.
        return protocol_violation(sptr, "Invalid SLINE type '%c', expected 'A', 'P', 'C', 'L', or 'Q'", type[i]);
      }
    }
  }

  /* Build flag string for propagation (only for add/burst operations) */
  if (action == SLINE_ACTIVATE || action == SLINE_BURST) {
    Debug((DEBUG_DEBUG, "Processing activation of S-line (%s): pattern=%s, type=%s, mode=%c",
            action == SLINE_ACTIVATE ? "ACTIVATE" : "BURST",
            pattern ? pattern : "NULL",
            sline_flags_to_string(flags), *action_str));

    /* Check if S-line already exists with the exact same pattern */
    asline = sline_find(pattern);
    if (asline) {
      /* Check whether the flags match. If they do, we ignore. */
      if (asline->sl_msgtype == flags) {
        Debug((DEBUG_DEBUG, "S-line already exists with same pattern and flags, ignoring"));
        return 0;
      }

      /* Check whether the timestamp is older than the existing S-line. If it is, we ignore. */
      if (asline->sl_lastmod >= lastmod) {
        Debug((DEBUG_DEBUG, "S-line already exists with newer or equal timestamp, ignoring"));
        return 0;
      }

      /* Update S:line. The pattern cannot be changed. */
      asline->sl_lastmod = lastmod;
      asline->sl_msgtype = flags;
        
      sendto_opmask_butone(0, SNO_GLINE, "%C updating global SLINE for pattern \"%s\" (%s)",
                            sptr, pattern,
                            sline_flags_to_string(flags));

      log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
                "%#C updating global SLINE for pattern \"%s\" (%s)", sptr,
                pattern,
                sline_flags_to_string(flags));

      Debug((DEBUG_DEBUG, "Updated flags for existing S-line with same pattern and flags"));
    } else {
      sline_add(cptr, sptr, pattern, lastmod, flags);
    }

    sendcmdto_serv_butone(sptr, CMD_SLINE, cptr, "%c %Tu %s :%s",
      *action_str, lastmod, sline_flags_to_string(flags), pattern);
    
  } else if (action == SLINE_DEACTIVATE) {
      Debug((DEBUG_DEBUG, "Processing removal of S-line with pattern=%s", pattern));

      /* Find the S-line to remove */
      asline = sline_find(pattern);
      if (!asline) {
        Debug((DEBUG_DEBUG, "S-line not found"));
        return 0;
      }

      sline_remove(cptr, sptr, asline);

      sendcmdto_serv_butone(sptr, CMD_SLINE, cptr, "%c :%s",
        *action_str, pattern);
  }

  return 1;
} 