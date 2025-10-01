/*
 * IRC - Internet Relay Chat, ircd/m_sasl.c
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
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "sasl.h"
#include "send.h"

#include <stdlib.h>

int m_sasl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  static uint64_t routing_ticker = 0;

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "AUTHENTICATE");

  if (!CapHas(cli_active(cptr), CAP_SASL))
    return 0;

  if (HasFlag(sptr, FLAG_SASL) || HasFlag(sptr, FLAG_ACCOUNT))
    return send_reply(cptr, ERR_SASLALREADY);

  acptr = find_match_server((char*)sasl_get_server());
  if (!sasl_available() || !acptr)
    return send_reply(cptr, ERR_SASLFAIL, "The login server is currently disconnected.  Please excuse the inconvenience.");

  if (strlen(parv[1]) > 400)
    return send_reply(cptr, ERR_SASLTOOLONG);
 
  if (strcmp(parv[1], "*") == 0) {
    send_reply(cptr, ERR_SASLABORTED);
    cli_sasl(cptr) = 0;
    return 0;
  }

  /* Is this the initial authentication challenge? */
  if (!cli_sasl(cptr)) {
    if (!sasl_mechanism_supported(parv[1]))
      return send_reply(cptr, RPL_SASLMECHS, sasl_get_mechanisms());

    cli_sasl(cptr) = ++routing_ticker;

    /* Is the user already registered? We then send the NumNick. */
    if (IsUser(cptr)) {
      sendcmdto_one(&me, CMD_XQUERY, acptr, "%C sasl:%lu :SASL %s%s %s",
                    acptr, cli_sasl(cptr), NumNick(cptr), parv[1]);
    } else {
      /* If not, we pass on the IP and fingerprint. */
      sendcmdto_one(&me, CMD_XQUERY, acptr, "%C sasl:%lu :SASL %s %s %s",
                    acptr, cli_sasl(cptr), ircd_ntoa(&cli_ip(cptr)),
                    /*cli_fingerprint(cptr) ? cli_fingerprint(cptr) : */"_",
                    parv[1]);
    }
  } else {
    sendcmdto_one(&me, CMD_XQUERY, acptr, "%C sasl:%lu :SASL %s",
                  acptr, cli_sasl(cptr), parv[1]);
  }

  return 0;
}

/** Handler for configuring the SASL authentication layer on the network
 * @param[in] cptr Local client that sent us the message
 * @param[in] sptr Original source of the message  
 * @param[in] parc Number of parameters
 * @param[in] parv Parameter vector
 * @return 0 on success
 */
int ms_sasl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  time_t timestamp;
  struct Client* acptr;
  
  if (parc < 2)
    return need_more_params(sptr, "AU");

  /* Check if this is a configuration message */
  if (parv[1][0] == '=') {
    /* Format: AU = <timestamp> <server> <mechanisms> */
    if (parc < 5)
      return need_more_params(sptr, "AU");

    timestamp = atoi(parv[2]);  
    if (timestamp > sasl_get_timestamp() || !sasl_get_server()) {
      const char* old_server = sasl_get_server();
      const char* old_mechanisms = sasl_get_mechanisms();
      
      sasl_update_configuration(timestamp, parv[3], parv[4]);
      sendcmdto_serv_butone(sptr, CMD_AUTHENTICATE, cptr, "= %s %s %s", 
                            parv[2], parv[3], parv[4]);
      
      /* Only send opmask if there was actually a change */
      if (!old_server || !old_mechanisms || 
          ircd_strcmp(old_server, parv[3]) != 0 || 
          ircd_strcmp(old_mechanisms, parv[4]) != 0) {
        sendto_opmask_butone(0, SNO_NETWORK,
                "SASL authentication layer is %s accepting %s",
                parv[3], parv[4]);
      }
    }
  }
  
  return 0;
}