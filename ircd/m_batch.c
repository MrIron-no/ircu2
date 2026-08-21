/*
 * IRC - Internet Relay Chat, ircd/m_batch.c
 * Copyright (C) 2026 UndernetIRC
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
 * @brief Server-to-server relay for IRCv3 labeled-response BATCH/ACK.
 *
 * BATCH and ACK are otherwise purely client-facing (see send.c's
 * label_capture_* family): a server answering a hunt_server_cmd()-routed
 * request on behalf of a *remote* client (see parse_server()'s
 * labeled-response wrapper) emits its own BATCH/ACK addressed to that
 * client by numnick -- ":<server> BA <target-numnick> +ref type" /
 * "-ref", ":<server> AK <target-numnick>" -- rather than the plain,
 * unaddressed client-facing form (which relies on there being exactly
 * one recipient: the socket it's written to).
 *
 * This file is the relay for that addressed form as it crosses however
 * many further hops separate the answering server from the original
 * requester: same pattern as do_numeric() in s_numeric.c (resolve the
 * target, then either deliver it locally in plain client-facing form, or
 * re-address it one more hop closer). @label=/@batch= tags on the
 * inbound line are preserved for free -- sendcmdto_one() picks up
 * whatever parse_server() already parsed into the current line's tags,
 * exactly like do_numeric()'s numeric relay already does.
 */
#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"

/** Relay an S2S-addressed BATCH open/close to its target.
 * @param[in] cptr Neighbor that sent us this line.
 * @param[in] sptr Server that generated it (the one actually answering
 *                 the labeled request, or a relay in between).
 * @param[in] parc Number of valid parameters.
 * @param[in] parv Parameters: parv[1] is the target numnick, the rest
 *                 (parv[2..]) is the BATCH ref/type payload verbatim.
 */
int ms_batch(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  struct Client *emitfrom;
  char rest[BUFSIZE];
  size_t len = 0;
  int i;

  if (parc < 3)
    return protocol_violation(cptr, "BATCH with too few parameters");

  if (!(acptr = findNUser(parv[1])))
    return 0; /* target already gone: drop silently, like do_numeric() */

  rest[0] = '\0';
  for (i = 2; i < parc && parv[i] && len < sizeof(rest) - 1; i++) {
    if (len)
      rest[len++] = ' ';
    len += ircd_snprintf(0, rest + len, sizeof(rest) - len, "%s", parv[i]);
  }

  emitfrom = (feature_bool(FEAT_HIS_REWRITE) && !IsOper(acptr)) ? &me : sptr;

  if (MyConnect(acptr))
    sendcmdto_one(emitfrom, CMD_BATCH, acptr, "%s", rest);
  else
    sendcmdto_one(emitfrom, CMD_BATCH, acptr, "%C %s", acptr, rest);

  return 0;
}

/** Relay an S2S-addressed labeled-response ACK to its target.
 * @param[in] cptr Neighbor that sent us this line.
 * @param[in] sptr Server that generated it.
 * @param[in] parc Number of valid parameters.
 * @param[in] parv Parameters: parv[1] is the target numnick.
 */
int ms_ack(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  struct Client *emitfrom;

  if (parc < 2)
    return protocol_violation(cptr, "ACK with no target");

  if (!(acptr = findNUser(parv[1])))
    return 0;

  emitfrom = (feature_bool(FEAT_HIS_REWRITE) && !IsOper(acptr)) ? &me : sptr;

  if (MyConnect(acptr))
    sendcmdto_one(emitfrom, CMD_ACK, acptr, "");
  else
    sendcmdto_one(emitfrom, CMD_ACK, acptr, "%C", acptr);

  return 0;
}
