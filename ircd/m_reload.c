/*
 * IRC - Internet Relay Chat, ircd/m_reload.c
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

#include "client.h"
#include "hotreload.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_misc.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <string.h>

/*
 * mo_reload - oper message handler
 *
 * parv[1] = "DUMP" (optional)
 * parv[2] = file name to dump the state to, when parv[1] is "DUMP"
 *
 * RELOAD alone needs PRIV_RESTART.  RELOAD DUMP needs PRIV_RESTART *and*
 * PRIV_DIE, because a state dump is not a lesser operation than a reload: the
 * file it writes holds every local user's nick, host, address, account,
 * operator privileges, silence list and queued output, so the right to ask
 * for one is the right to read the whole server's state off the disk.  The
 * name is a plain file name below RELOAD_DUMP_DIR (see
 * hotreload_dump_to_path()); the request is logged and noticed to opers
 * whether or not it succeeds at writing anything.
 *
 * Failures answer with a fixed string.  The one exception is the name check,
 * which the oper can act on and which reveals nothing about the filesystem;
 * every other reason (a name that already exists, a symlink in the way, a
 * directory that is not writable, an unreadable RELOAD_DUMP_DIR) is a probe
 * of the server's filesystem if it is reported back, so it goes to the log
 * and not to the client.
 */
int mo_reload(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (!HasPriv(sptr, PRIV_RESTART))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2) {
    log_write(LS_SYSTEM, L_NOTICE, 0, "Server RELOAD by %#C", sptr);
    /* A reload that aborts comes back here, and it may have shed this very
     * connection on the way (a TLS session the dump cannot carry).  When it
     * says so, cptr is already freed and only CPTR_KILLED is safe. */
    if (server_reload("received RELOAD", cptr))
      return CPTR_KILLED;
    return 0;
  }

  if (parc >= 3 && ircd_strcmp(parv[1], "DUMP") == 0) {
    if (!HasPriv(sptr, PRIV_DIE))
      return send_reply(sptr, ERR_NOPRIVILEGES);

    log_write(LS_SYSTEM, L_NOTICE, 0, "State dump to %s requested by %#C",
              parv[2], sptr);
    sendto_opmask_butone(0, SNO_OLDSNO, "%C requested a state dump to %s",
                         sptr, parv[2]);

    if (hotreload_dump_to_path(parv[2]))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :State dumped to %s", sptr,
                    parv[2]);
    else {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Dump failed", sptr);
      /* Only the name check earns a reason: it is the oper's own mistake and
       * it says nothing about what is on the disk. */
      if (EINVAL == errno)
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Dump failed: file name must "
                      "be a plain file name (no '/')", sptr);
    }
    return 0;
  }

  return send_reply(sptr, ERR_NEEDMOREPARAMS, "RELOAD");
}
