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
 */
#include "config.h"

#include "hotreload.h"

/** Read a state dump from \a fd.
 * @param[in] fd Descriptor holding the dump.
 * @return Non-zero on success; zero means the caller must cold boot.
 */
int hotreload_read(int fd)
{
  (void)fd;
  return 0;
}

/** Test whether a dump has been read but not yet applied.
 * @return Non-zero while a read dump awaits hotreload_apply().
 */
int hotreload_pending(void)
{
  return 0;
}

/** Claim the inherited listening socket for an address.
 * @param[in] family Address family of the listener.
 * @param[in] addr Address the listener is bound to.
 * @param[in] port Port the listener is bound to.
 * @return Inherited descriptor, or -1 when there is none.
 */
int hotreload_claim_listener(int family, const struct irc_in_addr *addr, int port)
{
  (void)family;
  (void)addr;
  (void)port;
  return -1;
}

/** Apply the dump that was read.
 * @param[in] check_only If non-zero, only check that the dump could be applied.
 * @return Non-zero on success, zero on failure.
 */
int hotreload_apply(int check_only)
{
  (void)check_only;
  return 0;
}
