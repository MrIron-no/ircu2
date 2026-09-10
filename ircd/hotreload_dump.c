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
 */
#include "config.h"

#include "hotreload.h"

/** Write the whole of the server state to \a out.
 * @param[in] out Stream to write the dump to.
 * @return Non-zero on success, zero on write error.
 */
int hotreload_dump(FILE *out)
{
  (void)out;
  return 0;
}
