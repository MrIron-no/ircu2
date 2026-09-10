/*
 * IRC - Internet Relay Chat, ircd/hotreload.c
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
 * @brief Orchestration of a hot reload.
 */
#include "config.h"

#include "hotreload.h"

/** Descriptor holding the state dump we were execed with; -1 unless booted with -R. */
int hotreload_fd = -1;
/** Non-zero when booted with -K, to check a dump instead of serving it. */
int hotreload_check = 0;

/** Dump state and exec this server in place, keeping connections open.
 * @param[in] reason Human readable reason for the reload, for the logs.
 */
void server_reload(const char *reason)
{
  (void)reason;
}

/** Write a state dump to a file, for debugging.
 * @param[in] path File to write the dump to.
 * @return Non-zero on success, zero on failure.
 */
int hotreload_dump_to_path(const char *path)
{
  (void)path;
  return 0;
}
