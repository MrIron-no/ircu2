#ifndef INCLUDED_servcap_h
#define INCLUDED_servcap_h
/*
 * IRC - Internet Relay Chat, include/servcap.h
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
 * @brief P11 server-to-server link capabilities (doc/P11.md, "Link
 * capabilities").
 *
 * On a P11 link each side sends exactly one unprefixed line
 *
 *     CAP :<cap> [<cap> ...]
 *
 * immediately after SERVER and before its burst.  The link's capability
 * set is the intersection of the two announcements, fixed for the life of
 * the link and never relayed.  A capability is for optional or transitional
 * features; the protocol version remains the mandatory baseline bundle.
 *
 * Parse rules (servcap_parse()):
 *  - Tokens are separated by one or more spaces; leading and trailing
 *    spaces are ignored.  A NULL or empty list yields no capabilities.
 *  - A token is split at its first '=' into a name and a value.
 *  - A name is valid iff it is 1..SERVCAP_NAME_MAX characters, each one of
 *    a-z, 0-9, '-' or '/'.  Invalid or unknown names are ignored.
 *  - An entry whose parse_value is NULL accepts only the bare name; a
 *    token carrying '=' does not set it.  An entry with parse_value set
 *    requires '=' and sets the bit only if parse_value(value) returns
 *    non-zero (a value the receiver does not understand means "absent").
 *  - The first occurrence of a name decides; later duplicates are ignored.
 */
#include <stddef.h>

struct Client;

/** One bit per negotiated capability. */
typedef unsigned int servcap_t;

/** Longest valid capability name. */
#define SERVCAP_NAME_MAX 63

/** Describes one capability the local server understands. */
struct ServCapEntry {
  const char *name;                     /**< lowercase [a-z0-9/-], <= 63 chars */
  servcap_t   bit;                      /**< bit set in struct Server::caps */
  int (*parse_value)(const char *value);/**< NULL: bare name only; else 1 if understood */
};

/** Capabilities this server understands; terminated by name == NULL. */
extern const struct ServCapEntry servcap_table[];

extern size_t servcap_announce(char *buf, size_t len);
extern servcap_t servcap_parse(const char *list, const struct ServCapEntry *table);
extern size_t servcap_names(servcap_t caps, char *buf, size_t len,
                            const struct ServCapEntry *table);

/** Return non-zero if the link to \a cptr negotiated capability \a cap. */
#define HasServCap(cptr, cap) ((cli_serv(cptr)->caps & (cap)) != 0)

#endif /* INCLUDED_servcap_h */
