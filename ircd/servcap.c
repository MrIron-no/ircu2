/*
 * IRC - Internet Relay Chat, ircd/servcap.c
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
 * @brief P11 link capability table, announcement and negotiation.
 * @version $Id$
 */
#include "config.h"

#include "servcap.h"

#include <string.h>

/** Capabilities this server understands.
 *
 * Empty as of u2.11.0: the exchange itself ships first so that the first
 * real capability can be added without a protocol bump.  Keep entries
 * lowercase and the terminator last.
 */
const struct ServCapEntry servcap_table[] = {
  { 0, 0, 0 }
};

/** Return non-zero if \a c may appear in a capability name. */
static int
servcap_name_char(char c)
{
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
      || c == '-' || c == '/';
}

/** Find the table entry for the name of length \a len at \a name.
 * @param[in] name Start of the name (not NUL-terminated at \a len).
 * @param[in] len Length of the name.
 * @param[in] table Capability table, terminated by a NULL name.
 * @return The matching entry, or NULL.
 */
static const struct ServCapEntry *
servcap_find(const char *name, size_t len, const struct ServCapEntry *table)
{
  const struct ServCapEntry *e;

  for (e = table; e->name; ++e)
    if (strlen(e->name) == len && 0 == memcmp(e->name, name, len))
      return e;
  return 0;
}

/** Build the capability list this server announces on a P11 link.
 * @param[out] buf Output buffer.
 * @param[in] len Size of \a buf.
 * @return Number of characters written, excluding the NUL.
 */
size_t
servcap_announce(char *buf, size_t len)
{
  const struct ServCapEntry *e;
  size_t pos = 0;

  if (len == 0)
    return 0;
  buf[0] = '\0';
  for (e = servcap_table; e->name; ++e) {
    size_t nlen = strlen(e->name);

    if (pos + nlen + (pos ? 1 : 0) + 1 > len)
      break;
    if (pos)
      buf[pos++] = ' ';
    memcpy(buf + pos, e->name, nlen);
    pos += nlen;
    buf[pos] = '\0';
  }
  return pos;
}

/** Intersect a peer's announced capability list with \a table.
 *
 * See servcap.h for the exact acceptance rules.
 * @param[in] list The trailing parameter of the peer's CAP line; may be NULL.
 * @param[in] table Capability table, terminated by a NULL name.
 * @return The bits of every capability both sides understand.
 */
servcap_t
servcap_parse(const char *list, const struct ServCapEntry *table)
{
  servcap_t caps = 0;
  servcap_t seen = 0;
  const char *p = list;

  if (!p)
    return 0;

  while (*p) {
    const char *tok;
    const char *eq = 0;
    const char *end;
    size_t nlen;
    size_t i;
    int valid = 1;
    const struct ServCapEntry *e;

    while (*p == ' ')
      ++p;
    if (!*p)
      break;
    tok = p;
    while (*p && *p != ' ') {
      if (*p == '=' && !eq)
        eq = p;
      ++p;
    }
    end = p;

    nlen = (eq ? eq : end) - tok;
    if (nlen == 0 || nlen > SERVCAP_NAME_MAX)
      valid = 0;
    for (i = 0; valid && i < nlen; ++i)
      if (!servcap_name_char(tok[i]))
        valid = 0;
    if (!valid)
      continue;

    if (!(e = servcap_find(tok, nlen, table)))
      continue;
    if (seen & e->bit)                  /* first occurrence decides */
      continue;
    seen |= e->bit;

    if (!e->parse_value) {
      if (!eq)
        caps |= e->bit;
    } else if (eq) {
      /* Copy the value out so the parser sees a NUL-terminated string. */
      char value[512];
      size_t vlen = end - (eq + 1);

      if (vlen >= sizeof(value))
        vlen = sizeof(value) - 1;
      memcpy(value, eq + 1, vlen);
      value[vlen] = '\0';
      if (e->parse_value(value))
        caps |= e->bit;
    }
  }
  return caps;
}

/** Render the names of the capabilities in \a caps, space separated.
 * @param[in] caps Capability bits.
 * @param[out] buf Output buffer; receives "" when no bit is set.
 * @param[in] len Size of \a buf.
 * @param[in] table Capability table, terminated by a NULL name.
 * @return Number of characters written, excluding the NUL.
 */
size_t
servcap_names(servcap_t caps, char *buf, size_t len,
              const struct ServCapEntry *table)
{
  const struct ServCapEntry *e;
  size_t pos = 0;

  if (len == 0)
    return 0;
  buf[0] = '\0';
  for (e = table; e->name; ++e) {
    size_t nlen;

    if (!(caps & e->bit))
      continue;
    nlen = strlen(e->name);
    if (pos + nlen + (pos ? 1 : 0) + 1 > len)
      break;
    if (pos)
      buf[pos++] = ' ';
    memcpy(buf + pos, e->name, nlen);
    pos += nlen;
    buf[pos] = '\0';
  }
  return pos;
}
