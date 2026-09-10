/*
 * IRC - Internet Relay Chat, ircd/hotreload_wire.c
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
 * @brief Record wire format for hot reload state dumps.
 */
#include "config.h"

#include "hotreload.h"

/** Start writing a record of the given type.
 * @param[in] out Stream to write to.
 * @param[in] type Record type.
 */
void hr_rec_begin(FILE *out, const char *type)
{
  (void)out;
  (void)type;
}

/** Append a string valued key to the record being written.
 * @param[in] out Stream to write to.
 * @param[in] key Key name.
 * @param[in] value Value for \a key.
 */
void hr_rec_add(FILE *out, const char *key, const char *value)
{
  (void)out;
  (void)key;
  (void)value;
}

/** Append an integer valued key to the record being written.
 * @param[in] out Stream to write to.
 * @param[in] key Key name.
 * @param[in] value Value for \a key.
 */
void hr_rec_add_int(FILE *out, const char *key, long long value)
{
  (void)out;
  (void)key;
  (void)value;
}

/** Append a key whose value is base64 encoded binary data.
 * @param[in] out Stream to write to.
 * @param[in] key Key name.
 * @param[in] data Data to encode.
 * @param[in] len Length of \a data in bytes.
 */
void hr_rec_add_b64(FILE *out, const char *key, const void *data, size_t len)
{
  (void)out;
  (void)key;
  (void)data;
  (void)len;
}

/** Finish the record being written.
 * @param[in] out Stream to write to.
 */
void hr_rec_end(FILE *out)
{
  (void)out;
}

/** Parse one dump line in place.
 * @param[in,out] line Line to parse; it is modified in place.
 * @param[out] rec Receives the parsed record.
 * @return Non-zero if the line was well formed, zero if malformed.
 */
int hr_parse_line(char *line, struct hr_record *rec)
{
  (void)line;
  (void)rec;
  return 0;
}

/** Look up a key in a parsed record.
 * @param[in] rec Record to search.
 * @param[in] key Key to look for.
 * @return Value for \a key, or NULL when the key is absent.
 */
const char *hr_get(const struct hr_record *rec, const char *key)
{
  (void)rec;
  (void)key;
  return NULL;
}

/** Look up an integer valued key in a parsed record.
 * @param[in] rec Record to search.
 * @param[in] key Key to look for.
 * @param[in] dflt Value to return when \a key is absent or unparsable.
 * @return Value for \a key, or \a dflt.
 */
long long hr_get_int(const struct hr_record *rec, const char *key, long long dflt)
{
  (void)rec;
  (void)key;
  return dflt;
}

/** Decode base64 data.
 * @param[in] src NUL terminated base64 text.
 * @param[out] dst Buffer for the decoded data.
 * @param[in] dstlen Size of \a dst in bytes.
 * @return Number of bytes written, or (size_t)-1 on error.
 */
size_t hr_b64_decode(const char *src, unsigned char *dst, size_t dstlen)
{
  (void)src;
  (void)dst;
  (void)dstlen;
  return (size_t)-1;
}

/** Read a whole dump and split it into lines.
 * @param[in] fd Descriptor to read to end of file.
 * @param[out] out Receives the lines read.
 * @return Non-zero on success, zero on failure.
 */
int hr_read_all(int fd, struct hr_lines *out)
{
  (void)fd;
  (void)out;
  return 0;
}

/** Release the storage held by hr_read_all().
 * @param[in,out] lines Lines to release.
 */
void hr_free_lines(struct hr_lines *lines)
{
  (void)lines;
}

/** Close every descriptor up to \a maxfd except those listed.
 * @param[in] keep Descriptors to leave open.
 * @param[in] nkeep Number of entries in \a keep.
 * @param[in] maxfd Highest descriptor to consider.
 */
void hr_close_all_except(const int *keep, unsigned int nkeep, int maxfd)
{
  (void)keep;
  (void)nkeep;
  (void)maxfd;
}
