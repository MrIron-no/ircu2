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
 *
 * A dump is a sequence of lines of the form
 *
 * @code
 * TYPE key=value key=value ...\n
 * @endcode
 *
 * where the type matches [A-Z][A-Z0-9_]*, keys match [A-Za-z0-9_]+ and
 * values are escaped so that a value can never contain the space that
 * separates the tokens nor the newline that ends the line: a backslash is
 * written as "\\", a space as "\s", a newline as "\n" and a carriage return
 * as "\r".  Every other byte, '=' included, goes out verbatim; binary data
 * is carried base64 encoded by hr_rec_add_b64().  Values have no length
 * limit -- the writer streams straight to the stream and the reader grows
 * its buffers -- so a record may be far longer than any IRC message.
 */
#include "config.h"

#include "hotreload.h"
#include "ircd_alloc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** Maximum number of key/value pairs in one record (size of hr_record::keys). */
#define HR_MAX_KEYS 64

/** Initial size of the read buffer used by hr_read_all(). */
#define HR_READ_CHUNK (64 * 1024)

/** The RFC 4648 base64 alphabet. */
static const char hr_b64_alphabet[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Value of one base64 digit.
 * @param[in] c Character to decode.
 * @return Value in 0..63, or -1 if \a c is not a base64 digit.
 */
static int hr_b64_value(unsigned char c)
{
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

/** Test whether \a s is a well formed record type ([A-Z][A-Z0-9_]*).
 * @param[in] s Candidate type.
 * @return Non-zero if \a s is a valid type.
 */
static int hr_valid_type(const char *s)
{
  if (!(*s >= 'A' && *s <= 'Z'))
    return 0;
  for (s++; *s; s++)
    if (!((*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '_'))
      return 0;
  return 1;
}

/** Test whether \a s is a well formed key ([A-Za-z0-9_]+).
 * @param[in] s Candidate key.
 * @return Non-zero if \a s is a valid key.
 */
static int hr_valid_key(const char *s)
{
  if (!*s)
    return 0;
  for (; *s; s++)
    if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
          (*s >= '0' && *s <= '9') || *s == '_'))
      return 0;
  return 1;
}

/** Collapse the escapes in \a s in place.
 *
 * Escapes only ever shrink the text, so the write cursor stays behind the
 * read cursor and no copy is needed.
 *
 * @param[in,out] s Value to unescape.
 * @return Non-zero on success, zero if \a s holds an unknown escape.
 */
static int hr_unescape(char *s)
{
  char *src = s;
  char *dst = s;

  while (*src) {
    if (*src != '\\') {
      *dst++ = *src++;
      continue;
    }
    switch (*++src) {
    case '\\': *dst++ = '\\'; break;
    case 's':  *dst++ = ' ';  break;
    case 'n':  *dst++ = '\n'; break;
    case 'r':  *dst++ = '\r'; break;
    default:   return 0;      /* unknown escape, or a trailing backslash */
    }
    src++;
  }
  *dst = '\0';
  return 1;
}

/** Start writing a record of the given type.
 * @param[in] out Stream to write to.
 * @param[in] type Record type.
 */
void hr_rec_begin(FILE *out, const char *type)
{
  if (!out || !type)
    return;
  fputs(type, out);
}

/** Append a string valued key to the record being written.
 * @param[in] out Stream to write to.
 * @param[in] key Key name.
 * @param[in] value Value for \a key; NULL is written as an empty value.
 */
void hr_rec_add(FILE *out, const char *key, const char *value)
{
  const unsigned char *p;

  if (!out || !key)
    return;

  putc(' ', out);
  fputs(key, out);
  putc('=', out);

  for (p = (const unsigned char *)(value ? value : ""); *p; p++) {
    switch (*p) {
    case '\\': fputs("\\\\", out); break;
    case ' ':  fputs("\\s", out);  break;
    case '\n': fputs("\\n", out);  break;
    case '\r': fputs("\\r", out);  break;
    default:   putc(*p, out);      break;
    }
  }
}

/** Append an integer valued key to the record being written.
 * @param[in] out Stream to write to.
 * @param[in] key Key name.
 * @param[in] value Value for \a key.
 */
void hr_rec_add_int(FILE *out, const char *key, long long value)
{
  char buf[32];

  snprintf(buf, sizeof(buf), "%lld", value);
  hr_rec_add(out, key, buf);
}

/** Append a key whose value is base64 encoded binary data.
 * @param[in] out Stream to write to.
 * @param[in] key Key name.
 * @param[in] data Data to encode.
 * @param[in] len Length of \a data in bytes.
 */
void hr_rec_add_b64(FILE *out, const char *key, const void *data, size_t len)
{
  const unsigned char *src = (const unsigned char *)data;
  char *enc;
  char *p;
  size_t i;

  if (!out || !key)
    return;
  if (!src)
    len = 0;

  /* Four output characters per three input bytes, rounded up, plus a NUL. */
  enc = (char *)MyMalloc(4 * ((len + 2) / 3) + 1);
  p = enc;

  for (i = 0; i + 3 <= len; i += 3) {
    unsigned long v = ((unsigned long)src[i] << 16) |
                      ((unsigned long)src[i + 1] << 8) |
                      (unsigned long)src[i + 2];
    *p++ = hr_b64_alphabet[(v >> 18) & 0x3f];
    *p++ = hr_b64_alphabet[(v >> 12) & 0x3f];
    *p++ = hr_b64_alphabet[(v >> 6) & 0x3f];
    *p++ = hr_b64_alphabet[v & 0x3f];
  }

  if (i + 1 == len) {
    unsigned long v = (unsigned long)src[i] << 16;
    *p++ = hr_b64_alphabet[(v >> 18) & 0x3f];
    *p++ = hr_b64_alphabet[(v >> 12) & 0x3f];
    *p++ = '=';
    *p++ = '=';
  } else if (i + 2 == len) {
    unsigned long v = ((unsigned long)src[i] << 16) |
                      ((unsigned long)src[i + 1] << 8);
    *p++ = hr_b64_alphabet[(v >> 18) & 0x3f];
    *p++ = hr_b64_alphabet[(v >> 12) & 0x3f];
    *p++ = hr_b64_alphabet[(v >> 6) & 0x3f];
    *p++ = '=';
  }
  *p = '\0';

  hr_rec_add(out, key, enc);
  MyFree(enc);
}

/** Finish the record being written.
 * @param[in] out Stream to write to.
 */
void hr_rec_end(FILE *out)
{
  if (!out)
    return;
  putc('\n', out);
}

/** Parse one dump line in place.
 *
 * The line buffer is modified: the separating spaces and the '=' of each
 * pair become NULs and the values are unescaped where they lie, so the
 * pointers left in \a rec are all into \a line and stay valid only as long
 * as it does.
 *
 * @param[in,out] line Line to parse; it is modified in place.
 * @param[out] rec Receives the parsed record.
 * @return Non-zero if the line was well formed, zero if malformed.
 */
int hr_parse_line(char *line, struct hr_record *rec)
{
  char *p;
  char *tok;
  char *eq;
  int more;

  if (!line || !rec)
    return 0;

  rec->type = 0;
  rec->nkeys = 0;

  /* Strip a trailing newline, and the carriage return of a CRLF with it. */
  p = line + strlen(line);
  if (p > line && p[-1] == '\n') {
    *--p = '\0';
    if (p > line && p[-1] == '\r')
      *--p = '\0';
  }

  if (!*line)
    return 0;

  /* The type is everything up to the first space. */
  p = line;
  while (*p && *p != ' ')
    p++;
  more = (*p == ' ');
  if (more)
    *p++ = '\0';
  if (!hr_valid_type(line))
    return 0;
  rec->type = line;

  /* Each remaining token is one key=value pair.  Splitting on a single space
   * means two spaces in a row yield an empty token, which is malformed --
   * and so is the empty token a trailing space leaves behind. */
  while (more) {
    tok = p;
    while (*p && *p != ' ')
      p++;
    more = (*p == ' ');
    if (more)
      *p++ = '\0';

    eq = strchr(tok, '=');
    if (!eq || eq == tok)
      return 0;                 /* no '=', or an empty key */
    *eq = '\0';
    if (!hr_valid_key(tok))
      return 0;
    if (!hr_unescape(eq + 1))
      return 0;
    if (rec->nkeys >= HR_MAX_KEYS)
      return 0;

    rec->keys[rec->nkeys] = tok;
    rec->values[rec->nkeys] = eq + 1;
    rec->nkeys++;
  }

  return 1;
}

/** Look up a key in a parsed record.
 * @param[in] rec Record to search.
 * @param[in] key Key to look for.
 * @return Value for the first matching \a key, or NULL when absent.
 */
const char *hr_get(const struct hr_record *rec, const char *key)
{
  unsigned int i;

  if (!rec || !key)
    return 0;
  for (i = 0; i < rec->nkeys; i++)
    if (!strcmp(rec->keys[i], key))
      return rec->values[i];
  return 0;
}

/** Look up an integer valued key in a parsed record.
 * @param[in] rec Record to search.
 * @param[in] key Key to look for.
 * @param[in] dflt Value to return when \a key is absent or unparsable.
 * @return Value for \a key, or \a dflt.
 */
long long hr_get_int(const struct hr_record *rec, const char *key, long long dflt)
{
  const char *value = hr_get(rec, key);
  char *end;
  long long result;

  if (!value || !*value)
    return dflt;
  errno = 0;
  result = strtoll(value, &end, 10);
  if (*end || errno == ERANGE)
    return dflt;                /* trailing junk, or out of range */
  return result;
}

/** Decode base64 data.
 *
 * Accepts both the padded and the unpadded forms of RFC 4648 base64.
 *
 * @param[in] src NUL terminated base64 text.
 * @param[out] dst Buffer for the decoded data.
 * @param[in] dstlen Size of \a dst in bytes.
 * @return Number of bytes written, or (size_t)-1 on error.
 */
size_t hr_b64_decode(const char *src, unsigned char *dst, size_t dstlen)
{
  size_t len;
  size_t npad = 0;
  size_t rem;
  size_t need;
  size_t i;
  size_t o = 0;

  if (!src)
    return (size_t)-1;

  len = strlen(src);
  if (len == 0)
    return 0;

  /* Peel the padding off, then require that it was the tail of a whole
   * number of quads. */
  while (len > 0 && src[len - 1] == '=') {
    if (++npad > 2)
      return (size_t)-1;
    len--;
  }
  if (npad > 0 && (len + npad) % 4 != 0)
    return (size_t)-1;

  rem = len % 4;
  if (rem == 1)
    return (size_t)-1;          /* no quad ever encodes to one character */

  for (i = 0; i < len; i++)
    if (hr_b64_value((unsigned char)src[i]) < 0)
      return (size_t)-1;

  need = (len / 4) * 3;
  if (rem == 2)
    need += 1;
  else if (rem == 3)
    need += 2;
  if (need > dstlen)
    return (size_t)-1;

  for (i = 0; i + 4 <= len; i += 4) {
    unsigned long v =
      ((unsigned long)hr_b64_value((unsigned char)src[i]) << 18) |
      ((unsigned long)hr_b64_value((unsigned char)src[i + 1]) << 12) |
      ((unsigned long)hr_b64_value((unsigned char)src[i + 2]) << 6) |
      (unsigned long)hr_b64_value((unsigned char)src[i + 3]);
    dst[o++] = (unsigned char)(v >> 16);
    dst[o++] = (unsigned char)(v >> 8);
    dst[o++] = (unsigned char)v;
  }

  if (rem == 2) {
    unsigned long v =
      ((unsigned long)hr_b64_value((unsigned char)src[i]) << 18) |
      ((unsigned long)hr_b64_value((unsigned char)src[i + 1]) << 12);
    dst[o++] = (unsigned char)(v >> 16);
  } else if (rem == 3) {
    unsigned long v =
      ((unsigned long)hr_b64_value((unsigned char)src[i]) << 18) |
      ((unsigned long)hr_b64_value((unsigned char)src[i + 1]) << 12) |
      ((unsigned long)hr_b64_value((unsigned char)src[i + 2]) << 6);
    dst[o++] = (unsigned char)(v >> 16);
    dst[o++] = (unsigned char)(v >> 8);
  }

  return o;
}

/** Read a whole dump and split it into lines.
 *
 * Reads \a fd to end of file into a buffer that starts at 64 KB and doubles
 * as needed, then hands back one separately allocated, NUL terminated copy
 * per line with the newline removed.  A final fragment with no newline is
 * kept if it has any content and dropped if it does not.
 *
 * @param[in] fd Descriptor to read to end of file.
 * @param[out] out Receives the lines read.
 * @return Non-zero on success, zero on read error.
 */
int hr_read_all(int fd, struct hr_lines *out)
{
  char *buf;
  char **lines = 0;
  size_t cap = HR_READ_CHUNK;
  size_t len = 0;
  size_t lcap = 0;
  size_t lcount = 0;
  size_t start;
  size_t i;

  if (!out)
    return 0;
  out->line = 0;
  out->count = 0;

  buf = (char *)MyMalloc(cap);
  for (;;) {
    ssize_t n;

    if (len == cap) {
      cap *= 2;
      buf = (char *)MyRealloc(buf, cap);
    }
    n = read(fd, buf + len, cap - len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      MyFree(buf);
      return 0;
    }
    if (n == 0)
      break;
    len += (size_t)n;
  }

  /* Split on newlines; the last fragment counts only if it is not empty. */
  start = 0;
  for (i = 0; i <= len; i++) {
    size_t llen;

    if (i < len && buf[i] != '\n')
      continue;
    if (i == len) {
      if (start >= len)
        break;                  /* nothing after the final newline */
    }
    llen = i - start;

    if (lcount == lcap) {
      lcap = lcap ? lcap * 2 : 64;
      lines = (char **)(lines ? MyRealloc(lines, lcap * sizeof(*lines))
                              : MyMalloc(lcap * sizeof(*lines)));
    }
    lines[lcount] = (char *)MyMalloc(llen + 1);
    memcpy(lines[lcount], buf + start, llen);
    lines[lcount][llen] = '\0';
    lcount++;

    start = i + 1;
  }

  MyFree(buf);
  out->line = lines;
  out->count = (unsigned int)lcount;
  return 1;
}

/** Release the storage held by hr_read_all().
 * @param[in,out] lines Lines to release.
 */
void hr_free_lines(struct hr_lines *lines)
{
  unsigned int i;

  if (!lines)
    return;
  if (lines->line) {
    for (i = 0; i < lines->count; i++)
      MyFree(lines->line[i]);
    MyFree(lines->line);
  }
  lines->line = 0;
  lines->count = 0;
}

/** Close every descriptor up to \a maxfd except those listed.
 *
 * Descriptors below 3 are never touched, so the standard streams survive.
 * Failures from close() are ignored: a descriptor that cannot be closed is
 * one that was not open.
 *
 * @param[in] keep Descriptors to leave open.
 * @param[in] nkeep Number of entries in \a keep.
 * @param[in] maxfd Highest descriptor to consider, exclusive.
 */
void hr_close_all_except(const int *keep, unsigned int nkeep, int maxfd)
{
  unsigned char *bitmap;
  unsigned int i;
  int fd;

  if (maxfd <= 3)
    return;

  bitmap = (unsigned char *)MyCalloc(((size_t)maxfd + 7) / 8, 1);

  for (i = 0; i < nkeep; i++) {
    fd = keep[i];
    if (fd >= 0 && fd < maxfd)
      bitmap[fd >> 3] |= (unsigned char)(1 << (fd & 7));
  }

  for (fd = 3; fd < maxfd; fd++)
    if (!(bitmap[fd >> 3] & (1 << (fd & 7))))
      close(fd);

  MyFree(bitmap);
}
