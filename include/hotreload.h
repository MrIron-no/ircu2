/*
 * IRC - Internet Relay Chat, include/hotreload.h
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
 * @brief Hot reload: exec the server in place, carrying connections across.
 *
 * A hot reload writes the whole of the server's state to a pipe as text
 * records, execs the new binary with the listening and client sockets still
 * open, and lets the new image read the dump back and adopt them.  This
 * header holds the contract between the four parts of that: the record wire
 * format (hotreload_wire.c), the dumper (hotreload_dump.c), the reader and
 * applier (hotreload_load.c) and the orchestration (hotreload.c).
 */
#ifndef INCLUDED_hotreload_h
#define INCLUDED_hotreload_h

#ifndef INCLUDED_stdio_h
#include <stdio.h>              /* FILE */
#define INCLUDED_stdio_h
#endif

#ifndef INCLUDED_stddef_h
#include <stddef.h>             /* size_t */
#define INCLUDED_stddef_h
#endif

struct Client;
struct irc_in_addr;

/** One parsed record of a state dump: a type and its key/value pairs. */
struct hr_record {
  const char *type;             /**< Record type, e.g. "client". */
  unsigned int nkeys;           /**< Number of key/value pairs used. */
  const char *keys[64];         /**< Key names, in the order parsed. */
  const char *values[64];       /**< Values, parallel to hr_record::keys. */
};

/* wire (hotreload_wire.c) */

/** Start writing a record of the given type. */
void hr_rec_begin(FILE *out, const char *type);
/** Append a string valued key to the record being written. */
void hr_rec_add(FILE *out, const char *key, const char *value);
/** Append an integer valued key to the record being written. */
void hr_rec_add_int(FILE *out, const char *key, long long value);
/** Append a key whose value is base64 encoded binary data. */
void hr_rec_add_b64(FILE *out, const char *key, const void *data, size_t len);
/** Finish the record being written. */
void hr_rec_end(FILE *out);
/** Parse one dump line in place; returns 1 if well formed, 0 if malformed. */
int  hr_parse_line(char *line, struct hr_record *rec);   /* parses in place; returns 1 ok, 0 malformed */
/** Look up a key in a parsed record; NULL when the key is absent. */
const char *hr_get(const struct hr_record *rec, const char *key);   /* NULL if absent */
/** Look up an integer valued key, returning \a dflt when absent or unparsable. */
long long hr_get_int(const struct hr_record *rec, const char *key, long long dflt);
/** Decode base64 into \a dst; returns the length written, or (size_t)-1 on error. */
size_t hr_b64_decode(const char *src, unsigned char *dst, size_t dstlen); /* (size_t)-1 on error */

/** A whole dump, split into NUL terminated lines. */
struct hr_lines { char **line; unsigned int count; };

/** Read a whole dump from \a fd and split it into lines; returns 1 on success. */
int  hr_read_all(int fd, struct hr_lines *out);           /* reads to EOF, splits on \n; 1 ok */
/** Release the storage held by hr_read_all(). */
void hr_free_lines(struct hr_lines *lines);
/** Close every descriptor up to \a maxfd except the \a nkeep listed in \a keep. */
void hr_close_all_except(const int *keep, unsigned int nkeep, int maxfd);

/* dump (hotreload_dump.c) */

/** Write the whole of the server state to \a out; returns 1 ok, 0 on write error. */
int  hotreload_dump(FILE *out);                            /* 1 ok, 0 on write error */

/* load (hotreload_load.c) */

/** Read a state dump from \a fd; returns 1 on success, 0 when the caller must cold boot. */
int  hotreload_read(int fd);                               /* 1 ok; 0 => caller cold-boots */
/** Return 1 while a dump has been read but not yet applied. */
int  hotreload_pending(void);                              /* 1 while a read dump awaits apply */
/** Claim the inherited listening socket for an address, or -1 if there is none. */
int  hotreload_claim_listener(int family, const struct irc_in_addr *addr, int port); /* fd or -1 */
/** Apply the dump that was read, or just check that it could be applied. */
int  hotreload_apply(int check_only);                      /* 1 ok, 0 failure */

/* orchestration (hotreload.c) */

/** Dump state and exec this server in place, keeping connections open.
 *
 * The reload sheds every connection the dump cannot carry, and \a by may be
 * one of them -- an oper on a TLS session that is not kernel-offloaded kills
 * its own connection by typing RELOAD.  When the reload then aborts (the
 * pre-flight check failing is the designed outcome, not an accident) this
 * function returns to a caller whose client is already freed, so it says so.
 *
 * @param[in] reason Human readable reason for the reload, for the logs.
 * @param[in] by Local client that issued the reload, or NULL for a signal.
 * @return 1 when \a by was exited during the attempt, in which case the
 *   caller must return CPTR_KILLED and must not touch \a by again; 0
 *   otherwise.  Never returns at all once the exec succeeds.
 */
int server_reload(const char *reason, struct Client *by);
/** Write a state dump to a file, for debugging; returns 1 on success. */
int  hotreload_dump_to_path(const char *path);             /* 1 ok */

extern int hotreload_fd;      /**< -1 unless booted with -R */
extern int hotreload_check;   /**< 1 when booted with -K */

#endif /* INCLUDED_hotreload_h */
