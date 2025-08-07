#ifndef INCLUDED_sline_h
#define INCLUDED_sline_h
/*
 * IRC - Internet Relay Chat, include/sline.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
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
 * @brief Structures and APIs for S-line manipulation.
 * @version $Id$
 */
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#include <stdint.h>

struct Client;
struct StatDesc;
struct Channel;

/** Forward declaration for hold queue entry */
struct HoldQueueEntry;

#define SLINE_MAX_EXPIRE 604800	/**< max expire: 7 days */

/* Regex capture group limits */
#define SLINE_MAX_CAPTURES 16  /**< Maximum regex capture groups supported (including full match).
                                    If an S-line regex pattern contains more than 15 capture groups,
                                    only the first 15 will be captured and passed to spam filters. */

/* Message type flags */
#define SLINE_ALL	    0x0001  /**< Match all message types. */
#define SLINE_PRIVATE	0x0002  /**< Match private messages. */
#define SLINE_CHANNEL	0x0004  /**< Match channel messages. */

/** Controllable flags that can be set on an actual S-line. */
#define SLINE_MASK	(SLINE_ALL | SLINE_PRIVATE | SLINE_CHANNEL)

/** Description of an S-line. */
struct Sline {
  struct Sline *sl_next;	    /**< Next S-line in linked list. */
  struct Sline **sl_prev_p;	  /**< Previous pointer to this S-line. */
  char	       *sl_pattern;	  /**< Regex pattern to match against messages. */
  time_t	      sl_lastmod;	  /**< When the S-line was last modified. */
  unsigned int	sl_flags;	    /**< S-line status flags. */
  uint64_t      sl_count;     /**< Number of times this S-line has matched. */
};

/** Return pattern of an S-line. */
#define SlinePattern(s)		((s)->sl_pattern)
/** Return last modified time of an S-line. */
#define SlineLastMod(s)		((s)->sl_lastmod)

/** Action to perform on a S-line. */
enum SlineAction {
  SLINE_BURST,        /**< S-line is received through a burst. */
  SLINE_ACTIVATE,		  /**< S-line should be activated. */
  SLINE_DEACTIVATE,		/**< S-line should be deactivated. */
  SLINE_MODIFY			  /**< S-line should be modified. */
};

extern int sline_add(struct Client *cptr, struct Client *sptr, char *pattern,
 		     time_t lastmod, unsigned int flags);
extern int sline_remove(struct Client *cptr, struct Client *sptr,
 			struct Sline *sline);
extern struct Sline *sline_find(char *pattern);
extern void sline_free(struct Sline *sline);
extern void sline_stats(struct Client *sptr, const struct StatDesc *sd,
                        char *param);
extern int sline_memory_count(size_t *sl_size);
extern void sline_send_meminfo(struct Client* sptr);
extern void sline_burst(struct Client *cptr);
extern char *sline_check_pattern(const char *text, unsigned int msg_type);
extern struct HoldQueueEntry *sline_hold_privmsg(struct Client *sender, struct Client *recipient, 
                                                  const char *text, const char *captures, int is_notice);
extern struct HoldQueueEntry *sline_hold_chanmsg(struct Client *sender, struct Channel *channel,
                                                  const char *text, const char *captures, int is_notice);
extern void sline_hold_free(struct HoldQueueEntry *entry);
extern int sline_notify_spamfilters(struct HoldQueueEntry *entry);
extern int sline_check_privmsg(struct Client *sender, struct Client *recipient, const char *text, int is_notice);
extern int sline_check_chanmsg(struct Client *sender, struct Channel *channel, const char *text, int is_notice);
extern struct HoldQueueEntry *sline_find_hold_entry(unsigned int token);
extern int sline_release_privmsg(struct HoldQueueEntry *entry);
extern int sline_release_chanmsg(struct HoldQueueEntry *entry);
extern int sline_release_hold(unsigned int token);
extern int sline_drop_hold(unsigned int token);
extern void sline_cleanup_client(struct Client *cptr);
extern void sline_cleanup_channel(struct Channel *chptr);
extern int sline_xreply_handler(struct Client *sptr, const char *token, const char *reply);
extern void sline_start_hold_timeout_timer(void);
extern void sline_stop_hold_timeout_timer(void);
extern void sline_init(void);

#endif /* INCLUDED_sline_h */