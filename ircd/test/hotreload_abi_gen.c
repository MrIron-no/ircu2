/*
 * hotreload_abi_gen.c - authoritative dump of the hot-reload "stored by value"
 * ABI.
 *
 * The hot-reload state dump (ircd/hotreload_dump.c) writes a handful of fields
 * as their RAW bit / enum values rather than as symbolic names.  Because a hot
 * reload hands that dump to a freshly execv()'d binary, those numeric values
 * MUST stay identical between the image that writes a dump and the one that
 * reads it back (ircd/hotreload_load.c).  If a bit is renumbered or an enum is
 * reordered, an old dump silently decodes into the wrong flags on the new
 * binary - a corruption with no error and no crash.
 *
 * This program is the source of truth for those values.  It includes the real
 * project headers and prints one "SYMBOL VALUE" line (space separated, VALUE
 * as an unsigned decimal) for every guarded symbol, sorted by symbol name.
 * Because it reads the COMPILED values (not a source parse), its output is
 * authoritative.  tools/check-hotreload-abi.sh compares this output against the
 * committed golden snapshot ircd/test/hotreload_abi.golden and fails CI when a
 * guarded value changes or disappears.  To change one on purpose: bump the
 * dump version in ircd/hotreload_dump.c, add loader compatibility handling in
 * ircd/hotreload_load.c, then refresh the golden file with
 * `tools/check-hotreload-abi.sh --update`.
 *
 * The guarded set is exactly the raw-value sites in ircd/hotreload_dump.c:
 *   - enum Flag        (client.h)  - the whole client flag bitset; bit
 *                                    POSITIONS matter, dumped by hr_client_flags.
 *   - SNO_* notice bits (client.h) - the atomic bits that make up cli_snomask().
 *   - GLINE_* flag bits (gline.h)  - the bits stored in gl_flags.
 *   - enum GlineLocalState (gline.h) - the gl_state value.
 *   - SLINE_* bits      (sline.h)  - the sl_msgtype_t / sl_flagtype_t bits.
 *   - BAN_* flag bits   (channel.h) - the ban->flags bits.
 *
 * Symbolically-encoded fields (caps, privs, channel modes, letter umodes) are
 * self-describing on reload and need no guard.  Account flags (user->acc_flags)
 * are stored by value too, but ircu defines NO named account-flag constants -
 * the value is an opaque uint64 handed over by services - so there is nothing
 * symbolic to guard for them.
 */

#include "config.h"

#include "client.h"
#include "channel.h"
#include "gline.h"
#include "sline.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** One guarded symbol and its compiled value. */
struct abi_sym {
  const char *name;
  unsigned long long value;
};

#define SYM(x) { #x, (unsigned long long)(x) }

static struct abi_sym syms[] = {
  /* enum Flag - client flag bitset (client.h).  Every enumerator up to
   * FLAG_LAST_FLAG; the aliases FLAG_LOCAL_UMODES / FLAG_GLOBAL_UMODES and the
   * count FLAG_LAST_FLAG itself are intentionally omitted (they are not stored
   * bit positions). */
  SYM(FLAG_PINGSENT),
  SYM(FLAG_DEADSOCKET),
  SYM(FLAG_KILLED),
  SYM(FLAG_BLOCKED),
  SYM(FLAG_CLOSING),
  SYM(FLAG_UPING),
  SYM(FLAG_HUB),
  SYM(FLAG_IPV6),
  SYM(FLAG_SERVICE),
  SYM(FLAG_GOTID),
  SYM(FLAG_NONL),
  SYM(FLAG_TS8),
  SYM(FLAG_MAP),
  SYM(FLAG_JUNCTION),
  SYM(FLAG_BURST),
  SYM(FLAG_BURST_ACK),
  SYM(FLAG_IPCHECK),
  SYM(FLAG_IAUTH_STATS),
  SYM(FLAG_NEGOTIATING_TLS),
  SYM(FLAG_EXEMPT_THROTTLE),
  SYM(FLAG_LOCOP),
  SYM(FLAG_SERVNOTICE),
  SYM(FLAG_OPER),
  SYM(FLAG_SASL),
  SYM(FLAG_INVISIBLE),
  SYM(FLAG_WALLOP),
  SYM(FLAG_DEAF),
  SYM(FLAG_BLOCK_UNAUTH_USERS),
  SYM(FLAG_CHSERV),
  SYM(FLAG_DEBUG),
  SYM(FLAG_ACCOUNT),
  SYM(FLAG_HIDDENHOST),
  SYM(FLAG_CAP302),
  SYM(FLAG_TLS),
  SYM(FLAG_TLS_RAW),
  SYM(FLAG_SPAMHOLD),
  SYM(FLAG_HIDEIDLE),
  SYM(FLAG_COMMONCHANS),

  /* SNO_* - the atomic server-notice bits that constitute a stored snomask
   * (client.h).  The operation selectors SNO_ADD/DEL/SET and the derived,
   * build-dependent composite masks (SNO_ALL, SNO_USER, ...) are excluded:
   * they are not stored bit positions and some vary with DEBUGMODE. */
  SYM(SNO_OLDSNO),
  SYM(SNO_SERVKILL),
  SYM(SNO_OPERKILL),
  SYM(SNO_HACK2),
  SYM(SNO_HACK3),
  SYM(SNO_UNAUTH),
  SYM(SNO_TCPCOMMON),
  SYM(SNO_TOOMANY),
  SYM(SNO_HACK4),
  SYM(SNO_GLINE),
  SYM(SNO_NETWORK),
  SYM(SNO_IPMISMATCH),
  SYM(SNO_THROTTLE),
  SYM(SNO_OLDREALOP),
  SYM(SNO_CONNEXIT),
  SYM(SNO_AUTO),
  SYM(SNO_DEBUG),
  SYM(SNO_AUTH),

  /* GLINE_* - the bits stored in gl_flags (gline.h).  The enum GlineAction
   * codes (GLINE_ACTIVATE, ...) and the composite masks (GLINE_MASK, ...) are
   * excluded: they are transient/derived, not stored by value. */
  SYM(GLINE_ACTIVE),
  SYM(GLINE_IPMASK),
  SYM(GLINE_BADCHAN),
  SYM(GLINE_LOCAL),
  SYM(GLINE_ANY),
  SYM(GLINE_FORCE),
  SYM(GLINE_EXACT),
  SYM(GLINE_LDEACT),
  SYM(GLINE_GLOBAL),
  SYM(GLINE_LASTMOD),
  SYM(GLINE_OPERFORCE),
  SYM(GLINE_REALNAME),
  SYM(GLINE_EXPIRE),
  SYM(GLINE_LIFETIME),
  SYM(GLINE_REASON),

  /* enum GlineLocalState - stored as gl_state (gline.h). */
  SYM(GLOCAL_GLOBAL),
  SYM(GLOCAL_ACTIVATED),
  SYM(GLOCAL_DEACTIVATED),

  /* SLINE_* - the sl_msgtype_t / sl_flagtype_t bits (sline.h).  The composite
   * SLINE_ALL is excluded (derived). */
  SYM(SLINE_PRIVATE),
  SYM(SLINE_CHANNEL),
  SYM(SLINE_PART),
  SYM(SLINE_QUIT),
  SYM(SLINE_ACTIVE),
  SYM(SLINE_INVALID),
  SYM(SLINE_EXPIRE),
  SYM(SLINE_MSGTYPE),
  SYM(SLINE_STATE),

  /* BAN_* - the bits stored in ban->flags (channel.h). */
  SYM(BAN_IPMASK),
  SYM(BAN_OVERLAPPED),
  SYM(BAN_BURSTED),
  SYM(BAN_BURST_WIPEOUT),
  SYM(BAN_EXCEPTION),
  SYM(BAN_DEL),
  SYM(BAN_ADD),
};

static int
cmp_sym(const void *a, const void *b)
{
  const struct abi_sym *sa = a;
  const struct abi_sym *sb = b;
  return strcmp(sa->name, sb->name);
}

int
main(void)
{
  size_t n = sizeof(syms) / sizeof(syms[0]);
  size_t i;

  qsort(syms, n, sizeof(syms[0]), cmp_sym);
  for (i = 0; i < n; i++)
    printf("%s %llu\n", syms[i].name, syms[i].value);
  return 0;
}
