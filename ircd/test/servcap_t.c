/* servcap_t.c - unit test for the P11 link capability parser.
 *
 * Exercises servcap_parse() / servcap_names() / servcap_announce() against
 * an injected table so that non-empty intersections are covered even while
 * the production table (servcap_table) is empty.  The acceptance rules are
 * spelled out in include/servcap.h.
 */

#include "servcap.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static int parse_gamma(const char *value)
{
  return 0 == strcmp(value, "x,y");
}

static const struct ServCapEntry table[] = {
  { "alpha", 1, 0 },
  { "beta",  2, 0 },
  { "gamma", 4, parse_gamma },
  { 0, 0, 0 }
};

static void check_parse(const char *list, servcap_t want)
{
  servcap_t got = servcap_parse(list, table);

  if (got != want) {
    printf("FAIL: servcap_parse(\"%s\") = %u, want %u\n",
           list ? list : "(null)", got, want);
    ++failures;
  } else {
    printf("Passed: servcap_parse(\"%s\") = %u\n", list ? list : "(null)", got);
  }
}

static void check_names(servcap_t caps, const char *want)
{
  char buf[128];
  size_t n = servcap_names(caps, buf, sizeof(buf), table);

  if (strcmp(buf, want) || n != strlen(want)) {
    printf("FAIL: servcap_names(%u) = \"%s\" (%u), want \"%s\"\n",
           caps, buf, (unsigned)n, want);
    ++failures;
  } else {
    printf("Passed: servcap_names(%u) = \"%s\"\n", caps, buf);
  }
}

int main(void)
{
  char longname[SERVCAP_NAME_MAX + 2 + 8];
  char buf[64];
  size_t n;

  check_parse("", 0);
  check_parse(0, 0);
  check_parse("alpha", 1);
  check_parse("alpha beta", 3);
  check_parse("  alpha   beta  ", 3);
  check_parse("Alpha", 0);                 /* uppercase is invalid */
  check_parse("alpha=1", 0);               /* bare-only entry given a value */
  check_parse("gamma", 0);                 /* value required */
  check_parse("gamma=x,y", 4);
  check_parse("gamma=z", 0);               /* value not understood */
  check_parse("alpha alpha=1", 1);         /* first occurrence decides */
  check_parse("alpha=1 alpha", 0);
  check_parse("unknown alpha", 1);
  check_parse("draft/foo alpha", 1);
  check_parse("al pha", 0);
  check_parse("=alpha", 0);                /* empty name */
  check_parse("gamma=", 0);                /* empty value */

  /* A 64-character name is ignored even if it is a table entry's prefix. */
  memset(longname, 'a', SERVCAP_NAME_MAX + 1);
  longname[SERVCAP_NAME_MAX + 1] = '\0';
  strcat(longname, " beta");
  check_parse(longname, 2);

  check_names(5, "alpha gamma");
  check_names(0, "");
  check_names(7, "alpha beta gamma");

  /* Truncation never overruns and always NUL-terminates. */
  n = servcap_names(7, buf, 8, table);
  if (n >= 8 || strlen(buf) != n || strcmp(buf, "alpha")) {
    printf("FAIL: truncated servcap_names = \"%s\" (%u)\n", buf, (unsigned)n);
    ++failures;
  } else
    printf("Passed: servcap_names truncates at a name boundary\n");

  n = servcap_announce(buf, sizeof(buf));
  if (n != 0 || buf[0] != '\0') {
    printf("FAIL: servcap_announce = \"%s\" (%u), want empty\n", buf, (unsigned)n);
    ++failures;
  } else
    printf("Passed: servcap_announce is empty in this release\n");

  if (failures) {
    printf("%d failure(s)\n", failures);
    return 1;
  }
  printf("All servcap tests passed\n");
  return 0;
}
