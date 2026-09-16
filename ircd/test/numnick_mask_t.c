/* numnick_mask_t.c - unit test for is_valid_numeric_mask().
 *
 * The SERVER numeric mask is read by two rules (FindNServer() for the
 * collision check, SetServerYXX() for registration) that only agree for
 * lengths 3 and 5; every other length lets a peer silently overwrite another
 * server's server_list[] slot.  The validator must accept exactly the two
 * agreeing forms and refuse everything else.
 */

#include "numnicks.h"

#include <stdio.h>

static int failures = 0;

static void check(const char *mask, int want)
{
  int got = is_valid_numeric_mask(mask);

  if (got != want) {
    printf("FAIL: is_valid_numeric_mask(\"%s\") = %d, want %d\n",
           mask ? mask : "(null)", got, want);
    ++failures;
  } else {
    printf("Passed: is_valid_numeric_mask(\"%s\") = %d\n", mask ? mask : "(null)", got);
  }
}

int main(void)
{
  check("ABAAB", 1);      /* our own form: YY + XXX */
  check("E]]", 1);        /* legacy YXX */
  check("AAAAA", 1);      /* all-'A' (value 0) is valid */
  check("A", 0);
  check("AB", 0);
  check("ABCD", 0);
  check("ABCDEF", 0);
  check("AB!AB", 0);      /* outside the numnick alphabet */
  check("AB AB", 0);
  check("AB:AB", 0);
  check("", 0);
  check(0, 0);

  if (failures) {
    printf("%d failure(s)\n", failures);
    return 1;
  }
  printf("All numnick mask tests passed\n");
  return 0;
}
