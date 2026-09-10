/* hotreload_wire_t.c - unit tests for the hot reload record wire format.
 *
 * Covers the encoder (hr_rec_*), the in-place line parser (hr_parse_line and
 * the hr_get accessors), the base64 codec, the whole-dump line reader
 * (hr_read_all) and the descriptor sweep (hr_close_all_except).  The wire
 * format is the contract between the dumper and the loader, so the round
 * trips here are deliberately hostile: embedded spaces, backslashes, '=',
 * CRLF, NUL bearing binary and values far larger than any sane line buffer.
 */

#include "hotreload.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/** Length of the oversized value used to prove there is no line limit. */
#define BIG_LEN (16 * 1024)

/** Write \a f's contents back as a single parsed record.
 *
 * Rewinds \a f, slurps it with hr_read_all(), and asserts it holds exactly
 * one line.  The line is handed back in \a *held so the caller can free it
 * after it is done with the pointers @a rec holds into it.
 */
static void
parse_only_line(FILE *f, struct hr_record *rec, char **held)
{
  struct hr_lines lines;

  fflush(f);
  assert(lseek(fileno(f), 0, SEEK_SET) == 0);
  assert(hr_read_all(fileno(f), &lines) == 1);
  assert(lines.count == 1);

  *held = strdup(lines.line[0]);
  assert(*held != NULL);
  hr_free_lines(&lines);

  assert(hr_parse_line(*held, rec) == 1);
}

/* A record whose values carry every character the escaper has to deal with
 * survives a write/read/parse round trip byte for byte. */
static void
test_roundtrip_hostile_values(void)
{
  FILE *f = tmpfile();
  struct hr_record rec;
  char *held = NULL;
  char *big;
  const char *spaces = "hello there world";
  const char *slashes = "a\\b\\\\c";
  const char *equals = "k=v=w";
  const char *crlf = "line1\r\nline2\n";
  const char *mixed = "\\s \\n=x\r";

  assert(f != NULL);

  big = (char *)malloc(BIG_LEN + 1);
  assert(big != NULL);
  {
    int i;
    /* Repeating pattern that includes the escaped characters, so the encoded
     * form is several times longer than the raw 16 KB. */
    for (i = 0; i < BIG_LEN; i++)
      big[i] = "abc \\def\r\nghij"[i % 14];
    big[BIG_LEN] = '\0';
  }

  hr_rec_begin(f, "CLIENT");
  hr_rec_add(f, "spaces", spaces);
  hr_rec_add(f, "slashes", slashes);
  hr_rec_add(f, "equals", equals);
  hr_rec_add(f, "crlf", crlf);
  hr_rec_add(f, "mixed", mixed);
  hr_rec_add(f, "big", big);
  hr_rec_add(f, "empty", "");
  hr_rec_add(f, "null", NULL);
  hr_rec_add_int(f, "num", -1234567890123LL);
  hr_rec_end(f);

  parse_only_line(f, &rec, &held);

  assert(!strcmp(rec.type, "CLIENT"));
  assert(rec.nkeys == 9);
  assert(!strcmp(rec.keys[0], "spaces"));
  assert(!strcmp(hr_get(&rec, "spaces"), spaces));
  assert(!strcmp(hr_get(&rec, "slashes"), slashes));
  assert(!strcmp(hr_get(&rec, "equals"), equals));
  assert(!strcmp(hr_get(&rec, "crlf"), crlf));
  assert(!strcmp(hr_get(&rec, "mixed"), mixed));
  assert(strlen(hr_get(&rec, "big")) == BIG_LEN);
  assert(!strcmp(hr_get(&rec, "big"), big));
  assert(!strcmp(hr_get(&rec, "empty"), ""));
  assert(!strcmp(hr_get(&rec, "null"), ""));
  assert(hr_get_int(&rec, "num", 7) == -1234567890123LL);

  free(held);
  free(big);
  fclose(f);
  printf("Passed: hostile values round trip through the wire format\n");
}

/* hr_get()/hr_get_int() report absent and unparsable keys as such. */
static void
test_accessors(void)
{
  char line[] = "CLIENT a=1 neg=-42 abc=abc empty= trail=12x";
  struct hr_record rec;

  assert(hr_parse_line(line, &rec) == 1);
  assert(rec.nkeys == 5);

  assert(hr_get(&rec, "nosuch") == NULL);
  assert(hr_get(&rec, "A") == NULL);        /* case sensitive */
  assert(hr_get_int(&rec, "nosuch", 99) == 99);
  assert(hr_get_int(&rec, "abc", 99) == 99);
  assert(hr_get_int(&rec, "empty", 99) == 99);
  assert(hr_get_int(&rec, "trail", 99) == 99);
  assert(hr_get_int(&rec, "neg", 99) == -42);
  assert(hr_get_int(&rec, "a", 99) == 1);

  printf("Passed: hr_get and hr_get_int accessors\n");
}

/** Round trip \a len pseudo-random bytes through hr_rec_add_b64/hr_b64_decode. */
static void
b64_roundtrip(size_t len)
{
  FILE *f = tmpfile();
  struct hr_record rec;
  char *held = NULL;
  unsigned char *raw;
  unsigned char *out;
  const char *enc;
  size_t got;
  size_t i;

  assert(f != NULL);
  raw = (unsigned char *)malloc(len ? len : 1);
  out = (unsigned char *)malloc(len ? len : 1);
  assert(raw != NULL && out != NULL);

  /* Deterministic pseudo-random bytes, NULs and high bytes included. */
  for (i = 0; i < len; i++)
    raw[i] = (unsigned char)((i * 97u + (i >> 3) * 31u) & 0xff);
  if (len > 2)
    raw[2] = 0;

  hr_rec_begin(f, "BLOB");
  hr_rec_add_b64(f, "data", raw, len);
  hr_rec_end(f);

  parse_only_line(f, &rec, &held);
  enc = hr_get(&rec, "data");
  assert(enc != NULL);
  /* Encoded form is padded to a multiple of four (empty stays empty). */
  assert(strlen(enc) == 4 * ((len + 2) / 3));

  got = hr_b64_decode(enc, out, len ? len : 1);
  assert(got == len);
  assert(len == 0 || !memcmp(out, raw, len));

  free(held);
  free(raw);
  free(out);
  fclose(f);
}

/* The base64 codec round trips, and rejects junk, bad length and short dst. */
static void
test_base64(void)
{
  unsigned char out[8];

  b64_roundtrip(0);
  b64_roundtrip(1);
  b64_roundtrip(2);
  b64_roundtrip(3);
  b64_roundtrip(300);

  assert(hr_b64_decode("!!!!", out, sizeof(out)) == (size_t)-1);
  assert(hr_b64_decode("A", out, sizeof(out)) == (size_t)-1);      /* bad length */
  assert(hr_b64_decode("AAAAA", out, sizeof(out)) == (size_t)-1);  /* bad length */
  assert(hr_b64_decode("A===", out, sizeof(out)) == (size_t)-1);   /* bad padding */
  assert(hr_b64_decode("YWJjZGVm", out, 5) == (size_t)-1);         /* dst too small */
  assert(hr_b64_decode("", out, sizeof(out)) == 0);

  /* Unpadded input decodes just like padded input. */
  memset(out, 0xff, sizeof(out));
  assert(hr_b64_decode("YWJj", out, sizeof(out)) == 3);
  assert(!memcmp(out, "abc", 3));
  memset(out, 0xff, sizeof(out));
  assert(hr_b64_decode("YWJjZA==", out, sizeof(out)) == 4);
  assert(!memcmp(out, "abcd", 4));
  memset(out, 0xff, sizeof(out));
  assert(hr_b64_decode("YWJjZA", out, sizeof(out)) == 4);
  assert(!memcmp(out, "abcd", 4));

  printf("Passed: base64 encode/decode\n");
}

/** Assert that hr_parse_line() calls \a text malformed (it is copied first). */
static void
reject(const char *text)
{
  struct hr_record rec;
  char *copy = strdup(text);

  assert(copy != NULL);
  assert(hr_parse_line(copy, &rec) == 0);
  free(copy);
}

/** Build a line of \a npairs "k<n>=v<n>" pairs; caller frees. */
static char *
make_pairs(unsigned int npairs)
{
  size_t cap = 32 + (size_t)npairs * 24;
  char *line = (char *)malloc(cap);
  unsigned int i;
  size_t used;

  assert(line != NULL);
  strcpy(line, "TYPE");
  used = strlen(line);
  for (i = 0; i < npairs; i++)
    used += (size_t)snprintf(line + used, cap - used, " k%u=v%u", i, i);
  return line;
}

/* The parser rejects every malformed shape the format forbids. */
static void
test_parse_rejects(void)
{
  struct hr_record rec;
  char *line;

  reject("");
  reject("\n");
  reject("TYPE novalue");
  reject("TYPE =x");
  reject("type k=v");            /* lowercase type */
  reject("1TYPE k=v");           /* type must start with a letter */
  reject("TY-PE k=v");           /* '-' is not a type character */
  reject("TYPE k=a\\q");         /* unknown escape */
  reject("TYPE k=a\\");          /* trailing backslash */
  reject("TYPE k-1=v");          /* '-' is not a key character */
  reject("TYPE  k=v");           /* double space */
  reject("TYPE k=v ");           /* trailing space */
  reject(" TYPE k=v");           /* leading space */

  /* A bare type with no pairs is legal, and so is a stripped CRLF. */
  {
    char bare[] = "TYPE\r\n";
    assert(hr_parse_line(bare, &rec) == 1);
    assert(!strcmp(rec.type, "TYPE"));
    assert(rec.nkeys == 0);
  }

  /* 64 pairs is the limit; 65 is malformed. */
  line = make_pairs(64);
  assert(hr_parse_line(line, &rec) == 1);
  assert(rec.nkeys == 64);
  assert(!strcmp(rec.values[63], "v63"));
  assert(!strcmp(hr_get(&rec, "k0"), "v0"));
  free(line);

  line = make_pairs(65);
  assert(hr_parse_line(line, &rec) == 0);
  free(line);

  printf("Passed: parser rejects malformed lines\n");
}

/** Push \a text (\a len bytes) through a pipe and split it with hr_read_all(). */
static void
read_all_pipe(const char *text, size_t len, struct hr_lines *out)
{
  int fds[2];

  assert(pipe(fds) == 0);
  if (len)
    assert(write(fds[1], text, len) == (ssize_t)len);
  close(fds[1]);
  assert(hr_read_all(fds[0], out) == 1);
  close(fds[0]);
}

/* hr_read_all() splits on newlines and keeps a non-empty trailing fragment. */
static void
test_read_all(void)
{
  struct hr_lines lines;

  read_all_pipe("a\nb\nc", 5, &lines);
  assert(lines.count == 3);
  assert(!strcmp(lines.line[0], "a"));
  assert(!strcmp(lines.line[1], "b"));
  assert(!strcmp(lines.line[2], "c"));
  hr_free_lines(&lines);
  assert(lines.count == 0 && lines.line == NULL);

  read_all_pipe("a\n", 2, &lines);
  assert(lines.count == 1);
  assert(!strcmp(lines.line[0], "a"));
  hr_free_lines(&lines);

  read_all_pipe("", 0, &lines);
  assert(lines.count == 0);
  hr_free_lines(&lines);

  /* An empty line in the middle is preserved; a trailing one is not. */
  read_all_pipe("a\n\nb\n", 5, &lines);
  assert(lines.count == 3);
  assert(!strcmp(lines.line[1], ""));
  hr_free_lines(&lines);

  printf("Passed: hr_read_all splits a dump into lines\n");
}

/* A dump larger than the initial read buffer forces it to grow.  A real dump
 * is far past 64 KB, so this is the ordinary path, not an edge case; it goes
 * through a file rather than a pipe because a pipe would block long before
 * this much data was buffered. */
static void
test_read_all_grows(void)
{
  FILE *f = tmpfile();
  struct hr_lines lines;
  const unsigned int nlines = 20000;
  unsigned int i;
  char expect[64];

  assert(f != NULL);
  for (i = 0; i < nlines; i++) {
    hr_rec_begin(f, "CLIENT");
    hr_rec_add_int(f, "id", i);
    hr_rec_add(f, "pad", "0123456789012345678901234567890123456789");
    hr_rec_end(f);
  }
  fflush(f);
  assert(lseek(fileno(f), 0, SEEK_SET) == 0);

  assert(hr_read_all(fileno(f), &lines) == 1);
  assert(lines.count == nlines);

  /* Spot check the first, a middle and the last line, so a buffer seam that
   * corrupted a record would show up. */
  for (i = 0; i < nlines; i += nlines / 2 ? nlines / 2 : 1) {
    struct hr_record rec;
    char *copy = strdup(lines.line[i]);

    assert(copy != NULL);
    assert(hr_parse_line(copy, &rec) == 1);
    sprintf(expect, "%u", i);
    assert(!strcmp(hr_get(&rec, "id"), expect));
    assert(strlen(hr_get(&rec, "pad")) == 40);
    free(copy);
  }
  {
    struct hr_record rec;
    char *copy = strdup(lines.line[nlines - 1]);

    assert(copy != NULL);
    assert(hr_parse_line(copy, &rec) == 1);
    sprintf(expect, "%u", nlines - 1);
    assert(!strcmp(hr_get(&rec, "id"), expect));
    free(copy);
  }

  hr_free_lines(&lines);
  fclose(f);
  printf("Passed: hr_read_all grows past its initial buffer\n");
}

/* hr_close_all_except() closes everything in range but the kept descriptors. */
static void
test_close_all_except(void)
{
  int p[3][2];
  int keep[2];
  int maxfd = 0;
  int i;
  int j;

  for (i = 0; i < 3; i++) {
    assert(pipe(p[i]) == 0);
    for (j = 0; j < 2; j++) {
      /* Never let the sweep touch stdin/stdout/stderr. */
      assert(p[i][j] >= 3);
      if (p[i][j] + 1 > maxfd)
        maxfd = p[i][j] + 1;
    }
  }

  keep[0] = p[0][0];
  keep[1] = p[2][1];

  hr_close_all_except(keep, 2, maxfd);

  assert(fcntl(keep[0], F_GETFD) != -1);
  assert(fcntl(keep[1], F_GETFD) != -1);
  assert(fcntl(p[0][1], F_GETFD) == -1);
  assert(fcntl(p[1][0], F_GETFD) == -1);
  assert(fcntl(p[1][1], F_GETFD) == -1);
  assert(fcntl(p[2][0], F_GETFD) == -1);

  /* stdio is untouched: this print would go nowhere otherwise. */
  assert(fcntl(1, F_GETFD) != -1);
  assert(fcntl(2, F_GETFD) != -1);

  close(keep[0]);
  close(keep[1]);

  printf("Passed: hr_close_all_except keeps only the listed descriptors\n");
}

int
main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  test_roundtrip_hostile_values();
  test_accessors();
  test_base64();
  test_parse_rejects();
  test_read_all();
  test_read_all_grows();
  /* Last: it closes every descriptor this process has above stderr. */
  test_close_all_except();

  printf("All hotreload_wire tests passed.\n");
  return 0;
}
