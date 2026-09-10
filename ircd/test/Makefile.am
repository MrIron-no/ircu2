AM_CPPFLAGS = -I$(top_srcdir)/include -I../..
AM_CFLAGS = -g -Wall

check_PROGRAMS = cidr_lookups_t hotreload_wire_t ircd_chattr_t ircd_in_addr_t ircd_match_t ircd_string_t msgq_excise_t tls_io_t

TESTS = $(check_PROGRAMS)

cidr_lookups_t_CPPFLAGS = $(AM_CPPFLAGS) -DIRCU2_BUILD
cidr_lookups_t_SOURCES = cidr_lookups_t.c test_stub.c
cidr_lookups_t_LDADD = ../cidr_lookups.o ../ircd_alloc.o ../ircd_string.o

hotreload_wire_t_CPPFLAGS = $(AM_CPPFLAGS) -DIRCU2_BUILD
hotreload_wire_t_SOURCES = hotreload_wire_t.c test_stub.c
hotreload_wire_t_LDADD = ../hotreload_wire.o ../ircd_string.o ../ircd_alloc.o

msgq_excise_t_CPPFLAGS = $(AM_CPPFLAGS) -DIRCU2_BUILD
msgq_excise_t_SOURCES = msgq_excise_t.c test_stub.c
msgq_excise_t_LDADD = ../msgq.o ../ircd_snprintf.o ../ircd_alloc.o ../ircd_string.o

tls_io_t_CPPFLAGS = $(AM_CPPFLAGS) -DIRCU2_BUILD
tls_io_t_SOURCES = tls_io_t.c test_stub.c
tls_io_t_LDADD = ../tls_io.o ../msgq.o ../ircd_snprintf.o ../ircd_alloc.o ../ircd_string.o

ircd_chattr_t_SOURCES = ircd_chattr_t.c test_stub.c
ircd_chattr_t_LDADD = ../ircd_string.o

ircd_in_addr_t_SOURCES = ircd_in_addr_t.c test_stub.c
ircd_in_addr_t_LDADD = ../ircd_alloc.o ../ircd_string.o ../match.o ../numnicks.o

ircd_match_t_SOURCES = ircd_match_t.c test_stub.c
ircd_match_t_LDADD = ../ircd_string.o ../match.o

ircd_string_t_SOURCES = ircd_string_t.c test_stub.c
ircd_string_t_LDADD = ../ircd_string.o
