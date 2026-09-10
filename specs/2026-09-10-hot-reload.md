---
mode: delegated
complexity: complex
type: feature
playwright: false
frontend-design: false
spec-version: 1
created: 2026-09-10T12:00:00
branch: feat/hot-reload
---

# Plan: Hot reload with connection survival

## Task Description

Add a `RELOAD` operation to ircu2 that replaces the running binary (upgrade
or plain restart) without disconnecting registered local clients. The
running process squits its server links, closes every connection it cannot
carry, writes a versioned text dump of its state to an unlinked temp file,
runs a pre-flight dry-run load in a forked child, and then `execv()`s the
server binary in place (same PID). Client sockets and listening sockets are
inherited by fd number across the exec. The new process boots normally,
adopts the inherited listeners instead of binding, rebuilds clients and
channels from the dump, and resumes. Bytes that arrive during the handoff
wait in the kernel socket buffers.

TLS connections survive only if the TLS record layer has been offloaded to
the kernel (kTLS). Offload is enabled per session after the handshake on
OpenSSL and GnuTLS builds, behind a feature flag. After the handoff an
inherited TLS connection runs in "raw mode": plain writes, `recvmsg()` reads
that surface TLS control records, close_notify on our close. TLS connections
not offloaded in both directions (and all TLS under libtls or `tls_none`)
are closed gracefully with an ERROR line before the handoff.

This branch (`feat/hot-reload`) is based on `tls-io-refactor` (PR #105),
which introduces `ircd/tls_io.c` as the single TLS I/O core and reduces the
backends to `tls_backend_read/write/handshake/drop` primitives. All TLS work
in this spec builds on that layer, never on `main`'s older TLS code.

## Objective

An oper issues `RELOAD` (or the daemon receives SIGUSR2). Within a few
seconds the same PID is running the binary at `SPATH` with a freshly parsed
config, every registered plaintext, kTLS-offloaded TLS, and WebSocket client
is still connected with identical nick, modes, channels, ops, bans, topics,
oper status and caps, and server links have relinked and re-bursted with
preserved channel timestamps. A failed pre-flight leaves the old process
serving. A corrupt dump at boot degrades to a cold start, never to a crash.

## Problem Statement

Today `RESTART` closes every fd and `execv()`s. Every client is dropped and
every upgrade is a full disconnect. The design note that produced this spec
established that (1) a separate "keeper" process is unnecessary because the
kernel already holds unread bytes and pending accepts, (2) the only genuine
obstacle is the userspace TLS session, and (3) kernel TLS removes that
obstacle. A background probe on this host (Debian trixie, OpenSSL 3.5.6,
kernel 6.12, `tls` module loaded) confirmed every premise; see Notes.

## Solution Approach

Exec-in-place with fd inheritance, plus a versioned text dump. No IPC
protocol, no second daemon, no changes to command handlers, channel code,
the event engines, or the pre-reload TLS data path.

Reload sequence, old process (`server_reload()` in `ircd/hotreload.c`):

1. Refuse with a notice if a reload is already in progress.
2. Notice opers: `Reloading server: <reason>`.
3. For each entry in `LocalClientArray[0..HighestFd]` (skip `&me`):
   - `IsServer`, `IsHandshake`, `IsConnecting`, `IsUnknown`, any status
     other than registered user: `exit_client(cptr, cptr, &me,
     "Server reloading")`. exit_client on a server issues the SQUIT and
     removes remote clients; for unregistered connections it sends
     `ERROR :Closing Link: ... (Server reloading)`.
   - Registered user with `IsTLS` and `!ircd_tls_offloaded(cptr)`:
     `exit_client(cptr, cptr, &me, "Server reloading (TLS session cannot
     be carried over, please reconnect)")`.
   - Registered user with `cli_listing(cptr)`: free the listing (same call
     `m_list.c` uses on QUIT) so no LIST cursor is carried.
4. `flush_connections(0)` once, so the ERROR/QUIT lines go out.
5. `FILE *f = tmpfile()`; clear `FD_CLOEXEC` on `fileno(f)`;
   `hotreload_dump(f)`; `fflush`; `lseek(fd, 0, SEEK_SET)`.
6. Pre-flight: `fork()`. Child: `execv(SPATH, argv_check)` where
   `argv_check` is the original `thisServer.argv` with any existing `-R`,
   `-K` arguments stripped and `-R <fd> -K` appended. Parent: `waitpid`
   with `WNOHANG` polled every 50 ms up to `feature_int(FEAT_RELOAD_TIMEOUT)`
   seconds. Exit status 0 = OK. Otherwise (non-zero, signal, timeout with
   `SIGKILL` of the child): log `LS_SYSTEM L_ERROR`, notice opers
   `Reload aborted: pre-flight check failed (<detail>)`, `fclose(f)`, return
   to the event loop. Server links reconnect on their own.
7. On OK: `lseek(fd, 0, SEEK_SET)` again. For every surviving TLS client
   call `ircd_tls_detach(cptr)` (frees the SSL object silently, leaves the
   socket and its kTLS state untouched). `log_close()`. Close every fd from
   3 to `MAXCONNECTIONS-1` that is not a surviving client fd, a listener fd
   (`fd_v4`/`fd_v6` of every listener in `ListenerPollList`), or the dump
   fd. Then `execv(SPATH, argv_reload)` with `-R <fd>` appended (no `-K`).
8. If `execv` fails: `log_reopen()`, log `L_CRIT`, `exit(8)` (mirrors
   `server_restart`).

New process, `main()` with `-R <fd>`:

1. `parse_command_line` records `reload_fd` and `reload_check`.
2. Skip `close_connections()` and `daemon_init()` entirely when
   `reload_fd >= 0`. `check_pid()` runs normally (the lock was released by
   the exec-time close and is re-acquired by the same PID).
3. Before `init_conf()`: `hotreload_read(reload_fd)` reads every line of
   the dump into memory and validates the `HOTRELOAD` header. On any
   failure: log, close every fd that the header/LISTENER/CLIENT records
   name, and continue as a cold boot (`reload_fd = -1`).
4. During `init_conf()`, `inetport()` in `listener.c` first calls
   `hotreload_claim_listener(family, &addr, port)`; if it returns an fd,
   that fd is used instead of `os_socket()/os_set_listen()` (options and
   `socket_add` still apply).
5. After `init_counters()` and before `event_loop()`:
   `hotreload_apply(reload_check)`. In check mode it loads everything into
   memory without `socket_add`, without timers, without touching IPcheck,
   closes nothing, and then `exit(0)`; any failure `exit(1)`. In real mode
   it adopts connections, rebuilds state, closes unclaimed inherited
   listener fds, resets `cli_lasttime`/`cli_since` on every adopted client
   to `CurrentTime`, sends the opers notice `Server reloaded: <n> clients
   carried over`, frees the in-memory dump, and returns.
6. If the header numeric differs from `cli_yxx(&me)` or the server name
   differs from `cli_name(&me)`: fail (check mode exits 1, so the old
   process aborts the reload with the pre-flight notice).

## Relevant Files

- `ircd/ircd.c` — `main()`, `parse_command_line()` (getopt string
  `options`), `server_restart()` as the model; hooks for `-R`/`-K`.
- `ircd/s_bsd.c` — `add_connection()` (model for adoption), `deliver_it()`,
  `read_packet()`, `update_write()`, `close_connection()`,
  `close_connections()`; `LocalClientArray`, `HighestFd`.
- `ircd/tls_io.c`, `include/tls_io.h` — TLS I/O core (`tls_io_sendv`,
  `tls_io_recv`, `tls_want_writable`, `tls_desired_events`). Raw mode
  branches live here.
- `ircd/tls_openssl.c`, `ircd/tls_gnutls.c`, `ircd/tls_libtls.c`,
  `ircd/tls_none.c`, `include/ircd_tls.h` — backends; gain offload enable,
  `ircd_tls_offloaded()`, `ircd_tls_detach()`.
- `ircd/listener.c` — `inetport()` adoption hook, `ListenerPollList`.
- `ircd/numnicks.c`, `include/numnicks.h` — `SetLocalNumNick()` model for
  `SetLocalNumNickAt()`.
- `ircd/IPcheck.c`, `include/IPcheck.h` — `IPcheck_local_connect()` model
  for `IPcheck_adopt()`.
- `ircd/client.c` — `privtab[]`, `client_report_privs()`; export priv name
  helpers.
- `ircd/m_cap.c`, `include/capab.h` — `capab_list[]`; export cap name
  helpers.
- `ircd/m_restart.c`, `include/msg.h`, `include/handlers.h`,
  `ircd/parse.c` — command registration model for `RELOAD`.
- `ircd/ircd_signal.c` — SIGHUP/SIGINT handlers as the model for SIGUSR2.
- `ircd/ircd_features.c`, `include/ircd_features.h` — `F_B`/`F_I` tables.
- `ircd/s_user.c` — `register_user()` (bookkeeping the loader mirrors),
  `userModeList[]`, `umode_str()`.
- `ircd/channel.c`, `include/channel.h` — `get_channel()`,
  `add_user_to_channel()`, `add_banid()`, `add_invite()`,
  `channel_modes()`, `send_channel_modes()`, `MODE_*` bits, `struct Ban`.
- `ircd/gline.c`, `ircd/jupe.c`, `ircd/sline.c`, `ircd/ircd_netconf.c` —
  `gline_burst()`, `jupe_burst()`, `sline_burst()`, `config_burst()` define
  the field sets; `gline_add()`, `jupe_add()`, `sline_add()`,
  `config_set()` are the loaders.
- `ircd/s_conf.c` — `rehash()` client re-check loop (`find_kill`,
  `conf_check_client`) the loader reuses; `attach_conf`.
- `ircd/test/Makefile.am`, `ircd/test/test_stub.c`, `ircd/test/tls_io_t.c`
  — C unit test conventions (`check_PROGRAMS`, `_LDADD` of `../x.o`).
- `tests/conftest.py`, `tests/irc_client.py`, `tests/irc_ws_client.py`,
  `tests/tls/helpers.py` (`oper_up`, `wait_for_server_link`),
  `tests/debug_support.py` (`docker_exec`), `tests/docker/ircd-tls-hub.conf`
  — docker integration harness. The `ircd_tls_network` fixture brings up
  `ircu-tls-hub` (plaintext 16677, TLS 16697, WebSocket-over-TLS 16700,
  server TLS 14440) and `ircu-tls-leaf`. `/opt/ircu/debug` in the container
  is bind-mounted from `tests/debug-output`.
- `tests/tls/test_tls_keyupdate.py` — must be made kTLS-aware (see Notes).
- `docker-compose.yml`, `Dockerfile` — the container runs `ircd -f conf -n`
  as a direct child of the entrypoint, which is why the PID must not change.

### New Files

- `include/hotreload.h` — public API of the reload subsystem (see task 1).
- `ircd/hotreload_wire.c` — record encoder/decoder, base64, in-memory dump
  reader, fd keep-set helper.
- `ircd/hotreload_dump.c` — `hotreload_dump(FILE *)`.
- `ircd/hotreload_load.c` — `hotreload_read()`, `hotreload_claim_listener()`,
  `hotreload_apply()`.
- `ircd/hotreload.c` — `server_reload()`, `hotreload_dump_to_path()`.
- `ircd/m_reload.c` — `mo_reload()`.
- `include/tls_ktls.h`, `ircd/tls_ktls.c` — raw-mode kTLS I/O.
- `ircd/test/hotreload_wire_t.c`, `ircd/test/tls_ktls_t.c` — C unit tests.
- `tests/hotreload/__init__.py`, `tests/hotreload/test_reload.py`,
  `tests/hotreload/test_reload_tls.py`, `tests/hotreload/test_reload_dump.py`
  — docker integration tests.
- `doc/readme.reload` — operator documentation.

## Implementation Phases

### Phase 1: Foundation
Headers, stubs, flags, features, small helper exports, command
registration, Makefile entries. Everything later builds against these
signatures, so this task is sequential and defines the contract.

### Phase 2: Core Implementation
Three independent workstreams in parallel: kTLS in the backends, raw-mode
I/O in the TLS core, and the wire format. Then dump and load in parallel.

### Phase 3: Integration & Polish
Orchestration (`server_reload`, `main()` hooks, command, signal), docker
tests from the spec, docs, final review, validation.

## Team Members

- Mason
  - **Role**: foundation contracts and final orchestration (`hotreload.c`,
    `ircd.c`, `m_reload.c`)
  - **Agent Type**: builder
- Sable
  - **Role**: TLS backends: kTLS enable, offload query, detach
  - **Agent Type**: builder
- Flint
  - **Role**: raw-mode kTLS I/O in `tls_ktls.c`, `tls_io.c`, `s_bsd.c`
  - **Agent Type**: builder
- Quill
  - **Role**: dump wire format and the dump writer
  - **Agent Type**: builder
- Ember
  - **Role**: dump loader, connection and listener adoption
  - **Agent Type**: builder
- Harper
  - **Role**: docker integration tests written from this spec
  - **Agent Type**: tester
- Vale
  - **Role**: code review after every builder task and final review
  - **Agent Type**: reviewer
- Ridge
  - **Role**: final mechanical validation
  - **Agent Type**: validator

## Review Policy
- **Review After**: each task
- **Fix Loop Trigger**: Critical and Important
- **Max Retries**: 3
- **Skip Review For**: researcher, validator

## Step by Step Tasks

### 1. Foundation contracts
- **Task ID**: foundation
- **Depends On**: none
- **Description**:
  - `include/client.h`: add `FLAG_TLS_RAW` to `enum Flag` (after
    `FLAG_TLS`) with macros `IsTLSRaw(x)`, `SetTLSRaw(x)`,
    `ClearTLSRaw(x)` following the `IsTLS`/`SetTLS` pattern.
  - `ircd/ircd_features.c` + `include/ircd_features.h`: add
    `F_B(TLS_KTLS, 0, 1, 0)` (default TRUE) and
    `F_I(RELOAD_TIMEOUT, 0, 15, 0)` (seconds). Place them next to
    `TLS_SYSTEMCA` and `CLIENT_FLOOD` respectively. Add both to
    `doc/features.txt` with one paragraph each.
  - `ircd/numnicks.c` + `include/numnicks.h`: add
    `int SetLocalNumNickAt(struct Client *cptr, unsigned int index)`.
    Behaves like `SetLocalNumNick()` but uses the given slot in
    `cli_serv(&me)->client_list`; returns 0 and does nothing if the slot is
    occupied or `index > cli_serv(&me)->nn_mask`; on success sets
    `cli_yxx`, stores the pointer, bumps `cli_serv(&me)->clients`
    exactly as `SetLocalNumNick()` does, and returns 1. Also add
    `unsigned int LocalNumNickIndex(const struct Client *cptr)` returning
    the slot index decoded from `cli_yxx`.
  - `ircd/IPcheck.c` + `include/IPcheck.h`: add
    `void IPcheck_adopt(struct Client *cptr)`: find-or-create the registry
    entry for `cli_ip(cptr)` exactly as `IPcheck_local_connect()` does, but
    apply no throttle or clone check; increment `connected` and call
    `SetIPChecked(cptr)`. Must pair with `IPcheck_disconnect()` later.
  - `ircd/client.c` + `include/client.h`: export
    `void client_privs_to_string(const struct Client *cptr, char *buf,
    size_t len)` (space-separated priv names from `privtab[]`, same order
    as `client_report_privs`) and
    `int client_privs_from_string(struct Client *cptr, const char *names)`
    (clears all privs then sets each named priv; unknown names are ignored
    and counted; returns the number of unknown names).
  - `ircd/m_cap.c` + `include/capab.h`: export
    `void cap_set_to_string(capset_t set, char *buf, size_t len)` (space
    separated cap names from `capab_list[]`) and
    `capset_t cap_set_from_string(const char *names)` (unknown names
    ignored).
  - `include/hotreload.h`: declare, with one doc comment each:
    ```c
    struct hr_record { const char *type; unsigned int nkeys;
                       const char *keys[64]; const char *values[64]; };
    /* wire (hotreload_wire.c) */
    void hr_rec_begin(FILE *out, const char *type);
    void hr_rec_add(FILE *out, const char *key, const char *value);
    void hr_rec_add_int(FILE *out, const char *key, long long value);
    void hr_rec_add_b64(FILE *out, const char *key, const void *data, size_t len);
    void hr_rec_end(FILE *out);
    int  hr_parse_line(char *line, struct hr_record *rec);   /* in place; 1 ok, 0 malformed */
    const char *hr_get(const struct hr_record *rec, const char *key);   /* NULL if absent */
    long long hr_get_int(const struct hr_record *rec, const char *key, long long dflt);
    size_t hr_b64_decode(const char *src, unsigned char *dst, size_t dstlen); /* (size_t)-1 on error */
    struct hr_lines { char **line; unsigned int count; };
    int  hr_read_all(int fd, struct hr_lines *out);           /* reads to EOF, splits on \n, 1 ok */
    void hr_free_lines(struct hr_lines *lines);
    void hr_close_all_except(const int *keep, unsigned int nkeep, int maxfd);
    /* dump (hotreload_dump.c) */
    int  hotreload_dump(FILE *out);                            /* 1 ok, 0 on write error */
    /* load (hotreload_load.c) */
    int  hotreload_read(int fd);                               /* 1 ok; 0 => caller cold-boots */
    int  hotreload_pending(void);                              /* 1 while a read dump awaits apply */
    int  hotreload_claim_listener(int family, const struct irc_in_addr *addr, int port); /* fd or -1 */
    int  hotreload_apply(int check_only);                      /* 1 ok, 0 failure */
    /* orchestration (hotreload.c) */
    void server_reload(const char *reason);
    int  hotreload_dump_to_path(const char *path);             /* 1 ok */
    extern int hotreload_fd;      /* -1 unless booted with -R */
    extern int hotreload_check;   /* 1 when booted with -K */
    ```
  - `include/tls_ktls.h`: declare
    ```c
    enum tls_ktls_record { TLS_KTLS_DATA, TLS_KTLS_CLOSE_NOTIFY, TLS_KTLS_FATAL };
    enum tls_ktls_record tls_ktls_classify(int record_type, const unsigned char *payload, size_t len);
    IOResult tls_ktls_recv(int fd, char *buf, unsigned int length, unsigned int *count_out, int *closed_out);
    int tls_ktls_send_close_notify(int fd);   /* 1 sent, 0 not sent */
    int tls_ktls_supported(void);             /* 1 when built with SOL_TLS support */
    ```
  - Create compiling stubs: `ircd/hotreload_wire.c`, `ircd/hotreload_dump.c`,
    `ircd/hotreload_load.c`, `ircd/hotreload.c`, `ircd/tls_ktls.c`, each
    defining every function from its header with a body that returns the
    failure value (and `hotreload_fd = -1`, `hotreload_check = 0`). Add all
    five to `ircd_SOURCES` in `ircd/Makefile.am` (the `tls_ktls.c` entry is
    unconditional; it compiles to no-ops without `SOL_TLS`).
  - `ircd/m_reload.c`: `mo_reload()` modelled on `mo_restart()`: requires
    `PRIV_RESTART`; `RELOAD` with no argument logs
    `"Server RELOAD by %#C"` at `L_NOTICE` and calls
    `server_reload("received RELOAD")`; `RELOAD DUMP <path>` calls
    `hotreload_dump_to_path(parv[2])` and replies with
    `sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :State dumped to %s", sptr,
    path)` or `"%C :Dump failed: %s"` with `strerror(errno)`. Any other
    argument: `send_reply(sptr, ERR_NEEDMOREPARAMS, "RELOAD")`. Register
    `MSG_RELOAD "RELOAD"`, `TOK_RELOAD "RELOAD"`, `CMD_RELOAD` in
    `include/msg.h`, the `msgtab[]` entry in `ircd/parse.c` directly after
    the RESTART entry with the same handler layout (`m_unregistered`,
    `m_not_oper`, `ms_ignore`... copy RESTART's row exactly, replacing
    `mo_restart` with `mo_reload`), the prototype in `include/handlers.h`,
    and `m_reload.c` in `ircd/Makefile.am`.
  - `ircd/ircd_signal.c`: register SIGUSR2 with a callback that calls
    `server_reload("caught signal: SIGUSR2")`, following the SIGHUP pattern
    (own `struct Signal`, counter field in `SignalCounter`).
  - Build must pass: `make -C ircd` and `make -C ircd/test check`.
- **Files**:
  - modifies: include/client.h
  - modifies: ircd/ircd_features.c
  - modifies: include/ircd_features.h
  - modifies: doc/features.txt
  - modifies: ircd/numnicks.c
  - modifies: include/numnicks.h
  - modifies: ircd/IPcheck.c
  - modifies: include/IPcheck.h
  - modifies: ircd/client.c
  - modifies: ircd/m_cap.c
  - modifies: include/capab.h
  - creates: include/hotreload.h
  - creates: include/tls_ktls.h
  - creates: ircd/hotreload_wire.c
  - creates: ircd/hotreload_dump.c
  - creates: ircd/hotreload_load.c
  - creates: ircd/hotreload.c
  - creates: ircd/tls_ktls.c
  - creates: ircd/m_reload.c
  - modifies: include/msg.h
  - modifies: include/handlers.h
  - modifies: ircd/parse.c
  - modifies: ircd/ircd_signal.c
  - modifies: ircd/Makefile.am
- **Tests**: N/A for new logic (registration, stubs, and small helpers
  whose behaviour is pinned by later tasks). Must pass the existing
  `make -C ircd/test check`.
- **Assigned To**: Mason
- **Agent Type**: builder
- **Background**: false

### 2. Review foundation
- **Task ID**: review-foundation
- **Depends On**: foundation
- **Description**: Review task 1 against this spec: every declared
  signature present, stubs compile, `SetLocalNumNickAt` refuses occupied
  slots, `IPcheck_adopt` cannot throttle, RELOAD row in `msgtab` matches
  RESTART's layout.
- **Assigned To**: Vale
- **Agent Type**: reviewer
- **Background**: false

### 3. kTLS in the TLS backends
- **Task ID**: tls-backends-ktls
- **Depends On**: foundation
- **Description**:
  - `include/ircd_tls.h`: declare
    `int ircd_tls_offloaded(const struct Client *cptr)` (1 only when the
    session's send AND receive directions are kernel-offloaded) and
    `void ircd_tls_detach(struct Client *cptr)` (frees the session object
    without sending close_notify and without closing the fd; sets
    `s_tls(&cli_socket(cptr)) = NULL`).
  - `ircd/tls_openssl.c`: in `ircd_tls_accept()` and `ircd_tls_connect()`,
    directly after `SSL_new()`, when `feature_bool(FEAT_TLS_KTLS)` and
    `SSL_OP_ENABLE_KTLS` is defined: `SSL_set_options(tls,
    SSL_OP_ENABLE_KTLS)`. Per session, not on the context, so a runtime
    `SET TLS_KTLS` affects new connections only. `ircd_tls_offloaded()`:
    `BIO_get_ktls_send(SSL_get_wbio(tls)) && BIO_get_ktls_recv(SSL_get_rbio(tls))`
    (0 when either macro is undefined or `s_tls` is NULL).
    `ircd_tls_detach()`: `SSL_set_quiet_shutdown(tls, 1); SSL_free(tls);`
    then NULL the pointer. Verified on this host: SSL_free after quiet
    shutdown writes nothing to the wire and leaves the socket's kTLS state
    intact.
  - `ircd/tls_gnutls.c`: `ircd_tls_offloaded()` returns 1 only if
    `gnutls_transport_is_ktls_enabled()` (available since 3.7.3; guard with
    `#if GNUTLS_VERSION_NUMBER >= 0x030703`) reports both
    `GNUTLS_KTLS_SEND` and `GNUTLS_KTLS_RECV`; GnuTLS enables offload only
    through the system-wide `[global] ktls = true` config, so no per-session
    enable call exists; document this in a comment. `ircd_tls_detach()`:
    `gnutls_deinit()` without `gnutls_bye()`, free any per-session
    credentials the backend allocated, NULL the pointer.
  - `ircd/tls_libtls.c` and `ircd/tls_none.c`: `ircd_tls_offloaded()`
    returns 0; `ircd_tls_detach()` frees the session without close_notify
    (libtls: `tls_free()` without `tls_close()`).
  - When offload is enabled after a successful handshake, log once per
    connection at `DEBUG_DEBUG`: `"kTLS offload for %C: send=%d recv=%d"`.
  - Keep the backend grep invariant from PR #105: backends touch no
    `msgq`, `con_rexmit`, `cli_tls_fingerprint`, `FLAG_*`, or
    `socket_events`.
- **Files**:
  - modifies: include/ircd_tls.h
  - modifies: ircd/tls_openssl.c
  - modifies: ircd/tls_gnutls.c
  - modifies: ircd/tls_libtls.c
  - modifies: ircd/tls_none.c
- **Tests**: N/A at unit level (needs a live handshake; `ircd/test`
  cannot link a backend). Covered by `tests/hotreload/test_reload_tls.py`
  (task 12). The builder must compile with `--with-tls=openssl` and,
  if `libgnutls28-dev` is installed, also `--with-tls=gnutls`.
- **Assigned To**: Sable
- **Agent Type**: builder
- **Background**: true

### 4. Review kTLS backends
- **Task ID**: review-tls-backends
- **Depends On**: tls-backends-ktls
- **Description**: Review task 3. Confirm per-session enable, both-direction
  check, quiet detach, stubs on libtls/none, no invariant breaches.
- **Assigned To**: Vale
- **Agent Type**: reviewer
- **Background**: true

### 5. Raw-mode kTLS I/O
- **Task ID**: tls-raw-mode
- **Depends On**: foundation
- **Description**:
  - `ircd/tls_ktls.c`: implement the header from task 1. Under
    `#if defined(__linux__) && defined(SOL_TLS)` (include `<linux/tls.h>`)
    or `#if defined(__FreeBSD__)` (include `<netinet/tcp.h>`, uses
    `TLS_GET_RECORD` / `TLS_SET_RECORD` on `IPPROTO_TCP`):
    `tls_ktls_recv()` calls `recvmsg()` with a 64-byte control buffer and
    `MSG_DONTWAIT`. If no cmsg or record type 23 (`TLS_RECORD_TYPE_DATA`):
    return `IO_SUCCESS` with `count_out`. Record type 21 (alert): payload
    `{1,0}` (warning, close_notify) or any other alert → `*closed_out = 1`,
    return `IO_SUCCESS` with `count_out = 0` (the caller treats it as EOF).
    Record type 22 (handshake; a KeyUpdate arrives as `18 00 00 01 xx`)
    or any other type → `*closed_out = 1`, `errno = EPROTO`, return
    `IO_FAILURE`. `recvmsg` = 0 → `*closed_out = 1`, `IO_SUCCESS`, 0 bytes.
    `EAGAIN`/`EWOULDBLOCK`/`EINTR` → `IO_BLOCKED`. Other errno →
    `IO_FAILURE`. `tls_ktls_classify()` is the pure function the above uses
    (record type + payload → enum). `tls_ktls_send_close_notify()` sends
    `sendmsg()` with cmsg `TLS_SET_RECORD_TYPE` = 21 and payload `{1, 0}`;
    returns 1 on a 2-byte send. On other platforms all functions compile to:
    `tls_ktls_supported()` = 0, `recv` = plain `recv()` semantics,
    `send_close_notify` = 0.
    Verified on this host: plain `read()` on a kTLS socket with a pending
    control record fails with `EIO` and does not consume it, so raw mode
    must always use `recvmsg`; a raw close_notify via `sendmsg` makes the
    peer's `SSL_read` return `SSL_ERROR_ZERO_RETURN`.
  - `ircd/tls_io.c`: at the top of `tls_io_recv()`: if `IsTLSRaw(cptr)`,
    call `tls_ktls_recv(cli_fd(cptr), ...)`; on `closed_out` with 0 bytes
    return `IO_SUCCESS` with `*count_out = 0` after
    `SetFlag(cptr, FLAG_DEADSOCKET)`... no: mirror what `read_packet()`
    does for plaintext EOF: return `IO_SUCCESS` with 0 bytes and let the
    existing zero-length handling close the connection (check
    `read_packet()`: a 0-byte `IO_SUCCESS` from `os_recv_nonb` is treated
    as EOF via the caller's `length == 0` path; replicate that exact
    contract). On `IO_FAILURE` call the existing `tls_io_fatal()` path
    minus `tls_backend_drop()` (no session exists) — factor a
    `tls_io_mark_dead()` helper. At the top of `tls_io_sendv()`: if
    `IsTLSRaw(cptr)`, delegate to `os_sendv_nonb(cli_fd(cptr), buf,
    count_in, count_out)` and return its result; no `con_rexmit` handling.
    `tls_want_writable()`/`tls_desired_events()`: for raw, return the
    plaintext answer (`base_want_writable`, `READABLE | (want ? WRITABLE :
    0)`).
  - `ircd/s_bsd.c`: `deliver_it()` line ~298 guard becomes
    `IsTLS(cptr) && !IsTLSRaw(cptr) && !s_tls(...)`; line ~319 partial-write
    handling applies when `!IsTLS(cptr) || IsTLSRaw(cptr)`; `read_packet()`
    guard at ~768 likewise; `update_write()` uses the plaintext branch for
    raw; `close_connection()`: when `IsTLSRaw(cptr)` and `cli_fd >= 0`,
    call `tls_ktls_send_close_notify(cli_fd(cptr))` after
    `flush_connections(cptr)` and before `close()`. Grep every `IsTLS(`
    in `s_bsd.c` and `send.c` and decide per site whether raw needs the
    plaintext behaviour; comment each changed site with `/* raw kTLS */`.
  - `ircd/test/tls_ktls_t.c` + `ircd/test/Makefile.am`: add
    `tls_ktls_t` to `check_PROGRAMS` linking `../tls_ktls.o`.
- **Files**:
  - modifies: ircd/tls_ktls.c
  - modifies: ircd/tls_io.c
  - modifies: ircd/s_bsd.c
  - modifies: ircd/send.c
  - creates: ircd/test/tls_ktls_t.c
  - modifies: ircd/test/Makefile.am
- **Tests**: `ircd/test/tls_ktls_t.c`: (a) `tls_ktls_classify` returns
  DATA for 23, CLOSE_NOTIFY for 21 with `{1,0}`, FATAL for 21 with
  `{2,80}`, FATAL for 22 with `{0x18,0,0,1,1}`, FATAL for 20 and 24;
  (b) `tls_ktls_recv` on an `AF_UNIX` socketpair (no ULP, so no cmsg):
  returns `IO_SUCCESS` with the written bytes, `IO_BLOCKED` when empty,
  `IO_SUCCESS`/0 bytes/`closed_out` after the peer closes;
  (c) `tls_ktls_send_close_notify` on an `AF_UNIX` socket returns 0 (the
  sendmsg fails with `EINVAL`/`ENOPROTOOPT`, must not crash). Also extend
  `ircd/test/tls_io_t.c` with one case: a client with `FLAG_TLS_RAW` set
  makes `tls_want_writable()` follow the plaintext rule regardless of
  `con_tls_want_rd/wr`.
- **Assigned To**: Flint
- **Agent Type**: builder
- **Background**: true

### 6. Review raw mode
- **Task ID**: review-tls-raw-mode
- **Depends On**: tls-raw-mode
- **Description**: Review task 5. Check every `IsTLS(` site in `s_bsd.c`
  and `send.c` for raw handling, the EOF contract in `tls_io_recv`, no
  `con_rexmit` use in raw sends, close_notify on close, and that the
  non-Linux/FreeBSD build compiles.
- **Assigned To**: Vale
- **Agent Type**: reviewer
- **Background**: true

### 7. Dump wire format
- **Task ID**: hotreload-wire
- **Depends On**: foundation
- **Description**: Implement `ircd/hotreload_wire.c` per the header.
  - Line format: `TYPE key=value key=value ...\n`. Keys are
    `[A-Za-z0-9_]+`. Values are escaped: backslash → `\\`, space → `\s`,
    newline → `\n`, carriage return → `\r`, `=` is allowed unescaped in
    values, empty value is written as `key=`. `hr_parse_line` splits on
    single spaces, unescapes in place, and rejects lines with more than 64
    keys, a missing `=`, or an empty key. `hr_rec_add_int` formats with
    `%lld`. `hr_rec_add_b64` uses standard RFC 4648 base64 with padding
    (write a local encoder; do not reuse the numnick base64).
  - `hr_read_all` reads until EOF with `read()`, grows a buffer, splits on
    `\n`, ignores a trailing partial line only if empty, and stores
    NUL-terminated copies.
  - `hr_close_all_except` closes every fd in `[3, maxfd)` not present in
    `keep` using a bitmap sized `maxfd`.
- **Files**:
  - modifies: ircd/hotreload_wire.c
  - creates: ircd/test/hotreload_wire_t.c
  - modifies: ircd/test/Makefile.am
- **Tests**: `ircd/test/hotreload_wire_t.c` (`hotreload_wire_t` linked with
  `../hotreload_wire.o ../ircd_string.o ../ircd_alloc.o`): round-trip of a
  record whose values contain spaces, backslashes, `=`, CRLF, and an empty
  value; `hr_get` on absent key → NULL; `hr_get_int` default; base64
  round-trip of 0, 1, 2, 3, 300 bytes and rejection of a corrupt string;
  `hr_parse_line` rejects `TYPE novalue`, `TYPE =x`, and 65 keys;
  `hr_read_all` on a pipe with 3 lines and no trailing newline yields 3
  lines; `hr_close_all_except` on a set of pipes closes exactly the
  non-kept ones (verify with `fcntl(fd, F_GETFD)`).
- **Assigned To**: Quill
- **Agent Type**: builder
- **Background**: true

### 8. Review wire format
- **Task ID**: review-hotreload-wire
- **Depends On**: hotreload-wire
- **Description**: Review task 7 for escaping completeness, buffer bounds
  on long lines (values up to 8 KB must work), and parser rejection paths.
- **Assigned To**: Vale
- **Agent Type**: reviewer
- **Background**: true

### 9. Dump writer
- **Task ID**: hotreload-dump
- **Depends On**: hotreload-wire, tls-backends-ktls, review-hotreload-wire, review-tls-backends
- **Description**: Implement `hotreload_dump(FILE *out)` in
  `ircd/hotreload_dump.c`. Records, in this order, using the exact keys:
  - `HOTRELOAD version=1 server=<cli_name(&me)> numeric=<cli_yxx(&me)>
    pid=<getpid()> time=<CurrentTime> tsoffset=<TSoffset>
    start=<cli_serv(&me)->timestamp>`
  - One `LISTENER` per listener in `ListenerPollList` per bound family:
    `fd= family=<4|6> addr=<ircd_ntoa of listener->addr.addr> port=
    flags=<letters: s server, t tls, w websocket, c cloudflare, i webirc,
    x exempt (use the listener flag names present in listener.h; every
    flag bit gets one letter, documented in a comment)>`.
  - For each local registered user (walk `LocalClientArray`, `IsUser`,
    `cli_fd >= 0`): `CLIENT fd= numnick=<cli_yxx> index=<LocalNumNickIndex>
    nick= user=<cli_user->username> host=<cli_user->host>
    realhost=<cli_user->realhost> sockhost=<cli_sockhost> sockip=<cli_sock_ip>
    ip=<ircd_ntoa(cli_ip)> info=<cli_info> firsttime= lastnick= since=
    lasttime= nextnick= nexttarget= umodes=<umode_str without leading +,
    including account/hiddenhost as umode_str emits them> snomask=
    account=<cli_user->account or absent> acc_id= acc_flags=
    away=<absent if not away> caps=<cap_set_to_string(cli_capab)>
    active=<cap_set_to_string(cli_active)> privs=<client_privs_to_string>
    oper=<1 if IsAnOper> tls=<IsTLS> raw=<1 if IsTLS (it will be raw after
    reload)> tlsfp=<cli_tls_fingerprint or absent> ws=<none|text|binary
    from con->ws_mode> port=<listener port> sendM= receiveM= sendB=
    receiveB= joined=<cli_user->joined> invites=<cli_user->invites>
    targets=<hex of con_targets[MAXTARGETS]> flags=<hex of every bit of
    cli_flags not otherwise represented; document which>`.
    Then for that client: `LINEBUF fd= data=<b64 of con_buffer[0..con_count]>`
    (only if `con_count > 0`); `RECVQ fd= data=<b64 of the full DBuf
    contents, gathered with dbuf_get/dbuf_getmsg-free iteration>` (only if
    non-empty); `SENDQ fd= data=<b64 of con_rexmit[0..con_rexmit_len]
    followed by every byte of con_sendQ via msgq_mapiov>` (only if
    non-empty; note that when con_rexmit points into the head MsgBuf the
    head must not be emitted twice: emit rexmit, then the queue minus the
    portion rexmit covers, using the same `msgq_excise`-style reasoning as
    `tls_io_sendv`); `WS fd= mode= buf=<b64 con_ws_handshake[0..len]>
    skip=<con_ws_skip> keepalive=<con_ws_last_keepalive>` (only for
    WebSocket clients); one `SILENCE fd= mask=<banstr> flags=<flags>
    when=` per entry of `cli_user->silence`; one `INVITE fd= chan=` per
    entry of `cli_user->invited`.
  - For each channel in `GlobalChannelList` that has at least one local
    member: `CHANNEL name= creationtime= modes=<letters via
    channel_modes() with &me as viewer, mode letters only, no leading +>
    limit= key= upass= apass= topic= topic_nick= topic_time= users=`.
    Then `MEMBER chan= fd= status=<letters: o chanop, v voice, d deopped,
    z zombie, b burst-joined, and any other MembershipFlags bit as a
    documented letter> oplevel=` for each local member, in list order;
    `BAN chan= mask=<banstr> who= when= flags=<numeric flags>` for each
    entry of `banlist`.
  - `GLINE mask=<user@host, or #chan, or $R realname form exactly as
    gline_burst() would print> expire= lastmod= lifetime= reason= flags=
    state=<gl_state as int>` for every entry in `GlobalGlineList` and
    `BadChanGlineList` (including local ones).
  - `JUPE server= expire= lastmod= reason= active=<0|1> local=<0|1>`.
  - `SLINE` with every field `sline_burst()` sends, one key per field,
    plus `local=`.
  - `CONFIG key= value= timestamp=` per netconf entry (walk `config_list`
    via a new iteration helper if none is exported; add
    `config_foreach()` to `ircd_netconf.c` if needed and list it in Files).
  - `STATS max_clients=<max_client_count> max_connections=
    <max_connection_count>` followed by one `key=value` pair per field of
    `struct ServerStatistics` using the field name as the key.
  - `END`.
  - Return 0 on any `ferror(out)`.
- **Files**:
  - modifies: ircd/hotreload_dump.c
  - modifies: ircd/ircd_netconf.c
  - modifies: include/ircd_netconf.h
- **Tests**: No unit harness can link the world; the builder must compile
  and run a docker smoke check manually only if no other builder is active
  (the compose project is shared): start `ircd_tls_network`, connect one
  client, `oper_up`, join a channel, set a ban and topic, `RELOAD DUMP
  /opt/ircu/debug/dump.txt`, and eyeball every record type above in
  `tests/debug-output/dump.txt`. The authoritative test is
  `tests/hotreload/test_reload_dump.py` (task 12).
- **Assigned To**: Quill
- **Agent Type**: builder
- **Background**: true

### 10. Dump loader and adoption
- **Task ID**: hotreload-load
- **Depends On**: hotreload-wire, tls-raw-mode, review-hotreload-wire, review-tls-raw-mode
- **Description**:
  - `ircd/s_bsd.c`: add `struct Client *adopt_connection(int fd, struct
    Listener *listener, int is_ws)`: `os_set_nonblocking(fd)`,
    `os_disable_options(fd)`, `make_client(0, STAT_UNKNOWN_USER)`,
    fill `cli_sock_ip`/`cli_sockhost`/`cli_ip` from `os_get_peername`,
    `cli_fd = fd`, `socket_add(&cli_socket, client_sock_callback,
    cli_connect, SS_CONNECTED, 0, fd)`, `FREEFLAG_SOCKET`,
    `cli_listener = listener; ++listener->ref_count`,
    `Count_newunknown(UserStats)`. No IPcheck, no TLS accept, no auth.
    Returns NULL (and closes fd) on failure. Declare in `include/s_bsd.h`.
  - `ircd/listener.c`: in `inetport()`, before `os_socket()`, call
    `hotreload_claim_listener(family, &listener->addr.addr,
    listener->addr.port)`; if `>= 0` skip socket/bind/listen and use that
    fd (still run `set_listener_options` and `socket_add`).
  - `ircd/hotreload_load.c`: `hotreload_read(fd)` uses `hr_read_all`,
    parses every line with `hr_parse_line` into a static array of records,
    validates the first is `HOTRELOAD version=1` (else returns 0 after
    closing every fd named by `LISTENER`/`CLIENT` records), and sets
    `hotreload_pending()` true. `hotreload_claim_listener()` matches an
    unclaimed `LISTENER` record by family, address string and port, marks
    it claimed, and returns its fd. `hotreload_apply(check_only)`:
    1. Header checks: `server` equals `cli_name(&me)`, `numeric` equals
       `cli_yxx(&me)`; else fail. Set `TSoffset` from `tsoffset` and
       `cli_serv(&me)->timestamp` from `start`.
    2. Unclaimed `LISTENER` fds: close (real mode only).
    3. `CONFIG` → `config_set(key, value, timestamp)`. `GLINE` →
       `gline_add(&me, &me, mask, reason, expire - CurrentTime, lastmod,
       lifetime, flags & (GLINE_ACTIVE|GLINE_LOCAL|GLINE_BADCHAN|GLINE_REALNAME))`
       then set `gl_state`; `JUPE` → `jupe_add(...)` with matching
       arguments; `SLINE` → `sline_add(...)`. Check the exact signatures
       in the headers and mirror how `ms_gline`/`ms_jupe`/`ms_sline` call
       them for a burst-sourced entry. Since no server links exist during
       apply, nothing propagates.
    4. `CHANNEL` → `get_channel(&me, name, CGT_CREATE)`, then set
       `creationtime`, `mode.mode` from letters via a local
       letter-to-`MODE_*` table (p s m t i n r D R c C N u M Z z, plus
       `MODE_KEY`/`MODE_LIMIT`/`MODE_APASS`/`MODE_UPASS` when the
       corresponding value keys are present), `mode.limit`, `key`,
       `upass`, `apass`, `topic`, `topic_nick`, `topic_time`.
    5. `CLIENT` → find the listener by `port` (`ListenerPollList` walk; if
       none, use the first listener; if no listeners, fail),
       `adopt_connection(fd, listener, ws != none)`. Then mirror
       `register_user()`'s local bookkeeping in this order: `make_user`,
       copy username/host/realhost/realname/sockhost, `cli_firsttime`,
       `cli_lastnick`, `cli_info`, `cli_ip`, `SetLocalNumNickAt(cptr,
       index)` (fail if 0), `hAddClient`, `add_client_to_list` only if
       `make_client` did not already, `Count_unknownbecomesclient`,
       `SetUser`, `cli_user->server = &me`, umodes via a loop over
       `userModeList[]` letters (setting flags directly; for `+o`/`+O`
       increment `UserStats.opers` and set oper handler, for `+i`
       increment `UserStats.inv_clients`, `+r` account with `acc_id`/
       `acc_flags`, `+x` hidden host), `set_snomask(cptr, snomask,
       SNO_SET)`, `client_privs_from_string`, `cli_capab`/`cli_active`
       via `cap_set_from_string`, `cli_tls_fingerprint`, `SetTLS` and
       `SetTLSRaw` when `raw=1`, `ws_mode`, away (`cli_user->away =
       DupString`), `con_since`/`con_lasttime` = `CurrentTime`,
       `con_nextnick`/`con_nexttarget`, stats counters, `con_targets`,
       `con_handler = IsAnOper ? OPER_HANDLER : CLIENT_HANDLER`,
       `conf_check_client(cptr)`; on `ACR_OK` continue, otherwise
       `exit_client(cptr, cptr, &me, "No longer authorized")` after
       adoption completes for that client (so the ERROR reaches it).
       `find_kill(cptr)` non-zero → exit with `"G-lined"`/`"K-lined"` as
       `rehash()` does. `IPcheck_adopt(cptr)`. Reset `ClearPingSent`.
       `LINEBUF` → copy into `con_buffer`, set `con_count`. `RECVQ` →
       `dbuf_put(&cli_recvQ, data, len)`. `SENDQ` → `msgq_append(0,
       &cli_sendQ, "%s", ...)` is wrong for binary data; add
       `msgq_append_raw(struct MsgQ*, const void*, size_t)` to `msgq.c`
       (splitting into MsgBufs of the largest bucket) and call
       `send_queued(cptr)`-equivalent scheduling via `update_write(cptr)`
       after adoption. `WS` → restore buffer, `con_ws_skip`,
       `con_ws_last_keepalive`. `SILENCE` → rebuild `cli_user->silence`
       entries via `make_ban(mask)` with flags/when. `INVITE` → resolved in
       step 7.
    6. `MEMBER` → `add_user_to_channel(chptr, cptr, flags_from_letters,
       oplevel)`; `BAN` → `add_banid`-equivalent: construct via
       `make_ban(mask)`, set `who`, `when`, `flags`, append to `banlist`
       preserving order (write a small local `channel_append_ban()`;
       `add_banid` does overlap logic that must not run here).
    7. `INVITE` → `add_invite(cptr, chptr)` after all channels exist.
    8. `STATS` → assign `max_client_count`, `max_connection_count`, and
       every `ServerStats->is_*` field by name (a static name→offset
       table).
    9. Recompute `UserStats.channels` (`GlobalChannelList` walk) and any
       counter not explicitly restored; `UserStats.clients` etc. follow
       from the calls above.
    10. In check mode: skip steps 2, `adopt_connection` (use
        `make_client` with `cli_fd = -1` and no `socket_add`),
        `IPcheck_adopt`, `update_write`, and all `exit_client` calls
        (record authorisation failures as counts only). Return 1.
    11. Real mode: `hr_free_lines`, clear pending, return 1. Any hard
        failure mid-way in real mode: log at `L_CRIT` with the offending
        record line number, `exit_client` every adopted client with
        `"Reload failed"`, and return 0 (caller continues as a cold boot
        with listeners already bound).
- **Files**:
  - modifies: ircd/hotreload_load.c
  - modifies: ircd/s_bsd.c
  - modifies: include/s_bsd.h
  - modifies: ircd/listener.c
  - modifies: ircd/msgq.c
  - modifies: include/msgq.h
- **Tests**: `ircd/test/msgq_excise_t.c` gains a case for
  `msgq_append_raw`: 5000 bytes of binary (including NULs and CRLF)
  appended then read back via `msgq_mapiov` equals the input. Loader
  behaviour is covered by `tests/hotreload/` (task 12); the builder must
  not run docker while background tasks are active.
- **Assigned To**: Ember
- **Agent Type**: builder
- **Background**: true

### 11. Review dump and load
- **Task ID**: review-dump-load
- **Depends On**: hotreload-dump, hotreload-load
- **Description**: Review tasks 9 and 10 together: every key the dump
  writes is read by the loader and vice versa (produce a key matrix in the
  review), bookkeeping order versus `register_user()`, no propagation
  side effects, check-mode has no side effects, failure paths free what
  they allocated.
- **Assigned To**: Vale
- **Agent Type**: reviewer
- **Background**: false

### 12. Orchestration and boot hooks
- **Task ID**: hotreload-orchestration
- **Depends On**: review-dump-load
- **Description**:
  - `ircd/hotreload.c`: `server_reload()` exactly as in Solution Approach
    steps 1–8, including argv composition (strip existing `-R <n>` and
    `-K`, append), the pre-flight `waitpid` poll, `ircd_tls_detach` on
    survivors, `hr_close_all_except` with the keep set, `execv(SPATH,...)`.
    `hotreload_dump_to_path(path)`: `fopen(path, "w")`, `hotreload_dump`,
    `fclose`; returns 1 on success.
  - `ircd/ircd.c`: add `R:` and `K` to the getopt `options` string;
    `-R` sets `hotreload_fd = atoi(optarg)`, `-K` sets `hotreload_check = 1`.
    When `hotreload_fd >= 0`: skip `close_connections()` and
    `daemon_init()`; call `hotreload_read(hotreload_fd)` immediately after
    `parse_command_line()` (and `chdir`), and if it returns 0 set
    `hotreload_fd = -1`; call `hotreload_apply(hotreload_check)` after
    `init_counters()` and before `event_loop()`; in check mode `exit(0)`
    on success, `exit(1)` on failure; in real mode close `hotreload_fd`
    afterwards. Update the usage text in `parse_command_line`.
  - Ensure `server_reload()` is reachable from `mo_reload()` and the
    SIGUSR2 handler already registered in task 1 (replace the stub).
  - `tests/docker/ircd-tls-hub.conf` and `ircd-tls-leaf.conf`: no change
    expected; `Operator testoper` is global and therefore holds
    `PRIV_RESTART` by default. If a change is needed, list it.
  - Manual verification (foreground task, docker allowed): bring up
    `ircd_tls_network`, connect a plaintext client and a TLS client, join
    `#reload`, `oper_up` the plaintext one, send `RELOAD`, confirm both
    clients still receive PONG replies, the leaf relinks, and
    `docker logs ircu-tls-hub` shows no crash.
- **Files**:
  - modifies: ircd/hotreload.c
  - modifies: ircd/ircd.c
  - modifies: ircd/m_reload.c
  - modifies: ircd/ircd_signal.c
- **Tests**: The docker scenarios in task 13 are the tests for this task;
  the builder must at minimum run
  `tests/.venv/bin/pytest tests/hotreload -x -k "plaintext"` once task 13
  exists, or reproduce the manual verification above before handing off.
- **Assigned To**: Mason
- **Agent Type**: builder
- **Background**: false

### 13. Docker integration tests
- **Task ID**: test-reload-integration
- **Depends On**: hotreload-orchestration
- **Description**: Write `tests/hotreload/` (package with `__init__.py`)
  using the `ircd_tls_network` fixture (hub + leaf), `IRCClient`,
  `IRCWSClient`, `oper_up`, `wait_for_server_link`, and `docker_exec`.
  Mark with `pytest.mark.tls` and `pytest.mark.asyncio`. Add a
  `hotreload:` line to the markers list in `tests/pyproject.toml` if a new
  marker is used, and a short section to `tests/README.md`.
  - `test_reload.py`:
    - `test_plaintext_clients_survive`: three clients on 16677 join
      `#reload`, one is opped, one voiced, a ban `*!*@banned.example` and
      topic `reload topic` are set; the oper sends `RELOAD`; wait until the
      port answers again; every client sends `PING :after` and receives
      `PONG`; `NAMES #reload` shows the same ops/voices; `MODE #reload b`
      lists the ban; `TOPIC #reload` returns the topic; `WHOIS` of the oper
      shows oper status; `MODE <nick>` for each client matches pre-reload.
    - `test_message_during_handoff_delivered`: client A sends a PRIVMSG to
      B immediately after the oper sends `RELOAD` (before waiting for the
      port); B receives it after the reload.
    - `test_server_link_relinks_with_timestamps`: record `#reload`
      creation TS via `MODE #reload` reply from the leaf side before
      reload; after reload `wait_for_server_link(leaf, hub)`; a leaf-side
      client's `MODE #reload` shows the same creation TS and the hub-side
      op is still op (no net-ride deop).
    - `test_unregistered_connection_gets_error`: a raw socket that has
      sent only `NICK x` receives a line starting with `ERROR :Closing
      Link` containing `Server reloading` and then EOF.
    - `test_caps_and_away_survive`: a client with `CAP REQ :multi-prefix`
      and `AWAY :brb` keeps both (`CAP LIST`, `WHOIS` 301).
    - `test_sigusr2_triggers_reload`: `docker_exec(HUB, "sh", "-c",
      "kill -USR2 $(cat /opt/ircu/lib/ircd-tls-hub.pid)")` (check the
      actual pid file path from `PPATH` in the hub conf) reloads; a client
      survives.
    - `test_reload_twice`: two consecutive reloads; client survives both
      (exercises argv stripping).
    - `test_gline_survives`: oper sets `GLINE +*@1.2.3.4 3600 :test`;
      after reload `STATS G` lists it.
  - `test_reload_tls.py`:
    - `test_tls_client_survives_when_offloaded`: TLS client on 16697 joins,
      reload, PING/PONG works, PRIVMSG round-trips both directions; then
      the client closes and the server-side does not log an error
      (check `docker logs` for `EIO` / assertion text).
    - `test_websocket_tls_client_survives`: `IRCWSClient` on 16700
      (wss) survives with a channel message round-trip after reload.
    - `test_tls_close_after_reload_is_clean`: after reload, the server
      closes a TLS client (oper `KILL`); the client's Python `ssl` read
      raises `SSLZeroReturnError` or returns EOF, never a protocol error.
    - `test_tls_keyupdate_after_reload_closes_cleanly`: reuse
      `tests/tls/keyupdate_peer.py` to send a KeyUpdate after reload; the
      connection is closed by the server and the hub stays responsive for
      another client.
    - `test_tls_not_offloaded_is_disconnected_gracefully`: with
      `SET TLS_KTLS FALSE` (oper, `CONFIG_OPERCMDS` is on) before the TLS
      client connects, then `RELOAD`: the TLS client gets `ERROR` with
      `TLS session cannot be carried over`, the plaintext oper survives;
      `SET TLS_KTLS TRUE` afterwards.
  - `test_reload_dump.py`:
    - `test_dump_roundtrip_is_identical`: populate state (clients,
      channels, bans, topic, invites, silence, away, gline), `RELOAD DUMP
      /opt/ircu/debug/before.txt`, `RELOAD`, `RELOAD DUMP
      /opt/ircu/debug/after.txt`; read both from `tests/debug-output/`,
      drop the `HOTRELOAD` line and the volatile keys `since`, `lasttime`,
      `sendM`, `receiveM`, `sendB`, `receiveB`, `keepalive`, `fd` (fd
      numbers are preserved by exec but must not be relied upon), sort the
      remaining lines, and assert equality.
    - `test_dump_contains_every_record_type`: the before dump contains at
      least one of each: `LISTENER`, `CLIENT`, `CHANNEL`, `MEMBER`, `BAN`,
      `INVITE`, `SILENCE`, `GLINE`, `STATS`, `END`.
  - Update `tests/tls/test_tls_keyupdate.py`: at the start of each test,
    an oper sends `SET TLS_KTLS FALSE` before the KeyUpdate peer connects,
    and `SET TLS_KTLS TRUE` in a `finally`. Add a module docstring
    paragraph explaining that under kernel TLS a peer KeyUpdate is fatal
    on this kernel/OpenSSL combination and is covered by
    `tests/hotreload/test_reload_tls.py`.
- **Files**:
  - creates: tests/hotreload/__init__.py
  - creates: tests/hotreload/test_reload.py
  - creates: tests/hotreload/test_reload_tls.py
  - creates: tests/hotreload/test_reload_dump.py
  - modifies: tests/tls/test_tls_keyupdate.py
  - modifies: tests/pyproject.toml
  - modifies: tests/README.md
- **Tests**: this task is the tests. Run with
  `cd tests && .venv/bin/pytest hotreload tls/test_tls_keyupdate.py -v`.
  Every test must pass against the built tree. Failures that are product
  bugs go back to the responsible builder via the review loop; do not
  weaken assertions to pass.
- **Assigned To**: Harper
- **Agent Type**: tester
- **Background**: false

### 14. Code Review
- **Task ID**: review-all
- **Depends On**: foundation, tls-backends-ktls, tls-raw-mode, hotreload-wire, hotreload-dump, hotreload-load, hotreload-orchestration, test-reload-integration
- **Description**: Review all code changes for correctness, style, edge
  cases, and security. Report issues by severity (Critical, Important,
  Minor). Specifically verify: no fd leak into the exec'd process other
  than the keep set; no double-close of listener fds; `server_reload` is
  re-entrancy guarded; the pre-flight child cannot read from client
  sockets; raw mode never calls a `tls_backend_*` primitive; a cold boot
  after a bad dump closes every named fd; `RELOAD DUMP` path handling
  cannot be abused beyond what `PRIV_RESTART` already allows (document the
  decision); no change to any command handler or channel logic beyond the
  helpers listed.
- **Assigned To**: Vale
- **Agent Type**: reviewer
- **Background**: false

### 15. Final Validation
- **Task ID**: validate-all
- **Depends On**: review-all
- **Description**: Run all validation commands, verify every acceptance
  criterion is met, confirm the documentation listed below exists.
- **Assigned To**: Ridge
- **Agent Type**: validator
- **Background**: false

## Documentation Requirements

- `doc/readme.reload`: what `RELOAD` does, the sequence, what is carried
  and what is dropped (unregistered connections, server links, TLS
  sessions not offloaded, LIST in progress, whowas, IPcheck history,
  in-flight DNS/ident/SASL), the kernel TLS requirements per platform
  (Linux `tls` module; FreeBSD `kern.ipc.tls.enable=1`; OpenSSL 3.x built
  with kTLS; GnuTLS `[global] ktls = true`; libtls unsupported), the
  KeyUpdate limitation, `RELOAD DUMP <path>`, SIGUSR2, `-R`/`-K` flags
  (internal), and the pre-flight/rollback behaviour.
- `doc/features.txt`: `TLS_KTLS` and `RELOAD_TIMEOUT` entries (task 1).
- `doc/example.conf`: a commented `"TLS_KTLS" = "TRUE";` line in the
  Features block with a one-line explanation.
- Inline comments: the record format table at the top of
  `hotreload_dump.c`; the fd keep-set reasoning in `server_reload()`; the
  raw-mode EOF contract in `tls_io_recv()`.
- `tests/README.md`: the `hotreload/` suite and the `tls` kernel module
  prerequisite for the host running docker tests (`sudo modprobe tls`).

## Acceptance Criteria

- `make -C ircd` succeeds with `--with-tls=openssl`; the tree also builds
  with `--with-tls=gnutls` and `--with-tls=none` if the dev packages are
  present.
- `make -C ircd/test check` passes, including the new `hotreload_wire_t`
  and `tls_ktls_t` programs and the extended `msgq_excise_t` and
  `tls_io_t`.
- `cd tests && .venv/bin/pytest hotreload -v` passes every test listed in
  task 13.
- `cd tests && .venv/bin/pytest tls/test_tls_keyupdate.py tls/test_tls_rehash.py tls/test_tls_s2s_burst.py -v` passes.
- After `RELOAD` the hub container's PID 1 chain is intact
  (`docker inspect ircu-tls-hub --format '{{.State.Running}}'` is `true`)
  and the ircd PID inside the container is unchanged.
- A `RELOAD` issued when the binary at `SPATH` fails its pre-flight (test
  by `docker_exec` renaming the config so `init_conf` fails, then
  restoring it) leaves the old process serving and sends the abort notice.
- No file outside the lists in the task `Files` fields is modified,
  except `doc/readme.reload`, `doc/example.conf` and `doc/features.txt`.
- `git diff tls-io-refactor --stat` shows no changes in `ircd/m_*.c`
  other than `m_reload.c` and `m_cap.c`, and none in `ircd/channel.c`.

## Validation Commands

```
make -C ircd
make -C ircd/test check
cd tests && .venv/bin/pytest hotreload -v
cd tests && .venv/bin/pytest tls/test_tls_keyupdate.py tls/test_tls_rehash.py tls/test_tls_s2s_burst.py -v
git diff tls-io-refactor --stat
docker inspect ircu-tls-hub --format '{{.State.Running}}'
```

## Cleanup

```
cd /home/iron/ircu/ircu2 && docker compose down --remove-orphans
rm -f tests/debug-output/before.txt tests/debug-output/after.txt tests/debug-output/dump.txt
```

## Notes

- **Base branch**: `feat/hot-reload` was created from `tls-io-refactor`
  (commit `5a839b1`). Builders work in worktrees of this branch. To build
  in a fresh worktree: `./autogen.sh && ./configure --enable-debug
  --with-maxcon=256 --with-tls=openssl && make -C ircd`. The
  tests need the venv at `tests/.venv` (already present in the main
  checkout; worktrees can symlink it).
- **Docker is a shared resource**: all topologies share one compose
  project. Only foreground tasks (12, 13, 15) may run docker tests.
  Background builders run `make` and `make -C ircd/test check` only.
- **Kernel TLS facts verified on this host** (probe at
  `scratchpad/ktls-probe/probe.c`, OpenSSL 3.5.6, kernel 6.12.101, `tls`
  module loaded via `sudo modprobe tls`): both directions offload for
  TLS 1.2 and 1.3 with default ciphers; `SSL_free` after quiet shutdown
  is wire-silent and leaves the socket's kTLS state intact; plaintext
  application data arrives via `recvmsg` with record type 23; a peer
  close_notify arrives as record type 21 payload `01 00`; plain `read()`
  with a pending control record fails with `EIO` and does not consume it;
  a raw close_notify sent via `sendmsg` makes the peer's `SSL_read`
  return `SSL_ERROR_ZERO_RETURN`; the offloaded fd works unchanged in
  another process; data pipelined behind the client Finished is not
  stranded in userspace.
- **KeyUpdate under kTLS is fatal on kernel 6.12 + OpenSSL 3.5**: the
  kernel cannot rekey (support arrived in 6.14), OpenSSL fails with `no
  suitable record layer` and sends a fatal alert. With `TLS_KTLS` on this
  affects every TLS 1.3 connection, not only reloaded ones. Peer-initiated
  KeyUpdate is effectively unused by IRC clients, so the default stays
  TRUE; operators who need it set `TLS_KTLS` FALSE and accept
  reconnect-on-reload for TLS. This trade must be spelled out in
  `doc/readme.reload`.
- **Why exec-in-place and not fork+exec**: in docker the daemon is the
  direct child of `su` under the entrypoint script, and under systemd
  `Type=simple` the main PID defines the service. A PID change would stop
  the container or the unit. Exec keeps the PID; the pre-flight dry-run in
  a forked child provides the rollback that fork+exec would have given.
- **What is deliberately not carried**: whowas, IPcheck throttle history,
  userload averages, S-line hold queue, in-flight DNS/ident/iauth/SASL/
  uping, LIST cursors, remote users and servers (squit first), any
  connection not yet registered.
- **Numeric or name change**: refused by the pre-flight (`hotreload_apply`
  header check), so an operator cannot reload into a config that renames
  or renumbers the server while clients keep their numnicks.
- **FreeBSD**: raw mode must compile on FreeBSD (`TLS_GET_RECORD` /
  `TLS_SET_RECORD` under `IPPROTO_TCP`, struct `tls_get_record`), but it
  cannot be tested here; the OpenSSL kTLS enable path is identical.
