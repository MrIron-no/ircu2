---
mode: sequential
complexity: medium
type: feature
playwright: false
frontend-design: false
spec-version: 1
created: 2026-09-16T10:22:30+02:00
---

# Plan: P11 server-to-server capability negotiation (CAP)

## Task Description

The `p11-integration` branch introduces protocol P11, where every extension
is gated per link on `Protocol(link) >= 11`. A version number is a linear
ladder: it cannot express optional, experimental, or build-dependent
features. This plan adds a per-link capability exchange to the P11 server
handshake so that future features can be negotiated individually without a
protocol bump.

The exchange is one unprefixed line per side, `CAP :<list>`, sent after the
`SERVER` line and before the burst, **only** on links where the peer has
announced protocol 11 or higher. A P10 peer never sees it. The negotiated set
is the intersection of the two announcements, fixed for the life of the link
and never relayed. The announced list is empty in this release (`CAP :`); the
mechanism ships now so that the first real capability can be added later
without a flag day.

The handshake is **strict**: on a P11 link the first line after `SERVER` must
be `CAP` (or `ERROR`). Anything else closes the link as a protocol violation.
Nothing announcing P11 has been deployed yet, so strictness is safe.

Two side items ride along because they touch the same code:

- A **numeric mask hardening**: the `SERVER` line's numnick mask is read by
  two different rules (collision check vs registration) that only agree when
  its length is 3 or 5. Other lengths silently overwrite another server's
  `server_list` slot. Refuse them.
- The legacy one-character-server numnick form (`YXX`) is **kept**. It is a
  network-wide property (relayed as-is by hubs), not a per-link one, so it
  cannot be deprecated in P11.

## Objective

When this plan is complete:

- Two P11 servers exchange `CAP :` lines between `SERVER` and burst, log the
  negotiated (empty) set, and link exactly as before otherwise.
- A P11 server linking to a P10 peer sends no `CAP` line and bursts
  immediately, byte-for-byte as today.
- A P11 peer that sends anything other than `CAP`/`ERROR` as its first
  post-`SERVER` line is disconnected with a clear reason; a silent peer is
  disconnected by the existing `CONNECTTIMEOUT`.
- A connection parked in the CAP wait cannot receive relayed traffic, cannot
  be duplicated by an oper `CONNECT`, and is resolved by the existing
  collision logic if the same server arrives via another path.
- A `SERVER` line with a numnick mask that is not 3 or 5 valid characters is
  refused.
- P11.md specifies the CAP line grammar and rules.

## Problem Statement

`mr_server()` registers a peer and `server_estab()` bursts to it in one
synchronous call. There is no point in the handshake where both sides know
each other's protocol before the burst begins: the connector sends
`PASS`+`SERVER` blind, and the acceptor bursts as soon as it has sent its own
`SERVER`. Capability negotiation needs a window between `SERVER` and burst
during which the connection is *not yet* a registered server (so it receives
no relayed traffic) but *is* known to opers and to the collision logic.

## Solution Approach

**Deferred registration.** When `mr_server()` sees a peer announcing
protocol 11 or higher, it runs every existing check, sends its own
`PASS`/`SERVER` (acceptor only) and then `CAP :<list>`, and *stops* before
registration. The connection stays in `STAT_UNKNOWN_SERVER` (inbound) or
`STAT_HANDSHAKE` (outbound) with a new `FLAG_SERVER_STAGED` flag and the
parsed `SERVER` data saved on `struct Server`. The connection is hashed by
server name so `connect_server()` and `check_loop_and_lh()` can see it.

Because the connection is unregistered:

- the packet layer keeps handing it to `parse_client()`, which dispatches
  `CAP` to the unregistered-handler column, so the line needs no numeric
  prefix and no packet-layer change;
- it is not in `cli_serv(&me)->down` and fails every `IsServer()` test, so
  no relayed traffic can reach it;
- the existing unregistered-connection `CONNECTTIMEOUT` path in
  `check_pings()` bounds the wait with no new timer.

The unregistered `CAP` handler branches on `FLAG_SERVER_STAGED`: it parses
the peer list, intersects with the local table, stores the bitmask, logs, and
runs the completion half (re-check loop/hub rules, `SetServerYXX`,
`server_estab()` registration and burst). `parse_client()` refuses any other
command from a staged connection.

Handshake:

```
A (connector)                          B (acceptor)
PASS, SERVER ... J11 ...        -->
                                <--    PASS, SERVER ... J11 ..., CAP :<B list>
                                       (B stages, waits)
A stages, sends CAP :<A list>   -->    B intersects, registers, bursts
A receives CAP, intersects, registers, bursts
```

If either `SERVER` announces 10, that side registers immediately as today.

## Relevant Files

- `ircd/m_server.c` — `mr_server()` (inbound and outbound SERVER handling),
  `ms_server()` (relayed introductions), `check_loop_and_lh()`,
  `parse_protocol()`, `set_server_flags()`. Staging, completion, mask
  validation, and the new `mr_server_cap()` live here.
- `ircd/s_serv.c` — `server_estab()`: currently sends PASS/SERVER (acceptor),
  registers (`SetServer`, `hAddClient`, `add_dlink` to `me->down`,
  introduces the server to other links) and bursts. Split into send half and
  completion half.
- `ircd/m_cap.c` — `m_cap()`, the unregistered/client `CAP` entry point. Gets
  the staged-server branch at its top (before the `parc < 2` check).
- `ircd/parse.c` — `parse_client()`: the strict gate goes right after the
  `msg_tree_parse()` lookup (around line 999), before the handler is chosen.
- `ircd/m_error.c` — `mr_error()` ignores ERROR unless Handshake/Connecting;
  must also accept it from a staged inbound.
- `ircd/s_bsd.c` — `connect_server()` "already in progress" check (line
  ~1044) must treat a staged connection like Handshake.
- `ircd/numnicks.c` / `include/numnicks.h` — add `is_valid_numeric_mask()`.
- `include/client.h` — `FLAG_SERVER_STAGED` and its macros.
- `include/struct.h` — `struct Server`: `caps`, staged fields.
- `include/handlers.h` — `mr_server_cap()` prototype.
- `include/s_serv.h` — `server_estab_send()` prototype.
- `ircd/Makefile.in` — add `servcap.c` to both source lists (lines ~122
  and ~490 region, alphabetically next to `s_conf.c`/`send.c`).
- `ircd/test/Makefile.am` — register the new unit tests.
- `tests/p10_server.py` — the Python S2S stub; gains CAP support and a
  listening mode.
- `tests/docker/ircd-hub.conf`, `tests/docker/ircd-leaf1.conf`,
  `tests/docker/ircd-leaf2.conf` — LOG feature for the network subsystem,
  hub Connect block for the sidecar stub, hub `CONNECTTIMEOUT`.
- `tests/tls/bogus_peer.py` — reference for the sidecar-container pattern
  (`SidecarBogusServer`, `_test_network()`), copied not imported.
- `doc/P11.md`, `doc/readme.cap.md`, `doc/p10.md` — documentation.

### New Files

- `include/servcap.h`, `ircd/servcap.c` — capability table, announce string,
  parser/intersection, name renderer.
- `ircd/test/servcap_t.c` — unit test for the parser with an injected table.
- `ircd/test/numnick_mask_t.c` — unit test for `is_valid_numeric_mask()`.
- `tests/s2s/test_cap_handshake.py` — acceptor-side integration tests (stub
  connects to the hub).
- `tests/s2s/cap_stub_main.py` — entry point run inside the sidecar
  container: a listening P10Server that emits JSON events on stdout.
- `tests/s2s/cap_sidecar.py` — `SidecarCapStub` helper that runs
  `cap_stub_main.py` in a `python:3-alpine` container on the test network.
- `tests/s2s/test_cap_handshake_outbound.py` — connector-side and
  multi-server integration tests.

## Implementation Phases

### Phase 1: Foundation

Teach the test stub to speak the new line (harmless against the current
server, which drops it), and build the pure capability module with its unit
test. Then split `server_estab()`/`mr_server()` into send and completion
halves with no behaviour change.

### Phase 2: Core Implementation

Enable the wait for P11 peers, add the staged `CAP` handler, the strict gate,
the log line, and the in-progress/collision awareness. Add the acceptor-side
integration tests. Add the numeric mask hardening.

### Phase 3: Integration & Polish

Give the stub a listening mode in a sidecar container, cover the
connector-side path, crossed connects and CONNECT-during-wait on the docker
network, write the P11.md section, review, validate.

## Step by Step Tasks

### 1. Stub: send and record CAP in the client (connecting) role
- **Task ID**: stub-cap-client
- **Depends On**: none
- **Description**:
  - In `tests/p10_server.py`, add constructor parameters to `P10Server`:
    `caps: str = ""` (our announced list, space separated), `send_cap: bool
    = True`, `first_line: str | None = None` (if set, this exact line is sent
    in place of our CAP line — used to provoke the strict gate),
    `numnick_mask: str | None = None` (overrides the computed mask verbatim).
  - Add attributes: `self.peer_protocol: int | None`, `self.peer_cap_line:
    str | None` (the hub's raw CAP line), `self.peer_caps: str` (its trailing
    parameter, `""` if none), `self.handshake_order: list[str]` (tokens
    `"SERVER"`, `"CAP"`, `"BURST"` appended as the hub's SERVER, CAP and first
    non-CAP post-SERVER line arrive).
  - In `begin_handshake()`: after sending our SERVER, read lines. When the
    hub's `SERVER` arrives (first token `SERVER`, no prefix), parse its
    protocol from the field matching `[JP](\d+)` and store
    `peer_protocol`, append `"SERVER"`. If `peer_protocol >= 11` and
    `self.protocol >= 11`: if `first_line` is set send it verbatim; elif
    `send_cap` send `f"CAP :{self.caps}"` (so the default is the literal
    `CAP :`). Do this immediately after the hub's SERVER is seen, before
    reading further. When a line whose first token is `CAP` arrives, store
    `peer_cap_line`, set `peer_caps` to the text after the first `:` (or
    `""`), append `"CAP"`. On the first other post-SERVER line append
    `"BURST"` once. Continue until `EB` as today.
  - Keep `handshake()`, `send_end_of_burst()`, `complete_handshake()`
    semantics unchanged for existing callers.
  - Run the existing S2S suite to prove the stub change is harmless against
    the current server (the hub currently drops the unprefixed `CAP :` in
    `parse_server()`'s unknown-prefix path).
- **Files**:
  - modifies: `tests/p10_server.py`
- **Tests**:
  - `cd tests && .venv/bin/pytest s2s/ commands/ -q` must pass unchanged.
  - Extend `tests/test_irc_client.py`-style pure unit coverage is not
    available for the stub; correctness of the new attributes is asserted by
    task 4's integration tests.

### 2. Capability module and unit test
- **Task ID**: servcap-module
- **Depends On**: stub-cap-client
- **Description**:
  - Create `include/servcap.h`:
    ```c
    typedef unsigned int servcap_t;              /* one bit per capability */
    struct ServCapEntry {
      const char *name;                          /* lowercase [a-z0-9/-], <= 63 chars */
      servcap_t   bit;
      int (*parse_value)(const char *value);     /* NULL: bare name only; else returns 1 if understood */
    };
    extern const struct ServCapEntry servcap_table[];   /* terminated by name == NULL */
    #define SERVCAP_NAME_MAX 63
    size_t servcap_announce(char *buf, size_t len);      /* our list; "" in this release */
    servcap_t servcap_parse(const char *list, const struct ServCapEntry *table);
    size_t servcap_names(servcap_t caps, char *buf, size_t len, const struct ServCapEntry *table);
    #define HasServCap(cptr, cap) ((cli_serv(cptr)->caps & (cap)) != 0)
    ```
  - Create `ircd/servcap.c` implementing them. `servcap_table[]` contains only
    the terminator in this release. `servcap_announce()` writes `""` and
    returns 0. `servcap_parse()` rules, exactly:
    - Tokens are separated by one or more spaces (0x20). Leading/trailing
      spaces ignored. `NULL` or empty list yields 0.
    - A token is split at the first `=` into name and value (value may be
      empty string if `=` present with nothing after it).
    - A name is valid iff 1..63 chars, each in `a-z`, `0-9`, `-`, `/`.
      Invalid names are ignored.
    - A valid name not in `table` is ignored.
    - Entry with `parse_value == NULL`: set the bit only if the token had no
      `=`. Entry with `parse_value != NULL`: set the bit only if the token had
      `=` and `parse_value(value)` returned non-zero.
    - Duplicate names: the first occurrence decides; later occurrences are
      ignored.
    - Returns the OR of accepted bits.
  - `servcap_names()` writes the space-separated names of set bits in table
    order, `""` if none, returns length written; truncates safely at `len-1`.
  - Add `servcap_t caps;` to `struct Server` in `include/struct.h` after
    `prot`, zeroed by `make_server()` (verify `make_server()` in
    `ircd/s_serv.c` or `ircd/client.c` calloc's or memset's the struct; if it
    does not, set the field explicitly there).
  - Add `servcap.c` to the two source lists in `ircd/Makefile.in`
    (alphabetically, next to `send.c`). Check whether `ircd/Makefile.am`
    exists and has the same list; if so, edit both.
  - Create `ircd/test/servcap_t.c`: define a local table
    `{ {"alpha", 1, NULL}, {"beta", 2, NULL}, {"gamma", 4, parse_gamma}, {NULL,0,NULL} }`
    with `parse_gamma` returning 1 only for value `"x,y"`. Follow the style
    of `ircd/test/msgq_excise_t.c` (plain `main()`, counted failures,
    non-zero exit on failure). Register in `ircd/test/Makefile.am`:
    `servcap_t_CPPFLAGS = $(AM_CPPFLAGS) -DIRCU2_BUILD`,
    `servcap_t_SOURCES = servcap_t.c test_stub.c`,
    `servcap_t_LDADD = ../servcap.o ../ircd_string.o` (add other objects only
    if the link requires them), and append `servcap_t` to `check_PROGRAMS`.
    Regenerate `ircd/test/Makefile.in` the same way the tree does it (run
    `automake` from the top level if `Makefile.in` is committed; otherwise
    edit `Makefile.in` by hand mirroring the `tls_io_t` stanza).
- **Files**:
  - creates: `include/servcap.h`, `ircd/servcap.c`, `ircd/test/servcap_t.c`
  - modifies: `include/struct.h`, `ircd/Makefile.in`, `ircd/test/Makefile.am`,
    `ircd/test/Makefile.in`
- **Tests**:
  - `ircd/test/servcap_t.c` cases: empty string -> 0; `NULL` -> 0;
    `"alpha"` -> 1; `"alpha beta"` -> 3; `"  alpha   beta  "` -> 3;
    `"Alpha"` -> 0 (uppercase invalid); `"alpha=1"` -> 0 (bare-only entry
    given a value); `"gamma"` -> 0 (value required); `"gamma=x,y"` -> 4;
    `"gamma=z"` -> 0; `"alpha alpha=1"` -> 1 (first occurrence decides);
    `"alpha=1 alpha"` -> 0; `"unknown alpha"` -> 1; `"draft/foo alpha"` ->
    1; a 64-char name -> ignored; `servcap_names(5)` -> `"alpha gamma"`;
    `servcap_names(0)` -> `""`; `servcap_announce()` -> `""` and 0.
  - `make -C ircd/test check` passes.

### 3. Split registration into send and completion halves (no behaviour change)
- **Task ID**: estab-split
- **Depends On**: servcap-module
- **Description**:
  - `include/client.h`: add `FLAG_SERVER_STAGED` to the flag enum immediately
    before `FLAG_LAST_FLAG` (doc comment: "server handshake staged, awaiting
    CAP"). Add macros `IsServerStaged(x)`, `SetServerStaged(x)`,
    `ClearServerStaged(x)` next to the `IsBurst`/`SetBurst`/`ClearBurst`
    groups.
  - `include/struct.h` `struct Server`: add
    `time_t stage_start_ts;` (peer's start timestamp, parv[3]),
    `time_t stage_recv_time;` (TStime() when SERVER was accepted),
    `char stage_mask[6];` (parv[6] verbatim, max 5 chars + NUL).
  - `ircd/s_serv.c`: create `int server_estab_send(struct Client *cptr,
    struct ConfItem *aconf)` containing exactly the current
    `if (IsUnknown(cptr)) { PASS; SERVER }` block from `server_estab()` and
    returning 0. Remove that block from `server_estab()`. Remove the
    `if (!IsHandshake(cptr)) hAddClient(cptr);` from `server_estab()` (it
    moves to `mr_server`, below). Declare `server_estab_send` in
    `include/s_serv.h`.
  - `ircd/m_server.c` `mr_server()`: after the password check and
    `memset(cli_passwd...)`, keep the first `check_loop_and_lh()` call. Then
    keep `make_server(cptr)`, `timestamp`, `prot`, `ghost`, privs, and
    `set_server_flags()`. Replace the remainder with:
    1. `if (!IsHandshake(cptr)) hAddClient(cptr);` (inbound becomes findable
       by name here; `hRemClient()` in `exit_one_client()` is unconditional so
       any later refusal cleans up).
    2. Save `cli_serv(cptr)->stage_start_ts = start_timestamp;`
       `cli_serv(cptr)->stage_recv_time = TStime();`
       `ircd_strncpy(cli_serv(cptr)->stage_mask, parv[6], 5);`
    3. `server_estab_send(cptr, aconf);`
    4. `return server_complete(cptr);`
  - Add `static int server_complete(struct Client *cptr)` in `m_server.c`
    that does, in this order:
    1. `aconf = find_conf_byname(cli_confs(cptr), cli_name(cptr), CONF_SERVER)`;
       if NULL, `return exit_client_msg(cptr, cptr, &me, "Access denied. No conf line for server %s", cli_name(cptr));`
    2. `ret = check_loop_and_lh(cptr, cptr, &ghost, cli_name(cptr), cli_serv(cptr)->stage_mask, cli_serv(cptr)->timestamp, cli_hopcount(cptr), 1); if (ret != 1) return ret;`
       and store `cli_serv(cptr)->ghost = ghost;`
    3. `SetServerYXX(cptr, cptr, cli_serv(cptr)->stage_mask);`
    4. `check_start_timestamp(cptr, cli_serv(cptr)->timestamp, cli_serv(cptr)->stage_start_ts, cli_serv(cptr)->stage_recv_time);`
    5. `ret = server_estab(cptr, aconf);`
    6. the existing `FEAT_RELIABLE_CLOCK` / `SETTIME` block, using
       `stage_recv_time` in place of `recv_time`.
    7. `compute_secure_path_groups(); return ret;`
  - `check_loop_and_lh()`: the branch
    `else if (IsHandshake(acptr) && acptr == cptr) break;` must also match a
    staged self-find: change to
    `else if ((IsHandshake(acptr) || IsServerStaged(acptr)) && acptr == cptr) break;`
    and change `else if (!IsServer(acptr) && !IsHandshake(acptr))` to
    `else if (!IsServer(acptr) && !IsHandshake(acptr) && !IsServerStaged(acptr))`.
    In this task nothing sets the flag yet, but an **inbound Unknown
    connection is now hashed before `server_complete()` re-runs the check**,
    so the self-find must also accept `IsUnknown(acptr) && acptr == cptr`.
    Write the condition as
    `else if (acptr == cptr && (IsHandshake(acptr) || IsUnknown(acptr))) break;`
    placed **before** the `!IsServer && !IsHandshake` nickname branch, and
    leave that nickname branch reading
    `else if (!IsServer(acptr) && !IsHandshake(acptr) && !IsServerStaged(acptr))`.
  - Behaviour must be identical to before: the P10 and P11 stub paths, the
    docker network autoconnects and the TLS suite must pass unchanged. The
    second `check_loop_and_lh()` call is redundant in this task and must be
    a no-op for a single connection (it finds only `cptr` itself).
- **Files**:
  - modifies: `include/client.h`, `include/struct.h`, `include/s_serv.h`,
    `ircd/s_serv.c`, `ircd/m_server.c`
- **Tests**:
  - `cd tests && .venv/bin/pytest s2s/ commands/ relay/ -q` passes.
  - `cd tests && .venv/bin/pytest -m multi_server -q` passes (autoconnect
    leaves link through the refactored path).
  - `make -C ircd/test check` passes.

### 4. CAP handshake: staging, handler, strict gate, log, in-progress awareness
- **Task ID**: cap-handshake
- **Depends On**: estab-split
- **Description**:
  - `ircd/m_server.c` `mr_server()`: after `server_estab_send()`, if
    `prot >= 11`:
    ```c
    char caps[BUFSIZE];
    servcap_announce(caps, sizeof(caps));
    sendrawto_one(cptr, "CAP :%s", caps);     /* literal "CAP :" this release */
    SetServerStaged(cptr);
    return 0;
    ```
    otherwise `return server_complete(cptr);` as in task 3. Both the acceptor
    (after its PASS/SERVER) and the connector (which sent SERVER earlier in
    `completed_connection()`) reach this point only after seeing the peer's
    protocol, so a P10 peer never receives `CAP`.
  - Add `int mr_server_cap(struct Client *cptr, struct Client *sptr, int parc, char *parv[])`
    in `m_server.c`, prototype in `include/handlers.h`:
    ```c
    const char *list = (parc > 1) ? parv[1] : "";
    char names[BUFSIZE];
    cli_serv(cptr)->caps = servcap_parse(list, servcap_table);
    servcap_names(cli_serv(cptr)->caps, names, sizeof(names), servcap_table);
    log_write(LS_NETWORK, L_NOTICE, LOG_NOSNOTICE,
              "CAP: %s offered [%s] negotiated [%s]", cli_name(cptr), list, names);
    ClearServerStaged(cptr);
    return server_complete(cptr);
    ```
  - `ircd/m_cap.c` `m_cap()`: insert as the very first statement
    `if (IsServerStaged(cptr)) return mr_server_cap(cptr, sptr, parc, parv);`
    (before the `parc < 2` check, since `CAP :` arrives with `parv[1] == ""`
    and a bare `CAP` with `parc == 1`). Include `handlers.h` is already
    present; add `#include "client.h"` if the macro is not visible.
  - `ircd/parse.c` `parse_client()`: immediately after the
    `msg_tree_parse(ch, &msg_tree)` lookup (before the `mptr == NULL` error
    block), add:
    ```c
    if (IsServerStaged(cptr)
        && (!mptr || (strcmp(mptr->cmd, MSG_CAP) && strcmp(mptr->cmd, MSG_ERROR)))) {
      sendto_opmask_butone(0, SNO_OLDSNO,
          "Protocol violation from %s: expected CAP after SERVER, got %s",
          cli_name(cptr), ch);
      log_write(LS_NETWORK, L_NOTICE, LOG_NOSNOTICE,
          "CAP: %s protocol violation, expected CAP after SERVER, got %s",
          cli_name(cptr), ch);
      return exit_client_msg(cptr, cptr, &me,
          "Protocol violation: expected CAP after SERVER, got %s", ch);
    }
    ```
    `ch` is the NUL-terminated command token at that point. Include
    `msg.h` and `s_misc.h` if not already included.
  - `ircd/m_error.c` `mr_error()`: change the first test to
    `if (!IsHandshake(cptr) && !IsConnecting(cptr) && !IsServerStaged(cptr)) return 0;`
  - `ircd/s_bsd.c` `connect_server()`: change
    `else if (IsHandshake(cptr) || IsConnecting(cptr))` to
    `else if (IsHandshake(cptr) || IsConnecting(cptr) || IsServerStaged(cptr))`
    so a staged inbound yields "Connection to %s already in progress".
  - `check_loop_and_lh()`: confirm the task 3 conditions cover a staged
    `acptr` that is *not* `cptr` (falls into the timestamp collision logic,
    which reads `cli_serv(acptr)->timestamp`; `make_server()` has run for a
    staged connection so this is safe).
  - Test configuration:
    - `tests/docker/ircd-hub.conf`, `ircd-leaf1.conf`, `ircd-leaf2.conf`
      `Features` blocks: add `"LOG" = "NETWORK" "FILE" "/tmp/ircd-network.log";`
      (the `ircu` user can write `/tmp` in the container; DPATH-relative
      paths are avoided on purpose).
    - `tests/docker/ircd-hub.conf` `Features`: add `"CONNECTTIMEOUT" = "15";`
      with a comment `# CAP handshake silent-peer test; default is 90`. If the
      full suite shows any registration-time failure caused by this, raise
      it to 30 and adapt the test's wait, do not remove it.
  - Create `tests/s2s/test_cap_handshake.py` (`pytestmark =
    pytest.mark.single_server`), helper `_hub_network_log(hub)` using
    `conftest.docker_exec(hub["container"], "cat", "/tmp/ircd-network.log")`
    and returning `""` when the file does not exist yet. Stub name
    `services.test.net`, `numeric=4`, `password="testpass"`.
- **Files**:
  - modifies: `ircd/m_server.c`, `ircd/m_cap.c`, `ircd/parse.c`,
    `ircd/m_error.c`, `ircd/s_bsd.c`, `include/handlers.h`,
    `tests/docker/ircd-hub.conf`, `tests/docker/ircd-leaf1.conf`,
    `tests/docker/ircd-leaf2.conf`
  - creates: `tests/s2s/test_cap_handshake.py`
- **Tests** (`tests/s2s/test_cap_handshake.py`):
  - `test_hub_sends_empty_cap_between_server_and_burst`: P11 stub, full
    `handshake()`. Assert `srv.peer_cap_line == "CAP :"` and
    `srv.handshake_order[:3] == ["SERVER", "CAP", "BURST"]`.
  - `test_peer_caps_intersect_to_empty_and_are_logged`: stub
    `caps="draft/foo bar=1"`. After `handshake()`, poll up to 5 s until the
    hub log contains the substring
    `CAP: services.test.net offered [draft/foo bar=1] negotiated []`.
  - `test_wrong_first_line_closes_link`: stub `first_line="PING :x"`. Using
    `begin_handshake()` inside `pytest.raises((TimeoutError, ConnectionError, asyncio.IncompleteReadError))`
    or by reading raw lines, assert a line containing
    `ERROR :Closing Link` and `Protocol violation: expected CAP after SERVER, got PING`
    was received and the connection then closed (read returns EOF).
  - `test_bare_cap_is_accepted`: stub `first_line="CAP"` (no parameter);
    link completes (`handshake()` succeeds) and the log shows `offered []`.
  - `test_silent_peer_times_out`: stub `send_cap=False`. Read raw lines with
    a 25 s overall deadline; assert the hub sends `ERROR :Closing Link` with
    `Registration Timeout` and closes, and that it happened no earlier than
    10 s after the stub's SERVER was sent (proves it was the timeout, not the
    gate).
  - `test_p10_peer_receives_no_cap`: stub `protocol=10`. After `handshake()`
    assert `srv.peer_cap_line is None` and
    `srv.handshake_order[:2] == ["SERVER", "BURST"]`.
  - `test_existing_suites_unaffected`: not a test function; run
    `cd tests && .venv/bin/pytest s2s/ commands/ relay/ labeled_response/ -q`
    and `-m multi_server` and confirm green.

### 5. Numeric mask hardening
- **Task ID**: mask-hardening
- **Depends On**: cap-handshake
- **Description**:
  - `ircd/numnicks.c`: add
    `int is_valid_numeric_mask(const char *mask)` returning 1 iff
    `strlen(mask)` is 3 or 5 and every character is in the numnick alphabet
    `A-Za-z0-9[]` (i.e. appears in `convert2y[]`; implement by checking
    `convert2n[c] != 0 || c == 'A'`). Prototype in `include/numnicks.h` with
    a doc comment stating that 3 is the legacy `YXX` form, accepted but never
    emitted.
  - `ircd/m_server.c`: in both `mr_server()` and `ms_server()`, immediately
    after the `prot < atoi(MINOR_PROTOCOL)` check, add
    `if (!is_valid_numeric_mask(parv[6])) return exit_client_msg(cptr, cptr, &me, "Bogus numeric mask (%s)", parv[6]);`
    (in `ms_server()` the offending line came over `cptr`, so the link to
    `cptr` is closed, matching the existing "Bogus server name" handling).
  - Create `ircd/test/numnick_mask_t.c`, register `numnick_mask_t` in
    `ircd/test/Makefile.am` (+ `Makefile.in`) with
    `numnick_mask_t_SOURCES = numnick_mask_t.c test_stub.c` and
    `numnick_mask_t_LDADD = ../ircd_alloc.o ../ircd_string.o ../match.o ../numnicks.o`
    (same objects as `ircd_in_addr_t`, which already links `numnicks.o`).
  - Add to `tests/s2s/test_cap_handshake.py`:
    `test_bogus_numeric_mask_refused`: stub `numnick_mask="ABCD"`; assert an
    `ERROR :Closing Link` line containing `Bogus numeric mask (ABCD)` and EOF.
    `test_legacy_three_char_mask_accepted`: stub `numnick_mask="E]]"`
    (server `E`, capacity `]]`); `handshake()` succeeds. Choose a numeric
    letter not used by any test server (hub is 1 = `B`, leaves 2/3, stub 4/5).
- **Files**:
  - modifies: `ircd/numnicks.c`, `include/numnicks.h`, `ircd/m_server.c`,
    `ircd/test/Makefile.am`, `ircd/test/Makefile.in`,
    `tests/s2s/test_cap_handshake.py`
  - creates: `ircd/test/numnick_mask_t.c`
- **Tests**:
  - `ircd/test/numnick_mask_t.c`: `"ABAAB"` -> 1; `"E]]"` -> 1; `"A"` -> 0;
    `"AB"` -> 0; `"ABCD"` -> 0; `"ABCDEF"` -> 0; `"AB!AB"` -> 0;
    `"AB AB"` -> 0; `""` -> 0.
  - The two new integration tests above; `make -C ircd/test check`.

### 6. Stub listening mode and sidecar container
- **Task ID**: stub-listener-sidecar
- **Depends On**: mask-hardening
- **Description**:
  - `tests/p10_server.py`: add `cap_delay: float = 0.0` to the constructor
    (seconds to wait before sending our CAP in the accepting role). Add
    `async def serve(self, host: str, port: int)` that calls
    `asyncio.start_server()` and stores the server object, and
    `async def accept_handshake(self, timeout: float = 15.0)` used by the
    connection callback: read the peer's `PASS` and `SERVER` (parse
    `peer_protocol` from the `[JP](\d+)` field, append `"SERVER"` to
    `handshake_order`), send `PASS :{password}` and our `SERVER ... J{protocol}
    {mask} +{flags} :{description}` line; if `peer_protocol >= 11 and
    self.protocol >= 11`: `await asyncio.sleep(cap_delay)`, then send
    `first_line` if set else (`send_cap` and `f"CAP :{caps}"`); then read
    lines recording the peer's `CAP` (`peer_cap_line`, `peer_caps`, append
    `"CAP"`) and the first burst line (append `"BURST"`), through `EB`; then
    send our `EB`, wait for `EA`, send `EA`. Set `self.accepted_count`
    incremented per accepted connection. Reuse the existing `_send`/`_recv`
    plumbing by assigning the accepted reader/writer to `self._reader`/
    `self._writer`. A second accepted connection while one is active is
    counted and then closed immediately.
  - Create `tests/s2s/cap_stub_main.py`: argparse `--port` (default 4501),
    `--name` (default `capstub.test.net`), `--numeric` (default 6),
    `--protocol` (default 11), `--caps` (default `""`), `--no-cap`,
    `--first-line`, `--cap-delay` (default 0), `--password` (default
    `testpass`). Runs `P10Server(...).serve("0.0.0.0", port)` and prints one
    JSON object per line to stdout, flushed: `{"event":"listening","port":N}`,
    `{"event":"accepted","n":k}`, `{"event":"line","dir":"in"|"out","text":...}`
    for every line exchanged, `{"event":"closed"}` on EOF. Exits when the
    connection closes and no further connection arrives within 5 s, or on
    SIGTERM.
  - Create `tests/s2s/cap_sidecar.py` with `class SidecarCapStub`, a copy of
    the `SidecarBogusServer` pattern in `tests/tls/bogus_peer.py` (do not
    import it): constants `SIDECAR_IMAGE = "python:3-alpine"`,
    `SIDECAR_NAME = "ircu-cap-stub"`, `SIDECAR_IP = "10.55.0.41"`,
    `SIDECAR_PORT = 4501`; `start()` runs
    `docker run -d --name ... --network <ircu-test-net> --ip 10.55.0.41 -v <tests dir>:/tests:ro -e PYTHONPATH=/tests -w /tests python:3-alpine python -u s2s/cap_stub_main.py <args>`;
    `wait_event(name, timeout)` polls `docker logs` and parses JSON lines
    into `self.events`; `lines_in`/`lines_out` properties; `stop()` runs
    `docker rm -f`.
  - `tests/docker/ircd-hub.conf`: add
    ```
    # Sidecar P11 stub in accepting role (tests/s2s/cap_sidecar.py).
    Connect {
            name = "capstub.test.net";
            host = "10.55.0.41";
            port = 4501;
            password = "testpass";
            class = "Server";
            hub;
            autoconnect = no;
    };
    ```
- **Files**:
  - modifies: `tests/p10_server.py`, `tests/docker/ircd-hub.conf`
  - creates: `tests/s2s/cap_stub_main.py`, `tests/s2s/cap_sidecar.py`
- **Tests**:
  - Smoke: `cd tests && .venv/bin/python -c "import s2s.cap_sidecar, s2s.cap_stub_main"`
    imports cleanly; `python s2s/cap_stub_main.py --help` exits 0.
  - Functional coverage arrives in task 7; the acceptor-side suite from tasks
    4 and 5 must still pass after the stub refactor.

### 7. Connector-side and multi-server integration tests
- **Task ID**: outbound-network-tests
- **Depends On**: stub-listener-sidecar
- **Description**:
  - Create `tests/s2s/test_cap_handshake_outbound.py`. Single-server tests use
    `ircd_hub` plus an oper client (reuse the oper helper pattern from
    `tests/tls/test_tls_bogus_peer.py::_oper` / `tests/commands/test_connect.py`;
    the hub conf's oper block credentials are whatever those tests use). Each
    test starts `SidecarCapStub(...)`, sends `CONNECT capstub.test.net 4501`
    from the oper, and stops the sidecar in `finally`. Multi-server tests are
    marked `pytest.mark.multi_server` and use `ircd_network`.
- **Files**:
  - creates: `tests/s2s/test_cap_handshake_outbound.py`
- **Tests**:
  - `test_outbound_sends_cap_only_after_peer_server`: stub P11 with
    `--caps "draft/foo"`. Assert in the stub's `lines_in` the order is
    `PASS`, `SERVER`, `CAP :`, then burst lines, and that the `CAP :` line
    index is greater than the index of the stub's own `SERVER` in
    `lines_out`-interleaved event order (i.e. the hub did not send CAP until
    it had our SERVER). Assert hub log contains
    `CAP: capstub.test.net offered [draft/foo] negotiated []`.
  - `test_outbound_wrong_first_line_is_violation`: stub
    `--first-line "PING :x"`. Assert stub `lines_in` ends with an
    `ERROR :Closing Link` line containing
    `Protocol violation: expected CAP after SERVER, got PING`, and the oper
    receives a server notice containing `Protocol violation from capstub.test.net`.
  - `test_outbound_to_p10_peer_sends_no_cap`: stub `--protocol 10`. Assert no
    `lines_in` entry starts with `CAP`, and a burst line follows `SERVER`.
  - `test_connect_during_cap_wait_is_refused`: stub `--cap-delay 4`. Send
    `CONNECT`, wait for the stub's `accepted` event, send a second
    `CONNECT capstub.test.net 4501` after 1 s; assert the oper receives a
    notice containing `Connection to capstub.test.net already in progress`,
    and after the link completes the stub reports `accepted` exactly once.
  - `test_network_links_negotiate_cap` (multi_server): after the network
    fixture is up, poll (up to 30 s) each container's `/tmp/ircd-network.log`
    via `docker_exec`; assert the hub log contains
    `CAP: leaf1.test.net offered [] negotiated []` and
    `CAP: leaf2.test.net offered [] negotiated []`, and each leaf log
    contains `CAP: hub.test.net offered [] negotiated []`.
  - `test_crossed_connects_converge` (multi_server): oper on hub issues
    `SQUIT leaf1.test.net :test`; wait until `LINKS` on the hub no longer
    lists leaf1. Then, with `asyncio.gather`, hub oper sends
    `CONNECT leaf1.test.net 4401` and a leaf1 oper sends
    `CONNECT hub.test.net 4400` in the same instant. Within 15 s assert hub
    `LINKS` lists `leaf1.test.net` exactly once and leaf1 `LINKS` lists
    `hub.test.net` exactly once; assert neither container's `docker logs`
    (via `debug_support.docker_logs`) nor network log contains
    `Unknown numeric nick`. Run the case 3 times in a loop inside the test.

### 8. Documentation
- **Task ID**: docs-p11-cap
- **Depends On**: outbound-network-tests
- **Description**:
  - `doc/P11.md`: insert a new section `## 3. Link capabilities (CAP)` after
    `## 2. Negotiation`, renumber the following sections and the table of
    contents. Content, in this order:
    1. Purpose: per-link optional features; version = mandatory baseline
       bundle, a cap = optional/transitional feature; a feature is gated by
       exactly one of version or cap, never both; a later P bump may fold
       mature caps into the baseline.
    2. Wire format, as a fenced block:
       ```
       CAP :<cap> [<cap> ...]
       <cap>   = <name> | <name>=<value>
       <name>  = 1*63( a-z / 0-9 / "-" / "/" )
       <value> = 1*( printable except SP ), "," separates list items
       ```
       Examples: `CAP :kill-split invite-numnick msgtags=account,label,time`
       and `CAP :`.
    3. Rules as a bullet list: unprefixed like PASS/SERVER; sent once,
       immediately after SERVER and only when the peer announced 11 or
       higher (so a P10 peer never sees it); one line is the whole list, no
       continuation, roughly 500 bytes available; `CAP :` or bare `CAP`
       announces the empty set; names lowercase, case-sensitive, unordered,
       first occurrence of a duplicate decides; slash names are namespaced
       (`draft/` for experiments, a fork's short tag for fork-specific caps);
       a value is opaque to the parser, comma-separated for lists, meaning
       defined per cap, and a cap whose value is not understood is treated
       as absent; the link's set is the intersection, fixed for the link's
       life, never relayed in SERVER introductions; the receiver's first
       post-SERVER line on a P11 link must be CAP or ERROR, anything else is
       a protocol violation and the link is closed; silence is bounded by
       the receiver's registration timeout; a CAP line after registration is
       undefined for the sender and ignored by the receiver.
    4. Handshake diagram (the one from Solution Approach above).
    5. Note: "As of u2.11.0 the announced list is empty; the exchange is
       `CAP :` in both directions."
  - `doc/P11.md` former section 4 (Server prefixes): add that PASS, SERVER
    and CAP are the only unprefixed lines and are exchanged before
    registration; add "Numerics are fixed width: two characters for a server,
    five for a client. The legacy one-plus-two form (`Y`/`YXX`) is accepted
    but never emitted, because a hub relays it unchanged and it is therefore
    a network-wide property, not a per-link one. A SERVER numeric mask that
    is not 3 or 5 valid characters is refused."
  - `doc/P11.md` Compatibility section: add a bullet "A P11 server never
    sends CAP to a P10 peer; the P10 handshake is unchanged."
  - `doc/readme.cap.md`: add one line under Overview: "The `CAP` token is
    also used, unprefixed, in the P11 server handshake; see
    [P11.md](P11.md)."
  - `doc/p10.md` command table row for `CAP`: change the note from
    "ignored" to "ignored from a registered server; P11 handshake use, see
    P11.md".
- **Files**:
  - modifies: `doc/P11.md`, `doc/readme.cap.md`, `doc/p10.md`
- **Tests**: N/A (documentation only).

### 9. Code Review
- **Task ID**: review-all
- **Depends On**: docs-p11-cap
- **Description**: Review your own work: re-read every file you changed,
  check for bugs, missing edge cases, security issues, and style problems.
  Fix any issues found before proceeding to validation. Specifically verify:
  - No path lets a staged connection into `cli_serv(&me)->down`, into
    `SetServer()`, or into `SERVER_HANDLER` before `server_complete()`.
  - `exit_client()` on a staged connection (timeout, ERROR, violation, peer
    EOF) frees cleanly: no `server_list` slot (SetServerYXX deferred), hash
    entry removed, no "Link with X established" or "Net junction" notices.
  - The strict gate cannot be bypassed by a `CAP` line carrying message tags
    or leading spaces, and does not fire for non-staged unregistered
    clients (ordinary client `CAP LS` still works, `tests/cap/` green).
  - `mr_server_cap()` handles `parc == 1`, `parv[1] == ""`, and a 500-byte
    list without overflow (`names`/`caps` buffers are `BUFSIZE`).
  - The P10 path in `mr_server()` is byte-for-byte unchanged on the wire.
  - `is_valid_numeric_mask()` is applied in both `mr_server()` and
    `ms_server()` and cannot reject any mask ircu itself emits.
  - Doc grammar matches the parser's actual acceptance rules.

### 10. Final Validation
- **Task ID**: validate-all
- **Depends On**: review-all
- **Description**: Run all validation commands, verify every acceptance
  criterion is met, and report any failure verbatim.

## Documentation Requirements

- `doc/P11.md`: new "Link capabilities (CAP)" section with grammar, rules,
  handshake diagram, and the empty-list note; server-prefix section exception
  for PASS/SERVER/CAP and the fixed-width/legacy numnick statement;
  compatibility bullet. (Task 8.)
- `doc/readme.cap.md`: one-line cross reference to P11.md. (Task 8.)
- `doc/p10.md`: CAP row note. (Task 8.)
- Inline comments: `mr_server()` must carry a short comment block describing
  the staged state and why registration is deferred; `parse_client()` gate
  must reference P11.md; `is_valid_numeric_mask()` must explain the two-rule
  disagreement it prevents; `servcap.h` must document the parse rules in the
  header comment.

## Acceptance Criteria

- `make -C ircd/test check` passes including `servcap_t` and
  `numnick_mask_t`.
- `cd tests && .venv/bin/pytest s2s/ -q` passes, including all tests in
  `test_cap_handshake.py` and `test_cap_handshake_outbound.py`.
- `cd tests && .venv/bin/pytest -q` (full suite, all topologies) passes.
- On a P11 link the wire order is `SERVER`, `CAP :`, first burst line, in
  both directions (proved by `test_hub_sends_empty_cap_between_server_and_burst`
  and `test_outbound_sends_cap_only_after_peer_server`).
- A P10 peer never receives a `CAP` line (both directions).
- A P11 peer sending a non-CAP first line is closed with
  `Protocol violation: expected CAP after SERVER, got <token>`.
- A silent P11 peer is closed with `Registration Timeout` by
  `CONNECTTIMEOUT`.
- `CONNECT` toward a server whose inbound is staged yields
  `Connection to <name> already in progress`.
- Crossed connects converge to one link with no `Unknown numeric nick`.
- A `SERVER` mask of length other than 3 or 5 is refused with
  `Bogus numeric mask (<mask>)`; a 3-character mask still links.
- Each linked server's `/tmp/ircd-network.log` contains one
  `CAP: <peer> offered [...] negotiated [...]` line per P11 link.
- P11.md documents the CAP section as specified in task 8.

## Validation Commands

```
# C build and unit tests (from repo root; configure/make as the tree is already built)
make -C ircd
make -C ircd/test check

# Integration: S2S, commands, relay, client CAP regression
cd tests && .venv/bin/pytest s2s/ commands/ relay/ cap/ labeled_response/ -q

# Integration: multi-server topology
cd tests && .venv/bin/pytest -m multi_server -q

# Full suite (rebuilds docker images from the working tree)
cd tests && .venv/bin/pytest -q
```

## Cleanup

```
docker rm -f ircu-cap-stub 2>/dev/null || true
```
(The sidecar helper removes its own container in `stop()`; this is a safety
net if a test aborted.)

## Notes

- **Why not a blind CAP after SERVER.** A P10 acceptor would parse an
  unprefixed `CAP` as a three-character legacy numnick (`C` + `AP`) and
  either drop it via the unknown-prefix path or misattribute it to a user on
  the server holding numeric `AC`. Sending CAP only after seeing the peer's
  protocol avoids this entirely; it costs the acceptor one round trip.
- **Why not register-then-wait.** Registering before the burst would let
  relayed traffic reach a peer that has not been introduced to the network,
  and the peer would answer with upstream KILLs for unknown numerics.
- **Why `SetServerYXX` is deferred.** It writes the global `server_list`
  slot; two staged connections claiming one numeric would otherwise clobber
  each other before the collision check at completion sees the right
  pointer.
- **YXX is kept on purpose.** `NumNick()` concatenates stored strings, so a
  2.10.10 server's three-character numnicks are relayed unchanged across the
  whole network; dropping acceptance would be a network flag day, not a
  per-link P11 decision.
- **`CONNECTTIMEOUT = 15` in the hub test config** exists only to make the
  silent-peer test run in reasonable time. If it destabilises other tests,
  raise it rather than drop the test.
- **Memory notes relevant to the build**: docker images build from the
  working tree; use `tests/.venv/bin/pytest` (uv is not installed); any
  S2S-relayed behaviour needs a leaf-side observer assertion (here: the leaf
  network log).
- Commit convention on this branch: `P11: <imperative summary>` for protocol
  code, `tests: ...` for test-only commits, `docs: ...` for documentation.
  Task 5 should be its own commit (`P11: refuse a SERVER numeric mask that is
  not 3 or 5 characters`).
