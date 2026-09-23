# ircu2 Test Harness

Python-based integration test suite for ircu2 using Docker and pytest.

## Prerequisites

- Docker and Docker Compose
- Python 3.10+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
cd tests
uv sync
```

## Running Tests

All commands are run from the `tests/` directory:

```bash
cd tests

# All tests (starts Docker containers automatically)
uv run pytest

# Specific PR tests
uv run pytest pr59_part_messages/
uv run pytest pr61_uhnames/

# Only unit tests (no Docker needed)
uv run pytest test_irc_client.py

# By marker
uv run pytest -m single_server    # tests needing only the hub
uv run pytest -m multi_server     # tests needing hub + 2 leaves
uv run pytest -m tls              # TLS trust / verification tests (hub + TLS leaf)
uv run pytest -m tls_single       # standalone TLS hub (no peer server ever links)
uv run pytest -m nf_compat        # A(prod P10)-B-C rolling-upgrade topology

# TLS suite only
uv run pytest tls/ -v

# TLS suite against a specific TLS backend (default: openssl)
# The tls-hub/tls-leaf images are (re)built with the chosen backend.
TLS_BACKEND=gnutls uv run pytest tls/ -v
TLS_BACKEND=libtls uv run pytest tls/ -v

# P10/P11 rolling-upgrade compat (downloads prod release on first build)
uv run pytest pr_network_features_compat/ -v

All docker topologies (hub-only, full network, TLS, limits, DNS, standalone
TLS hub, NF compat) share one compose project and are mutually exclusive —
each topology brings up only its own containers. `conftest.py`
manages them explicitly: an autouse fixture starts the topology each test
needs and tests are grouped by topology at collection time, so any selection
(`-m`, `-k`, paths) is safe — mixing topologies in one run just costs extra
docker restarts.

## TLS integration tests (`tls/`)

Dedicated Docker services `ircd-tls-hub` and `ircd-tls-leaf` exercise per-block
TLS settings with a private test PKI under `tests/docker/certs/`.

| Test area | What it covers |
|-----------|----------------|
| Client TLS | Plain and TLS user registration on hub/leaf |
| Plaintext rejection | Non-TLS connect to TLS-only ports |
| Inbound S2S fingerprint | Accept matching cert; reject mismatch/self-signed |
| Inbound S2S CA verify | Accept CA-signed peer cert; reject self-signed/rogue CA |
| Outbound S2S | Hub→leaf (fingerprint), leaf→hub (CA + verifypeer) |

Regenerate certificates with `tests/docker/generate-certs.sh` after changing
the PKI. Host ports use the `166xx`/`144xx` range to avoid clashing with
standard IRC ports.

**Note:** Docker images are built with OpenSSL (`--with-tls=openssl`). TLS
listener ports in the test configs set `tls systemca = no` so each port gets
its own listener TLS context at config parse time.

# Verbose with output
uv run pytest -v -s --timeout=60
```

## Test Organization

Each PR has its own directory:

```
irc_client.py          # Async IRC client for client-level testing
p11_server.py          # Fake P11 (or P10) server for server-to-server testing
conftest.py            # pytest fixtures (ircd_hub, ircd_network, make_client)
  pr59_part_messages/
    test_fix.py          # TDD: reproduces the exact bug the PR fixes
    test_edge_cases.py   # Adversarial: tries to break the implementation
  pr61_uhnames/
    test_fix.py
    test_edge_cases.py
  pr62_remote_x/
    test_fix.py              # S2S tests using P11Server for OPMODE +x and ACCOUNT
    test_edge_cases.py
    test_privilege_check.py  # U:line privilege tiers (CONF_UWORLD vs CONF_UWORLD_OPER)
    test_umode_ordering.py   # send_umode_out() / hide_hostmask() ordering
```

- **test_fix.py** — focused tests that reproduce the bug or verify the feature claimed by the PR. These fail on the base branch and pass with the PR applied.
- **test_edge_cases.py** — adversarial tests that exercise boundary conditions, invalid inputs, and feature interactions. Tests that depend on the PR feature use `pytest.skip()` when it's not available.

## Behaviour suites (main-branch changes since 2019)

Besides the per-PR directories, these suites pin down behaviour changes made
directly on the release branch (each module docstring names the commits):

| Path | What it covers |
|------|----------------|
| `chanmodes/` | channel modes +P (no part/quit messages) and +M (moderate unauthed users) |
| `cap/test_cap_list.py`, `cap/test_extended_join.py`, `cap/test_echo_message.py`, `cap/test_cap_edge_cases_main.py` | capability list, extended-join on every JOIN path, echo-message |
| `relay/` | `NOTICE nick@server`, JOIN target limits (`JOIN_TARGET`), CPRIVMSG idle reset |
| `commands/` | WHOWAS `0`, WHOX `%l`, PART, INFO, CONNECT `0`, PRIVS, remote STATS |
| `features/` | Boolean features (`0`/`1`, spellings), HIS_REMOTE, defaults, removed features |
| `s2s/` | server parser robustness (`END_OF_BURST`, bad numerics), GLINE reason/lifetime updates |
| `username/` | ident / WebIRC username handling, STRICT_USERNAME rules |
| `iauth/` | `/STATS iauth` and `/STATS iauthconf`, asynchronous `? stats2`, IAuth line parsing |
| `config/` | `Include` and the configuration lexer via `ircd -k` inside the hub container |

Shared helpers for these live in `common.py` (`join`, `drain`, `whois`,
`set_feature`, ...).  `set_feature()` exists because `SET` only answers when
the value changes and ircu defers a client's commands once its flood penalty
builds up, so "SET + sleep" is racy.

Strict `xfail` markers in `config/test_include.py` document known ircd bugs:
`Include <types> from "file"` is a syntax error (the lexer has no `from`
token), a missing include file makes `ircd -k` hang, and a self-including
file aborts it.

## Docker Topology

Three ircd servers form a test network:

| Service    | Server Name    | Client Port | Server Port | Numeric |
|------------|----------------|-------------|-------------|---------|
| ircd-hub   | hub.test.net   | 6667        | 4400        | 1       |
| ircd-leaf1 | leaf1.test.net | 6668        | 4401        | 2       |
| ircd-leaf2 | leaf2.test.net | 6669        | 4402        | 3       |

leaf2 differs from the others: ident lookups are on (`Client { username = "*" }`),
it runs the non-forcing `docker/iauth-test.pl` (policy `ARUS`, supports `? config` /
`? stats2`) instead of `iauth-tilded.pl`, and port 6691 is a WebIRC port
(`WEBIRC webircpass ...`).  The hub Connect block `notulined.test.net` points at
port 4499 where nothing listens (CONNECT tests).

| ircd-tls-hub  | tls-hub.test.net  | 16677 / 16697 | 14440 / 14441 | 10        |
| ircd-tls-leaf | tls-leaf.test.net | 16678 / 16680 | 14411 / 14412 | 11        |

The TLS containers use certificates under `tests/docker/certs/` (regenerate
with `tests/docker/generate-certs.sh`). Host port 14411 maps to leaf S2S
port 4401; 14412 maps to 4402.

The hub is a HUB server. Leaves autoconnect to the hub. All servers have `NODNS` enabled for fast client registration.

Operator credentials: name `testoper`, password `operpass`.

The hub also has Connect blocks for two external test servers used by the P10 test harness:

| Server              | Numeric | U:lined     | Purpose                              |
|---------------------|---------|-------------|--------------------------------------|
| services.test.net   | 4       | Yes (oper)  | Fake services for S2S testing        |
| notulined.test.net  | 5       | No          | Non-U:lined server for rejection tests |
| uworldonly.test.net | 6       | Yes (no oper) | U:lined without CONF_UWORLD_OPER   |

Configs are baked into the Docker images (in `docker/`), not volume-mounted.

### P10/P11 compat topology (`pr_network_features_compat/`)

Rolling-upgrade guard tests use a dedicated A—B—C chain.  **A** is built from
the current [UndernetIRC/ircu2 release](https://github.com/UndernetIRC/ircu2/releases)
(`Dockerfile` target `runtime-release`, default tag `u2.10.12.19`).  **B** and
**C** are built from the working tree.

| Service   | Server Name      | Binary   | Links            | Client | S2S  | IP         |
|-----------|------------------|----------|------------------|--------|------|------------|
| ircd-nf-a | a.prod.test.net  | release  | P10 (announces J10) | 6674 | 4420 | 10.55.0.40 |
| ircd-nf-b | b.test.net       | tree     | P10 to A, P11 to C | 6675 | 4421 | 10.55.0.41 |
| ircd-nf-c | c.test.net       | tree     | P11 (also HUB)   | 6676   | 4422 | 10.55.0.42 |

The protocol number is negotiated per link from the SERVER line (`J10` /
`J11`); the tree announces J11 and clamps a J10 peer down to P10.  The P11
extensions — message-tag prefixes and TAGMSG, the `+z` TLS fingerprint
parameter, remote `OPMODE +x`, and already-authed `ACCOUNT` updates — are
sent only on P11 links.  `P11Server` announces J11 by default; pass
`protocol=10` to act as a legacy peer.

Services (`P11Server`, numeric 4) attach to **C** (C sets `HUB` so it can
accept that server link).  Assertions check that remote `OPMODE +x`,
already-authed `ACCOUNT` flag updates, and `+z` TLS fingerprint tokens on
NICK/umode bursts never reach **A**.  On **u2.10.12.19 and earlier**, a
second ACCOUNT for an already-authed nick is a hard `protocol_violation`;
**u2.10.13.0** tolerates same-name updates locally.  The ACCOUNT gate is
asserted on the wire via a J10 spy on **B** (`spy.test.net`): over a P10
link, B must not relay a second `AC` for that numnick.  A J11 spy on **C**
(`spyc.test.net`) checks that a flag update after bare-name registration
still leaves C with id+flags over a P11 link.  TOPIC-with-who from the
tree is also checked for prod parse tolerance (topic text still last
param).  Override the release with `IRCD_RELEASE_TAG=...`.

Positive-path checks (TAGMSG / OPMODE +x / ACCOUNT flag update still leave
the hub over a P11 link) live in `test_nf_true_positive.py` on the
standard hub topology, using `notulined.test.net` as a wire spy beside
services.

## IRC Client API

`irc_client.py` provides `IRCClient` — a minimal async IRC client:

```python
from irc_client import IRCClient

client = IRCClient()
await client.connect("127.0.0.1", 6667)
await client.register("nick", "user", "Real Name")

# CAP negotiation (must be called BEFORE register)
acked = await client.negotiate_cap(["userhost-in-names"])

# Send raw IRC commands
await client.send("JOIN #channel")

# Wait for a specific server response
msg = await client.wait_for("366")  # RPL_ENDOFNAMES

# Collect messages until a terminator
msgs = await client.collect_until("366")

# Send and wait for response
msg = await client.send_and_expect("NAMES #channel", "366")
```

`Message` is a namedtuple: `Message(prefix, command, params)`.

## P10 Server API

`p11_server.py` provides `P11Server` — a fake IRC server that connects to ircd on its server port and speaks the P11 protocol (P10 on request). This enables testing server-to-server behavior (OPMODE, ACCOUNT, etc.) that can't be triggered from client connections.

```python
from p11_server import P11Server

srv = P11Server("services.test.net", numeric=4, password="testpass")
await srv.connect("127.0.0.1", 4400)
await srv.handshake()

# Wait for a user to appear (registered after handshake)
numnick = await srv.wait_for_user("somenick")

# Send S2S commands
await srv.send_account(numnick, "AccountName")
await srv.send_opmode(numnick, "+x")

# Read server responses
await srv.drain_messages()

await srv.disconnect()
```

The P10 server handles the full handshake (PASS, SERVER, burst, EB/EA), auto-responds to PINGs, and tracks users by parsing NICK messages. It requires a matching Connect block in the hub config.

## pytest Fixtures

- **`ircd_hub`** (session) — starts the hub container, yields connection info
- **`ircd_network`** (session) — starts all 3 containers, waits for linking
- **`make_client`** (function) — factory for connected+registered IRC clients:
  ```python
  client = await make_client("mynick")
  client = await make_client("mynick", host="127.0.0.1", port=6668)
  client = await make_client("mynick", caps=["extended-join"])  # negotiates CAPs first
  ```
- **`oper`** (function) — a registered global operator (`testop`) on the hub
- **`ulined_server`** (function) — U:lined fake P10 server (`services.test.net`) linked to the hub
- `docker_exec()` / `docker_cp_text()` — run commands / write files inside a test container

## Writing Tests for a New PR

1. Create `pr<N>_<short_name>/`
2. Add `__init__.py`
3. Write `test_fix.py` — reproduce the bug/feature
4. Write `test_edge_cases.py` — try to break it
5. Use `@pytest.mark.single_server` or `@pytest.mark.multi_server`
6. For S2S protocol tests, use `P11Server` to connect as a fake server
7. Use the `/ircu2-test` Claude skill for automated test generation

## Memory checking: sanitizers and valgrind

The docker images can be built with AddressSanitizer / UndefinedBehaviorSanitizer,
and the ircds can be run under valgrind or gdb. Both are driven by environment
variables read by `docker-compose.yml` and `tests/docker/ircd-entrypoint.sh`;
nothing in the test code changes.

```bash
# ASan + UBSan: rebuild the images, then run any subset of the suite
IRCD_SANITIZE=address,undefined docker compose build
IRCD_SANITIZE=address,undefined .venv/bin/pytest -v --tb=short

# valgrind memcheck (20-50x slower; skip the timing-sensitive TLS stress tests)
IRCD_DEBUG=valgrind .venv/bin/pytest -v --tb=short -m "not tls_stress"
```

- `IRCD_SANITIZE` becomes the Dockerfile's `SANITIZE` build arg: every ircd is
  compiled with `-fsanitize=<list> -fno-omit-frame-pointer -g -O1
  -DIRCD_NO_FREELISTS`. `ASAN_OPTIONS` defaults to
  `abort_on_error=1:halt_on_error=1:detect_leaks=0:log_path=/opt/ircu/debug/asan`,
  so a sanitizer hit aborts that ircd, the test fails, and the report is in
  `tests/debug-output/asan.<pid>` (the `pytest_runtest_makereport` hook in
  `conftest.py` also appends it to the failure output). LeakSanitizer is off
  on purpose: ircu never frees its global tables at exit.
- `IRCD_NO_FREELISTS` matters. ircu recycles `struct Client`, `Connection`,
  `SLink`, `Membership`, `DBufBuffer`, `MsgBuf` and `Msg` through private free
  lists, so a use-after-free on any of them never reaches `free()` and is
  invisible to ASan and valgrind alike. With the define each release goes
  through `MyFree()` instead, so the sanitizer's quarantine sees stale
  pointers. It is set automatically for sanitizer builds; it is not meant for
  production.
- `IRCD_DEBUG=valgrind` runs each ircd under
  `valgrind --leak-check=full --track-origins=yes` (`tests/docker/ircd-entrypoint.sh`);
  output lands in `tests/debug-output/valgrind.log`. Leak and fd reports are
  only written when the ircd exits, so bring the stack down with
  `docker compose down` rather than killing it. `IRCD_DEBUG=gdb` is the same
  idea with a gdb wrapper that captures a backtrace on a crash.
- Sanitized and valgrind builds are slower; a few tests with tight deadlines
  (the 5 s TLS handshake timeout, `relay/test_join_target`) can flake under
  them. Re-run those individually before treating a failure as real.

## Troubleshooting

Docker commands must be run from the repo root (where `docker-compose.yml` lives):

```bash
cd ..  # back to repo root

# View server logs
docker compose logs ircd-hub
docker compose logs ircd-leaf1

# Rebuild containers (after code changes)
docker compose build --no-cache

# Manual connection for debugging
docker compose up -d ircd-hub
nc 127.0.0.1 6667

# Stop everything
docker compose down
```
