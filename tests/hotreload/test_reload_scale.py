"""Scale and blocked-send-queue integration tests for hot-reload.

The rest of the hotreload/ suite proves RELOAD's *contract* (what must
survive, what must be shed) with 2-3 clients and one channel -- adequate to
show correctness of a single record, but nothing there has ever driven
hotreload_dump()/hotreload_load() with a client/channel graph large enough
to catch a per-record capacity bug, an O(n^2) walk that only hurts at size,
or ambient corruption that a two-client dump could never expose by sheer
volume. Nothing existing exercises RELOAD against a connection whose
*kernel* socket write is genuinely blocked (FLAG_BLOCKED, con_rexmit
holding a partial message) -- the historically fragile path a real
production RELOAD will hit constantly (any client with a slow link) and
that carried a real heap bug during this feature's own development (see
send_queued_zero_credit_leak in project memory).

Three tests:

  * test_many_clients_survive_reload -- a few hundred plaintext clients
    spread across several dozen channels reload cleanly, every one keeps
    its state, and the reload pause is measured and bounded.
  * test_dump_roundtrip_at_scale -- the same dump/reload/dump round trip
    test_reload_dump.py runs at 2-3 clients, run again at ~150 clients /
    ~15 channels to catch anything that only shows up at size.
  * test_blocked_sendq_client_survives_reload -- one victim client is
    throttled at the kernel level (small SO_RCVBUF, connected to the
    container IP so docker-proxy can't launder the throttle away -- see
    the container-IP techniques in test_finding4_repro.py and this
    project's memory) and never reads its socket while a flood of channel
    traffic is pushed at it, so the server's cli_sendQ to that client
    genuinely backs up and blocks. RELOAD must carry that queued,
    unflushed output across the exec() and deliver it intact, in order,
    with the connection still alive, once the victim finally reads.

All three are slow (dominated by connection setup and the flood), so they
carry `pytest.mark.slow` in addition to the suite's `tls`/`hotreload`
markers -- run them explicitly with `-m slow` or as part of the full
`hotreload` directory run; a plain `pytest -m "not slow"` skips them.
"""

from __future__ import annotations

import asyncio
import re
import socket
import subprocess
import time as _time
import uuid

import pytest

from conftest import wait_for_port
from hotreload.helpers import (
    HUB,
    ban_list,
    chan_state,
    get_hub_pid,
    hub_running,
    names_prefixes,
    normalize_dump,
    ping_pong,
    read_system_log,
    umode_string,
    wait_for_reload,
)
from hotreload.test_reload_dump import _cat, _dump_to, _rm
from irc_client import IRCClient
from tls.helpers import oper_up

pytestmark = [pytest.mark.tls, pytest.mark.asyncio, pytest.mark.hotreload, pytest.mark.slow]

# "hot reload: applied: <N> clients, <M> channels, <K> authorisation
# failures" -- ircd/hotreload_load.c, logged to SYSTEM at LS_SYSTEM/L_INFO
# on every real (non-check-only) apply.
_APPLIED_RE = re.compile(
    r"hot reload: applied: (\d+) clients, (\d+) channels, (\d+) authorisation failures"
)


def _hub_container_ip() -> str:
    """The hub container's bridge-network IP (not 127.0.0.1/docker-proxy).

    test_blocked_sendq_client_survives_reload needs the victim's kernel
    receive-window throttle to actually reach the server socket:
    docker-proxy is a userspace relay with its own buffering that absorbs
    well more than this test's flood before ever blocking (see
    test_finding4_repro.py's docstring and the list-pause-repro-technique
    project memory), so the victim must bypass it.
    """
    out = subprocess.run(
        [
            "docker",
            "inspect",
            HUB,
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    ip = out.stdout.strip()
    assert ip, "could not determine hub container IP"
    return ip


async def _disconnect_all(*clients: IRCClient) -> None:
    for c in clients:
        try:
            await c.disconnect()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Bulk client / channel population, shared by the two scale tests.
# ---------------------------------------------------------------------------


async def _register_one(host: str, port: int, nick: str, username: str, realname: str) -> IRCClient:
    c = IRCClient()
    await asyncio.wait_for(c.connect(host, port), timeout=30.0)
    await asyncio.wait_for(c.register(nick, username, realname), timeout=30.0)
    return c


async def _register_batch(
    host: str, port: int, specs: list[tuple[str, str, str]], batch_size: int = 30
) -> list[IRCClient]:
    """Connect+register many clients concurrently, batch_size at a time.

    Fully concurrent (one giant gather) risks the accept()/ident-lookup
    stampede reading like a hang; batching keeps wall-clock sane and any
    single failure's traceback attributable to a small cohort.
    """
    clients: list[IRCClient] = []
    for start in range(0, len(specs), batch_size):
        chunk = specs[start : start + batch_size]
        results = await asyncio.gather(
            *[_register_one(host, port, nick, user, real) for nick, user, real in chunk]
        )
        clients.extend(results)
    return clients


async def _join_and_wait(client: IRCClient, chan: str) -> None:
    await client.send(f"JOIN {chan}")
    await client.collect_until("366")


async def _build_population(
    host: str, port: int, client_count: int, channel_count: int, prefix: str
) -> tuple[list[IRCClient], list[str]]:
    """Register client_count clients and spread them over channel_count
    channels (client_count / channel_count per channel). The first member
    of each channel is its op (auto-opped as first joiner); the next two
    are voiced; each channel gets one ban and one topic, set by its op.
    """
    assert client_count % channel_count == 0, (client_count, channel_count)
    per_channel = client_count // channel_count
    uniq = uuid.uuid4().hex[:6]

    specs = [
        (f"{prefix}{i:03d}", f"u{prefix}{i:03d}", f"Scale {prefix} {i}")
        for i in range(client_count)
    ]
    clients = await _register_batch(host, port, specs)

    channels = [f"#{prefix}c{c}-{uniq}" for c in range(channel_count)]

    async def setup(c: int) -> None:
        chan = channels[c]
        group = clients[c * per_channel : (c + 1) * per_channel]
        leader, members = group[0], group[1:]
        await leader.send(f"JOIN {chan}")
        await leader.collect_until("366")
        if members:
            await asyncio.gather(*[_join_and_wait(m, chan) for m in members])
        for m in members[:2]:
            await leader.send(f"MODE {chan} +v {m.nick}")
            await leader.wait_for("MODE", timeout=20.0)
        await leader.send(f"MODE {chan} +b *!*@banned-{prefix}{c}.example")
        await leader.wait_for("MODE", timeout=20.0)
        await leader.send(f"TOPIC {chan} :{prefix} scale topic {c}")
        await leader.wait_for("TOPIC", timeout=20.0)

    await asyncio.gather(*[setup(c) for c in range(channel_count)])
    return clients, channels


# ---------------------------------------------------------------------------
# 1. Many clients / many channels survive a reload.
# ---------------------------------------------------------------------------

CLIENT_COUNT = 300
CHANNEL_COUNT = 30  # 10 clients/channel
SAMPLE_SIZE = 20


@pytest.mark.timeout(600)
async def test_many_clients_survive_reload(ircd_tls_network):
    """300 clients / 30 channels: RELOAD must apply cleanly, every client
    must survive, a spread sample's state must be byte-identical, and the
    reload pause -- the whole point of measuring at this size -- is
    reported and bounded.

    300 was chosen because it ran reliably (no flakiness across repeated
    runs) in this environment within a few minutes total; see the test
    report for the measured pause. If 300 proves flaky in a different
    environment, the spec's escape hatch is to step down to the largest
    count that runs reliably, no lower than 150.
    """
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]
    per_channel = CLIENT_COUNT // CHANNEL_COUNT
    uniq = uuid.uuid4().hex[:6]

    issuer = IRCClient()
    clients: list[IRCClient] = []
    channels: list[str] = []
    try:
        await issuer.connect(host, port)
        await issuer.register(f"mscissuer{uniq[:4]}", "op", "Scale Reload Issuer")
        assert (await oper_up(issuer)).command == "381"

        clients, channels = await _build_population(host, port, CLIENT_COUNT, CHANNEL_COUNT, "m")

        sample_stride = max(1, CLIENT_COUNT // SAMPLE_SIZE)
        sample_indices = list(range(0, CLIENT_COUNT, sample_stride))[:SAMPLE_SIZE]

        pre_umode: dict[int, str] = {}
        pre_prefix: dict[int, str] = {}
        pre_chan: dict[str, tuple[list[str], str, int]] = {}

        async def record_channel(chan: str) -> None:
            if chan in pre_chan:
                return
            bans = await ban_list(issuer, chan)
            await issuer.send(f"TOPIC {chan}")
            topic_msg = await issuer.wait_for("332", timeout=20.0)
            _, ts = await chan_state(issuer, chan)
            pre_chan[chan] = (bans, topic_msg.params[-1], ts)

        for i in sample_indices:
            c = clients[i]
            chan = channels[i // per_channel]
            pre_umode[i] = await umode_string(c)
            names = await names_prefixes(c, chan)
            pre_prefix[i] = names.get(c.nick, "")
            await record_channel(chan)

        pid_before = get_hub_pid()
        pre_log = read_system_log()

        loop = asyncio.get_running_loop()
        t0 = loop.time()
        await issuer.send("RELOAD")
        await asyncio.to_thread(wait_for_port, host, port, 90.0)
        port_ready_at = loop.time()
        await ping_pong(issuer, f"scale-probe-{uniq}", timeout=60.0)
        reload_pause = loop.time() - t0

        print(
            f"\n[test_many_clients_survive_reload] {CLIENT_COUNT} clients / "
            f"{CHANNEL_COUNT} channels: reload pause = {reload_pause:.3f}s "
            f"(port ready after {port_ready_at - t0:.3f}s)"
        )
        assert reload_pause < 20.0, (
            f"reload pause {reload_pause:.3f}s exceeded the 20s bound at "
            f"{CLIENT_COUNT} clients / {CHANNEL_COUNT} channels"
        )

        # (a) every one of the 300 clients survived and answers its own
        # tagged PING -- batched via gather, not the sequential helper, so
        # this reflects genuine concurrent liveness rather than 300
        # round trips paid one at a time.
        await asyncio.gather(
            *[
                ping_pong(c, f"m-post-{i}-{uniq}", timeout=60.0)
                for i, c in enumerate(clients)
            ]
        )

        # (b) the sampled clients' state is unchanged.
        for i in sample_indices:
            c = clients[i]
            chan = channels[i // per_channel]
            post_umode = await umode_string(c)
            assert post_umode == pre_umode[i], (i, c.nick, pre_umode[i], post_umode)
            names = await names_prefixes(c, chan)
            post_prefix = names.get(c.nick, "")
            assert post_prefix == pre_prefix[i], (i, c.nick, pre_prefix[i], post_prefix, names)

        for chan, (bans, topic, ts) in pre_chan.items():
            post_bans = await ban_list(issuer, chan)
            assert set(post_bans) == set(bans), (chan, bans, post_bans)
            await issuer.send(f"TOPIC {chan}")
            topic_msg = await issuer.wait_for("332", timeout=20.0)
            assert topic_msg.params[-1] == topic, (chan, topic, topic_msg)
            _, post_ts = await chan_state(issuer, chan)
            assert post_ts == ts, (chan, ts, post_ts)

        # (c) the container/process itself: same PID, still running.
        assert hub_running()
        assert get_hub_pid() == pid_before, (pid_before, get_hub_pid())

        # (d) the SYSTEM log recorded exactly this reload applying exactly
        # this many clients and channels, with zero authorisation
        # failures.
        post_log = read_system_log()
        new_log = post_log[len(pre_log):] if post_log.startswith(pre_log) else post_log
        m = _APPLIED_RE.search(new_log)
        assert m, f"no 'hot reload: applied' line in the new SYSTEM log text:\n{new_log[-4000:]}"
        applied_clients, applied_channels, applied_failures = (int(x) for x in m.groups())
        expected_clients = CLIENT_COUNT + 1  # + the issuer
        assert applied_clients == expected_clients, (
            "hot reload applied a different client count than expected -- "
            f"got {applied_clients}, expected {expected_clients} "
            f"({CLIENT_COUNT} scale clients + 1 issuer); log:\n{new_log[-2000:]}"
        )
        assert applied_channels == CHANNEL_COUNT, (
            f"got {applied_channels}, expected {CHANNEL_COUNT}; log:\n{new_log[-2000:]}"
        )
        assert applied_failures == 0, f"log:\n{new_log[-2000:]}"
    finally:
        await _disconnect_all(issuer, *clients)


# ---------------------------------------------------------------------------
# 2. RELOAD DUMP round trip at scale.
# ---------------------------------------------------------------------------

DUMP_CLIENT_COUNT = 150
DUMP_CHANNEL_COUNT = 15  # 10 clients/channel


@pytest.mark.timeout(400)
async def test_dump_roundtrip_at_scale(ircd_tls_network):
    """The dump/reload/dump round trip test_reload_dump.py runs at 2-3
    clients and one or two channels, run again at 150 clients / 15
    channels (plus an invite and a silence entry) to catch anything --
    ordering, a per-record capacity limit, truncation -- that only shows
    up with many records. Reuses the exact normalize_dump()/diff
    machinery test_reload_dump.py uses, just at size.
    """
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]
    uniq = uuid.uuid4().hex[:8]
    before_name = f"scale-before-{uniq}.txt"
    after_name = f"scale-after-{uniq}.txt"

    oper = IRCClient()
    clients: list[IRCClient] = []
    try:
        await oper.connect(host, port)
        await oper.register("rlsc2op", "op", "Scale Dump Oper")
        assert (await oper_up(oper)).command == "381"

        clients, channels = await _build_population(
            host, port, DUMP_CLIENT_COUNT, DUMP_CHANNEL_COUNT, "d"
        )

        # One invite, on a dedicated invite-only channel (not part of the
        # main population) -- matches test_reload_dump.py's coverage of
        # the INVITE record type.
        inviter, invitee = clients[0], clients[1]
        inv_chan = f"#dinv-{uniq}"
        await inviter.send(f"JOIN {inv_chan}")
        await inviter.collect_until("366")
        await inviter.send(f"MODE {inv_chan} +i")
        await inviter.wait_for("MODE", timeout=20.0)
        await inviter.send(f"INVITE {invitee.nick} {inv_chan}")
        await inviter.wait_for("341", timeout=20.0)

        # One SILENCE entry.
        silencer = clients[2]
        silence_reply = await silencer.silence(f"*!*@dscalesilence-{uniq}.example")
        assert silence_reply.command == "SILENCE", silence_reply

        _rm(before_name)
        await _dump_to(oper, before_name, timeout=30.0)

        await oper.send("RELOAD")
        await wait_for_reload(host, port, [(oper, f"dscale-op-{uniq}")], pong_timeout=60.0)

        _rm(after_name)
        await _dump_to(oper, after_name, timeout=30.0)

        before_text = _cat(before_name)
        after_text = _cat(after_name)
        before_lines = normalize_dump(before_text)
        after_lines = normalize_dump(after_text)

        if before_lines != after_lines:
            import difflib

            diff = "\n".join(
                difflib.unified_diff(
                    before_lines,
                    after_lines,
                    fromfile="before (normalized, sorted)",
                    tofile="after (normalized, sorted)",
                    lineterm="",
                )
            )
            raise AssertionError(
                f"dump mismatch across reload at {DUMP_CLIENT_COUNT} clients / "
                f"{DUMP_CHANNEL_COUNT} channels ({len(before_lines)} before-lines, "
                f"{len(after_lines)} after-lines); diff (head):\n{diff[:8000]}"
            )
    finally:
        _rm(before_name)
        _rm(after_name)
        await _disconnect_all(oper, *clients)


# ---------------------------------------------------------------------------
# 3. A client with a genuinely blocked server-side sendQ survives a reload.
# ---------------------------------------------------------------------------

FLOOD_CLIENTS = 8
LINES_PER_CLIENT = 40
_PAD = "X" * 250
# Class Local's sendq is 160000 bytes (tests/docker/ircd-tls-hub.conf); the
# flood below targets roughly 100-110KB of queued output to the victim --
# comfortably enough to overwhelm a kernel receive window throttled to a
# couple KB, comfortably under the hard "Max SendQ exceeded" kill.
_SENDQ_EVIDENCE_THRESHOLD = 5000  # bytes; see _stats_sendq_bytes below
# The victim connects to the container's *internal* plaintext port (6677,
# tests/docker/ircd-tls-hub.conf), not the host-published one (16677):
# it must land straight on the bridge network, bypassing the docker-proxy
# relay entirely, or the SO_RCVBUF throttle below never reaches the real
# server socket.
_HUB_INTERNAL_PLAINTEXT_PORT = 6677

# The flood clients register on the hub's dedicated "Flood"-class port
# (tests/docker/ircd-tls-hub.conf) instead of the normal client port: the
# default (Local-class) maxflood is only 1024 bytes of outstanding recvQ,
# tuned for one line at a time, and this test's many-line-per-connection
# flood can legitimately land several lines in a single read() before the
# event loop drains them, which trips "Excess Flood" and kills the flood
# client -- a self-inflicted failure unrelated to what is under test (the
# victim's server-side sendQ). The published host port for it is
# docker-compose.yml's 16710:6710 mapping.
_FLOOD_PORT = 16710


def _numeric(line: str) -> str | None:
    """Return an IRC line's numeric reply code (e.g. "001"), or None.

    Lines are "[:prefix ]CODE ...". Only ever called on server-sourced
    lines here (the victim never sends itself anything but NICK/USER/JOIN/
    PONG), so a plain split is enough -- no need for irc_client.parse_message.
    """
    parts = line.split(" ")
    idx = 1 if line.startswith(":") else 0
    if idx < len(parts) and parts[idx].isdigit():
        return parts[idx]
    return None


class _RawVictim:
    """A raw, throttled, *synchronous blocking* socket IRC connection.

    Deliberately not asyncio.open_connection()/StreamReader: an asyncio
    transport wrapping a socket keeps reading from it in the background
    (into its own, much larger, internal buffer) as soon as the socket is
    readable, regardless of whether application code ever calls
    reader.readline() -- discovered the hard way, as the reason an earlier
    revision of this test never saw a nonzero server-side sendQ no matter
    how much was flooded at the victim: asyncio itself was quietly
    draining the kernel receive window we were trying to starve. A plain
    blocking socket only ever reads when one of this class's methods is
    called, and every call here is explicit and awaited via
    loop.run_in_executor from the async test body -- so "the test does
    not read victim_reader" genuinely means the kernel receive window
    (throttled by SO_RCVBUF) goes unconsumed.
    """

    def __init__(self, ip: str, port: int, rcvbuf: int = 2048) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self._sock.settimeout(15.0)
        self._sock.connect((ip, port))
        self._buf = b""

    def send_line(self, line: str) -> None:
        self._sock.sendall(line.encode() + b"\r\n")

    def send_raw(self, data: bytes) -> None:
        self._sock.sendall(data)

    def readline(self, timeout: float) -> str:
        """Blocking read of exactly one CRLF-terminated line, answering
        any PING transparently (including the server's pre-registration
        "authorization ping", sent before any NICK/USER numerics)."""
        while True:
            line = self._readline_raw(timeout)
            if line.startswith("PING"):
                cookie = line.split(":", 1)[-1] if ":" in line else line.rsplit(" ", 1)[-1]
                self.send_line(f"PONG :{cookie}")
                continue
            return line

    def _readline_raw(self, timeout: float) -> str:
        self._sock.settimeout(timeout)
        while b"\r\n" not in self._buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionError("victim connection closed unexpectedly")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\r\n", 1)
        return line.decode("utf-8", errors="replace")

    def drain_through_numerics(self, wanted: set[str], timeout: float) -> list[str]:
        deadline = _time.monotonic() + timeout
        lines: list[str] = []
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"victim stream never produced a numeric in {wanted}; "
                    f"last lines: {lines[-5:]}"
                )
            line = self.readline(remaining)
            lines.append(line)
            if _numeric(line) in wanted:
                return lines

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


async def _stats_sendq_bytes(oper: IRCClient, nick: str, timeout: float = 15.0) -> int | None:
    """STATS l * <nick>; return the SendQ byte count from
    RPL_STATSLINKINFO (211), or None if the nick never appeared (e.g.
    already disconnected).

    m_stats.c's parv layout for "stats l" is
    `<selector> [<target-server>] [<mask>]` -- the name filter is the
    *third* token (parv[3]), not the second: "STATS l <nick>" alone puts
    the nick in the target-server slot instead (silently defaulting the
    mask to none, so stats_links() emits only its header row and no data
    -- discovered the hard way while writing this test). "*" as the
    target-server means "this server".
    """
    await oper.send(f"STATS l * {nick}")
    deadline = asyncio.get_running_loop().time() + timeout
    sendq: int | None = None
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError("STATS l never reached 219 (RPL_ENDOFSTATS)")
        msg = await oper.recv(timeout=remaining)
        if msg.command == "211" and len(msg.params) >= 3 and msg.params[1] == nick:
            sendq = int(msg.params[2])
        elif msg.command == "219":
            return sendq


@pytest.mark.timeout(300)
async def test_blocked_sendq_client_survives_reload(ircd_tls_network):
    """A victim client that never reads its socket accumulates a real,
    server-side blocked sendQ (FLAG_BLOCKED, con_rexmit holding a partial
    write -- see ircd/hotreload_dump.c's SENDQ record and the
    send_queued_zero_credit_leak bug this carried during development).
    RELOAD must carry that queue across the exec() and deliver it intact,
    in order, once the victim reads again, with the connection still
    alive throughout.

    Technique (see also test_finding4_repro.py and this project's
    list-pause-repro-technique memory): connect the victim to the hub
    container's *bridge IP*, not the published 127.0.0.1 port --
    docker-proxy is a userspace relay whose own buffering absorbs this
    test's flood without ever blocking the real server socket -- with
    SO_RCVBUF set small before connecting, then never call recv() on it
    again until after the reload. Many other clients flood a shared
    channel the victim is in; because nothing ever drains the victim's
    receive window, the server's software sendQ to it backs up for real.

    KNOWN INTERMITTENT FAILURE (observed ~2026-09-10, ~40-50% of runs on
    this branch, HEAD c78077f/c9620e6): the pre-RELOAD blocked sendQ is
    reliably built (STATS l consistently shows ~97-98KB, well over
    _SENDQ_EVIDENCE_THRESHOLD, every run) and the SYSTEM log always
    reports "hot reload: applied: ... 0 authorisation failures" -- but on
    a substantial fraction of runs the victim connection goes silent
    forever after the reload: no data, no EOF/RST, the fresh liveness
    PING never gets a PONG even after a 90s read budget. When it does not
    reproduce, the whole backlog (all FLOOD_CLIENTS*LINES_PER_CLIENT
    messages, in order, no dupes) plus the liveness PONG all arrive
    normally, usually within a couple of seconds of the reload. This is
    NOT a bug in this test (verified by stashing every test-infra change
    this file's task introduced and re-running an adjacent, pre-existing
    hotreload test -- unaffected; and by reproducing the same signature
    outside pytest against a manually-held container). The leading
    candidate is the write-interest re-arm path for an adopted connection
    whose sendQ is nonempty: ircd/hotreload_load.c's post-adoption loop
    (`if (MsgQLength(&cli_sendQ(fdmap[i]))) update_write(fdmap[i]);`,
    hr_apply_clients()) calls ircd/s_bsd.c's update_write() ->
    socket_events(), which for a client freshly socket_add()-ed by
    adopt_connection() (s_bsd.c) is now the *second* interest-mask change
    on that fd before the event loop has ever run (the first being
    adopt_connection()'s own SOCK_EVENT_READABLE arm) -- worth
    instrumenting ircd/engine_epoll.c's engine_set_events()/EPOLL_CTL_MOD
    call for this fd specifically to see whether the kernel ever actually
    gets asked for EPOLLOUT on the runs that hang. Left as a strict,
    unweakened assertion (not xfail) per this task's instructions: this
    is exactly the class of adoption-time bug the dump/load rewrite was
    supposed to guard against, and coverage should keep failing until
    it's fixed, not paper over it.
    """
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]
    uniq = uuid.uuid4().hex[:8]
    chan = f"#sqblock-{uniq}"
    victim_nick = f"sqv{uniq[:5]}"
    marker = f"MARKER-{uniq}"

    oper = IRCClient()
    flooders: list[IRCClient] = []
    victim: _RawVictim | None = None
    try:
        await oper.connect(host, port)
        await oper.register("rlsqop", "op", "SendQ Block Oper")
        assert (await oper_up(oper)).command == "381"
        await oper.send(f"JOIN {chan}")
        await oper.collect_until("366")

        # --- victim: raw, throttled, *synchronous blocking* socket
        # connected straight to the container IP (see _RawVictim's
        # docstring for why not asyncio.open_connection). ---
        ip = _hub_container_ip()
        loop = asyncio.get_running_loop()
        victim = await loop.run_in_executor(
            None, _RawVictim, ip, _HUB_INTERNAL_PLAINTEXT_PORT, 2048
        )
        await loop.run_in_executor(
            None, victim.send_line, f"NICK {victim_nick}\r\nUSER v 0 * :SendQ Victim"
        )
        # Drain the full registration burst through end-of-MOTD (376) or
        # no-MOTD (422), same terminator set IRCClient.register() uses.
        await loop.run_in_executor(
            None, victim.drain_through_numerics, {"376", "422"}, 20.0
        )

        await loop.run_in_executor(None, victim.send_line, f"JOIN {chan}")
        await loop.run_in_executor(None, victim.drain_through_numerics, {"366"}, 20.0)

        # From here on the test does NOT touch the victim's socket again
        # until after the reload: the whole point is to let the kernel
        # receive window (throttled to 2048 bytes of SO_RCVBUF) go
        # unconsumed -- a plain blocking socket, unlike an asyncio
        # transport, never reads on its own.

        flood_specs = [
            (f"sqflood{i:02d}", f"f{i}", f"SendQ Flood {i}") for i in range(FLOOD_CLIENTS)
        ]
        flooders = await _register_batch(host, _FLOOD_PORT, flood_specs, batch_size=FLOOD_CLIENTS)
        await asyncio.gather(*[_join_and_wait(f, chan) for f in flooders])

        async def flood_one(client: IRCClient, idx: int) -> None:
            for j in range(LINES_PER_CLIENT):
                await client.send(f"PRIVMSG {chan} :flood|{idx}|{j:04d}|{_PAD}")

        await asyncio.gather(*[flood_one(f, i) for i, f in enumerate(flooders)])

        # The marker is queued behind the flood -- sent only once every
        # flood client's send loop has completed -- so its arrival after
        # the reload proves the backlog ahead of it was carried, not just
        # skipped over.
        await oper.send(f"PRIVMSG {chan} :{marker}")

        # Confirm the server-side sendQ to the victim is genuinely
        # nonzero (poll briefly -- the flood's PRIVMSGs are processed
        # asynchronously by the server relative to this oper connection).
        sendq_bytes = None
        deadline = loop.time() + 15.0
        while loop.time() < deadline:
            sendq_bytes = await _stats_sendq_bytes(oper, victim_nick)
            if sendq_bytes and sendq_bytes >= _SENDQ_EVIDENCE_THRESHOLD:
                break
            await asyncio.sleep(0.5)

        if not sendq_bytes or sendq_bytes < _SENDQ_EVIDENCE_THRESHOLD:
            pytest.xfail(
                "could not build a substantial blocked server-side sendQ in "
                f"this environment (STATS l {victim_nick} last showed "
                f"{sendq_bytes!r} bytes, wanted >= {_SENDQ_EVIDENCE_THRESHOLD}) "
                "-- kernel socket buffering absorbed the flood before "
                "blocking; see the test's docstring for the technique "
                "attempted (container-IP + SO_RCVBUF=2048 + a genuine "
                f"~{FLOOD_CLIENTS * LINES_PER_CLIENT}-message flood)"
            )

        print(
            f"\n[test_blocked_sendq_client_survives_reload] blocked server-side "
            f"sendQ to victim before RELOAD: {sendq_bytes} bytes "
            f"(evidence threshold {_SENDQ_EVIDENCE_THRESHOLD}, class ceiling 160000)"
        )
        pid_before = get_hub_pid()
        expected_total = FLOOD_CLIENTS * LINES_PER_CLIENT

        await oper.send("RELOAD")
        await wait_for_reload(host, port, [(oper, f"sq-op-{uniq}")], pong_timeout=60.0)

        assert hub_running()
        assert get_hub_pid() == pid_before, (pid_before, get_hub_pid())

        # Now, and only now, start reading the victim's backlog. The
        # marker is not guaranteed to be the literal last byte the server
        # ever queues for the victim (it was sent from a different
        # connection than the flood, and the server has no obligation to
        # interleave separate connections' input in wall-clock send
        # order) -- so this is one continuous drain, not "stop at the
        # marker": the postcheck PING is fired the moment the marker is
        # seen, but reading keeps going (recording any further flood
        # lines too) until the PONG for it turns up, so a PONG queued
        # behind remaining backlog is not mistaken for a dead connection.
        received: dict[int, list[int]] = {}
        marker_seen = False
        postcheck = f"postreload-{uniq}"
        postcheck_sent = False
        found_pong = False
        lines_seen = 0
        read_deadline = loop.time() + 90.0
        while loop.time() < read_deadline and not found_pong:
            line = await loop.run_in_executor(
                None, victim.readline, max(0.5, read_deadline - loop.time())
            )
            lines_seen += 1
            if not marker_seen and marker in line:
                marker_seen = True
                continue
            if marker_seen and not postcheck_sent:
                # First line read *after* the marker: safe to fire the
                # liveness probe now -- any earlier and a slow drain could
                # still misread it as "dead" while backlog is legitimately
                # still arriving.
                await loop.run_in_executor(None, victim.send_line, f"PING :{postcheck}")
                postcheck_sent = True
            # The server's reply to a client-initiated PING is source-
            # prefixed (":tls-hub.test.net PONG ... :<cookie>"), so a
            # startswith("PONG") check (right for the *unprefixed* PING
            # the server itself sends -- see readline() above) would
            # never match it.
            if " PONG " in f" {line} " and postcheck in line:
                found_pong = True
                continue
            fm = re.search(r"flood\|(\d+)\|(\d+)\|", line)
            if fm:
                idx, j = int(fm.group(1)), int(fm.group(2))
                received.setdefault(idx, []).append(j)

        assert marker_seen, (
            f"victim never received the post-reload marker {marker!r} within "
            f"the read timeout ({lines_seen} lines seen); the pre-reload "
            "blocked sendQ was not delivered -- backlog lost across RELOAD"
        )
        assert found_pong, (
            "victim connection did not survive the reload (no PONG after "
            f"the marker, {lines_seen} lines seen total) -- connection was "
            "not dropped outright (no EOF/reset), but stopped answering"
        )

        # Per-sender order and completeness: every sender's indices must
        # arrive as an unbroken 0..N-1 run -- any gap, reorder, or
        # duplicate fails this.
        for idx, seq in received.items():
            assert seq == list(range(len(seq))), (
                f"flood sender {idx}: received sequence {seq[:10]}...{seq[-10:]} "
                "is not a clean 0..N-1 run -- reordering, gap, or duplication "
                "in the carried sendQ"
            )
        total_received = sum(len(v) for v in received.values())
        assert total_received == expected_total, (
            f"expected {expected_total} flood messages ({FLOOD_CLIENTS} senders x "
            f"{LINES_PER_CLIENT}), received {total_received}: "
            f"{ {k: len(v) for k, v in received.items()} }"
        )
        assert set(received.keys()) == set(range(FLOOD_CLIENTS)), (
            "one or more flood senders' backlog vanished entirely across "
            f"the reload: got senders {sorted(received.keys())}, expected "
            f"{list(range(FLOOD_CLIENTS))}"
        )
    finally:
        if victim is not None:
            victim.close()
        await _disconnect_all(oper, *flooders)
