"""Misbehaving TLS peers against ircd's inbound and outbound handshake paths.

Each scenario parks ircd in one handshake state (waiting for the peer,
blocked on a write, mid-record, garbage on the wire, RST/FIN mid-handshake,
peer that never reads) and checks three things:

  * the deadline: the connection is torn down at TLS_HANDSHAKE_TIMEOUT (5 s)
    or promptly on a hard failure, with nothing written before the close;
  * no CPU spin: `docker stats` on the hub stays far below 100% while peers
    are stalled (the original inbound bug spun on a level-triggered writable
    event for the whole handshake);
  * liveness: a healthy client keeps getting PONGs while peers are stalled.

Outbound scenarios use the hub's `Connect { name = "bogus.test.net";
host = "10.55.0.40"; }` block: a BogusTLSServer runs in a sidecar container
on the test network and an oper issues `CONNECT bogus.test.net <port>`, so
the hub runs its own client-side handshake against a server we control
byte by byte.

Set BOGUS_TLS_HOST / BOGUS_TLS_PORT / BOGUS_TLS_SERVER_PORT to run the
inbound scenarios against a real ircd instead of the docker hub (CPU and
notice checks are skipped there).
"""

from __future__ import annotations

import asyncio
import os
import re
import time

import pytest
import pytest_asyncio

from irc_client import IRCClient
from tls.bogus_peer import BogusTLSClient, SidecarBogusServer, sample_cpu, wait_for_eof
from tls.helpers import oper_up

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

HUB_CONTAINER = "ircu-tls-hub"
HANDSHAKE_TIMEOUT = 5.0
# Deadline window: timer fires at 5 s, plus docker/scheduling slack.
CLOSE_MIN, CLOSE_MAX = 3.5, 10.0
CPU_SPIN_THRESHOLD = 50.0   # a single-threaded spin shows as ~100%

EXTERNAL = os.environ.get("BOGUS_TLS_HOST")


def _target(hub: dict) -> dict:
    if EXTERNAL:
        return {
            "host": EXTERNAL,
            "tls_port": int(os.environ["BOGUS_TLS_PORT"]),
            "server_port": int(os.environ["BOGUS_TLS_SERVER_PORT"]),
            "external": True,
        }
    return {"host": hub["host"], "tls_port": hub["tls_port"],
            "server_port": hub["server_port"], "external": False}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def _oper(hub: dict, nick: str) -> IRCClient:
    c = IRCClient()
    await c.connect(hub["host"], hub["port"])
    await c.register(nick, "oper", "Bogus peer oper")
    msg = await oper_up(c)
    assert msg.command == "381", msg
    await c.send(f"MODE {nick} +s +65535")
    await asyncio.sleep(0.2)
    return c


async def _notices(oper: IRCClient, pattern: str, seconds: float) -> list[str]:
    """Collect server notices matching `pattern` for `seconds`."""
    rx = re.compile(pattern)
    found = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return found
        try:
            msg = await oper.recv(timeout=remaining)
        except asyncio.TimeoutError:
            return found
        if msg.command == "NOTICE" and rx.search(msg.params[-1]):
            found.append(msg.params[-1])


async def _wait_notice(oper: IRCClient, pattern: str, timeout: float) -> str:
    rx = re.compile(pattern)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    seen = []
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise AssertionError(f"no notice matching {pattern!r} within {timeout}s; saw {seen[-5:]}")
        msg = await oper.recv(timeout=remaining)
        if msg.command == "NOTICE":
            seen.append(msg.params[-1])
            if rx.search(msg.params[-1]):
                return msg.params[-1]


async def _ping_rtt(client: IRCClient, token: str, timeout: float = 2.0) -> float:
    start = time.monotonic()
    await client.send(f"PING :{token}")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise AssertionError("healthy client got no PONG while peers stalled")
        msg = await client.recv(timeout=remaining)
        if msg.command == "PONG" and msg.params[-1] == token:
            return time.monotonic() - start


async def _recv_until(peer: BogusTLSClient, needle: str, timeout: float) -> str:
    """Read decrypted data until `needle` appears or `timeout` elapses."""
    got = ""
    answered = 0
    deadline = time.monotonic() + timeout
    while needle not in got:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            got += await peer.recv_app(timeout=min(remaining, 5.0))
        except asyncio.TimeoutError:
            continue
        except ConnectionError:
            break
        # Registration requires answering the nospoof PING.
        for m in re.finditer(r"^PING :(\S+)\r?$", got, re.M):
            if m.end() > answered:
                await peer.send_app(f"PONG :{m.group(1)}\r\n")
                answered = m.end()
    return got


async def _cpu_or_none(target: dict, seconds: float) -> list[float]:
    if target["external"]:
        await asyncio.sleep(seconds)
        return []
    return await sample_cpu(HUB_CONTAINER, seconds)


def _assert_no_spin(samples: list[float], what: str) -> None:
    if not samples:
        return
    assert max(samples) < CPU_SPIN_THRESHOLD, (
        f"hub CPU spun while {what}: samples={samples}"
    )


def _assert_closed_on_deadline(elapsed: float, what: str) -> None:
    assert elapsed >= 0, f"{what}: still open after {CLOSE_MAX}s"
    assert CLOSE_MIN <= elapsed <= CLOSE_MAX, (
        f"{what}: closed after {elapsed:.1f}s, expected ~{HANDSHAKE_TIMEOUT}s"
    )


@pytest_asyncio.fixture
async def healthy(ircd_tls_network):
    """A registered plaintext client on the hub used as a liveness probe."""
    hub = ircd_tls_network["hub"]
    if EXTERNAL:
        yield None
        return
    c = IRCClient()
    await c.connect(hub["host"], hub["port"])
    await c.register("bogushealthy", "probe", "liveness probe")
    yield c
    try:
        await c.disconnect()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# inbound: bogus clients
# ---------------------------------------------------------------------------


async def test_silent_peers_time_out_without_spin(ircd_tls_network, healthy):
    """Several peers that connect and send nothing: each is closed at the
    deadline with no bytes written, the hub does not spin, and a healthy
    client stays responsive meanwhile."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    oper = None if tgt["external"] else await _oper(hub, "bogusop1")
    peers = [BogusTLSClient(tgt["host"], tgt["tls_port"]) for _ in range(4)]
    peers += [BogusTLSClient(tgt["host"], tgt["server_port"]) for _ in range(2)]
    start = time.monotonic()
    try:
        for p in peers:
            await p.connect()
        samples = await _cpu_or_none(tgt, 3.0)
        if healthy:
            rtt = await _ping_rtt(healthy, "silent")
            assert rtt < 1.0, f"PONG took {rtt:.2f}s during stall"
        results = await asyncio.gather(*(wait_for_eof(p.reader, CLOSE_MAX) for p in peers))
        for (data, waited), p in zip(results, peers):
            assert data == b"", f"server wrote {data[:40]!r} to a silent peer"
            _assert_closed_on_deadline(
                (time.monotonic() - start) if waited >= 0 else -1, f"silent peer on :{p.port}"
            )
        _assert_no_spin(samples, "6 peers sat silent in the handshake")
        if oper:
            notes = await _notices(oper, r"TLS negotiation failed from unknown server.*timed out", 2.0)
            assert len(notes) >= 2, notes   # the two server-port peers
    finally:
        for p in peers:
            await p.close()
        if oper:
            await oper.disconnect()


async def test_stall_after_clienthello_times_out_without_spin(ircd_tls_network, healthy):
    """ClientHello sent, server flight received, peer never continues."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"])
    try:
        await peer.connect()
        hello = peer.start_tls()
        start = time.monotonic()
        await peer.send_raw(hello)
        flight = await peer.feed(timeout=5.0)
        assert flight[:1] == b"\x16", f"expected a TLS handshake record, got {flight[:8]!r}"
        samples = await _cpu_or_none(tgt, 3.0)
        if healthy:
            assert await _ping_rtt(healthy, "stall") < 1.0
        data, waited = await wait_for_eof(peer.reader, CLOSE_MAX)
        _assert_closed_on_deadline((time.monotonic() - start) if waited >= 0 else -1, "stalled after ClientHello")
        # Nothing but TLS records: no plaintext ERROR into the handshake stream.
        assert not data or data[:1] in (b"\x15", b"\x16", b"\x17"), data[:40]
        _assert_no_spin(samples, "peer stalled after ClientHello")
    finally:
        await peer.close()


async def test_slowloris_clienthello_is_cut_at_deadline(ircd_tls_network, healthy):
    """A ClientHello dribbled one byte at a time keeps generating read
    events but must not extend the deadline (and must not spin)."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"])
    try:
        await peer.connect()
        hello = peer.start_tls()
        start = time.monotonic()
        dribble = asyncio.create_task(peer.send_slowly(hello, 1, 0.15))
        samples = await _cpu_or_none(tgt, 3.0)
        data, waited = await wait_for_eof(peer.reader, CLOSE_MAX)
        dribble.cancel()
        _assert_closed_on_deadline((time.monotonic() - start) if waited >= 0 else -1, "slowloris ClientHello")
        assert data == b""
        _assert_no_spin(samples, "ClientHello dribbled 1 byte at a time")
    finally:
        await peer.close()


async def test_slow_but_complete_handshake_registers(ircd_tls_network):
    """Control: a slow peer that does finish inside the deadline registers."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"])
    try:
        await peer.connect()
        hello = peer.start_tls()
        await peer.send_slowly(hello, 48, 0.1)      # ~0.5-1 s
        await peer.complete_handshake(timeout=8.0)
        await peer.send_app("NICK bogusslow\r\nUSER slow 0 * :slow\r\n")
        got = await _recv_until(peer, " 001 ", 15.0)
        assert " 001 " in got, got[-300:]
    finally:
        await peer.close()


async def test_finished_coalesced_with_data_registers(ircd_tls_network):
    """The client's Finished and its first application record arrive in
    one segment.  After the handshake completes the server must still pick
    up the application data that is already queued (whether it sits in the
    kernel or was pulled into the TLS library's buffer)."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"])
    try:
        await peer.connect()
        finished = await peer.complete_handshake(timeout=8.0, flush=False)
        assert finished, "expected an unsent client Finished flight"
        await peer.send_raw(finished + peer.app_bytes("NICK boguscoal\r\nUSER coal 0 * :coalesced\r\n"))
        got = await _recv_until(peer, " 001 ", 15.0)
        assert " 001 " in got, got[-300:]
    finally:
        await peer.close()


async def test_garbage_after_clienthello_closes_promptly(ircd_tls_network, healthy):
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"])
    try:
        await peer.connect()
        hello = peer.start_tls()
        await peer.send_raw(hello)
        await peer.feed(timeout=5.0)                  # server flight
        start = time.monotonic()
        await peer.send_raw(os.urandom(2048))
        data, waited = await wait_for_eof(peer.reader, CLOSE_MAX)
        assert waited >= 0, "server kept a garbage-fed handshake open"
        assert time.monotonic() - start < 3.0, "garbage should fail the handshake immediately"
        assert not data or data[:1] in (b"\x15", b"\x16", b"\x17"), data[:40]
        if healthy:
            assert await _ping_rtt(healthy, "garbage") < 1.0
    finally:
        await peer.close()


@pytest.mark.parametrize("how", ["rst", "fin"])
async def test_abort_mid_handshake_then_normal_client_works(ircd_tls_network, how):
    """RST or FIN right after ClientHello must be handled cleanly; a normal
    TLS registration afterwards proves nothing was left wedged."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"])
    await peer.connect()
    hello = peer.start_tls()
    await peer.send_raw(hello)
    await peer.feed(timeout=5.0)
    if how == "rst":
        await peer.close_rst()
    else:
        await peer.close_fin()
        data, waited = await wait_for_eof(peer.reader, 6.0)
        assert waited >= 0, "server did not close after peer FIN mid-handshake"
        assert waited < 3.0, f"FIN mid-handshake took {waited:.1f}s to close"
        await peer.close()
    await asyncio.sleep(0.3)

    ok = IRCClient()
    await ok.connect_tls(tgt["host"], tgt["tls_port"])
    try:
        msgs = await ok.register(f"bogusok{how}", "ok", "after abort")
        assert any(m.command == "001" for m in msgs)
    finally:
        await ok.disconnect()


async def test_peer_that_never_reads_is_cut_at_deadline(ircd_tls_network, healthy):
    """Tiny receive window, ClientHello sent, then the peer never reads: the
    server's flight may block on write (WANT_WRITE); it must wait on the
    write side without spinning and still abort at the deadline."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"], rcvbuf=1024)
    try:
        await peer.connect()
        hello = peer.start_tls()
        start = time.monotonic()
        await peer.send_raw(hello)
        samples = await _cpu_or_none(tgt, 3.5)
        if healthy:
            assert await _ping_rtt(healthy, "noread") < 1.0
        await asyncio.sleep(max(0.0, HANDSHAKE_TIMEOUT + 1.5 - (time.monotonic() - start)))
        # Only now start reading: whatever was queued, then EOF.
        data, waited = await wait_for_eof(peer.reader, 4.0)
        assert waited >= 0, "server kept a never-reading peer open past the deadline"
        assert data[:1] == b"\x16", f"expected the server flight, got {data[:8]!r}"
        _assert_no_spin(samples, "peer never read the server flight")
    finally:
        await peer.close()


async def test_flood_without_reading_after_handshake(ircd_tls_network, healthy):
    """Completed handshake, then the peer floods commands and never reads
    the replies: the data-path write side must back off, kill the client
    (sendq or flood limit) and never spin."""
    hub = ircd_tls_network["hub"]
    tgt = _target(hub)
    peer = BogusTLSClient(tgt["host"], tgt["tls_port"], rcvbuf=2048)
    try:
        await peer.connect()
        await peer.complete_handshake()
        await peer.send_app("NICK bogusflood\r\nUSER flood 0 * :flood\r\n")
        start = time.monotonic()
        # Ask for lots of output without ever reading it.
        try:
            for _ in range(400):
                await peer.send_app("MOTD\r\nLUSERS\r\nVERSION\r\nADMIN\r\n")
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        samples = await _cpu_or_none(tgt, 3.0)
        if healthy:
            assert await _ping_rtt(healthy, "flood") < 1.0
        data, waited = await wait_for_eof(peer.reader, 60.0)
        assert waited >= 0, "flooding peer was never disconnected"
        _assert_no_spin(samples, "peer flooded without reading")
    finally:
        await peer.close()


# ---------------------------------------------------------------------------
# outbound: bogus servers the hub connects to
# ---------------------------------------------------------------------------

PEER_NAME = "bogus.test.net"


@pytest_asyncio.fixture
async def link_oper(ircd_tls_network):
    if EXTERNAL:
        pytest.skip("outbound scenarios need the docker hub")
    hub = ircd_tls_network["hub"]
    oper = await _oper(hub, "boguslink")
    yield oper
    try:
        await oper.disconnect()
    except Exception:
        pass


async def _connect_out(oper: IRCClient, port: int) -> None:
    await oper.send(f"CONNECT {PEER_NAME} {port}")


async def test_outbound_silent_server_times_out(ircd_tls_network, link_oper):
    srv = SidecarBogusServer("silent")
    port = await srv.start()
    try:
        await _connect_out(link_oper, port)
        await srv.wait_event("accepted", 10.0)
        start = time.monotonic()
        samples = await sample_cpu(HUB_CONTAINER, 3.0)
        note = await _wait_notice(link_oper, rf"TLS negotiation failed to {PEER_NAME}.*timed out", CLOSE_MAX)
        elapsed = time.monotonic() - start
        assert elapsed <= CLOSE_MAX, f"outbound timeout took {elapsed:.1f}s"
        # The hub did start the handshake: a TLS handshake record arrived.
        await srv.wait_event("raw", 3.0)
        assert srv.received_raw[:1] == b"\x16", srv.received_raw[:8]
        _assert_no_spin(samples, "outbound peer stayed silent")
        assert "timed out" in note
    finally:
        await srv.stop()


async def test_outbound_truncated_server_flight_times_out(ircd_tls_network, link_oper):
    srv = SidecarBogusServer("truncated_flight", truncate=200)
    port = await srv.start()
    try:
        await _connect_out(link_oper, port)
        await srv.wait_event("accepted", 10.0)
        start = time.monotonic()
        samples = await sample_cpu(HUB_CONTAINER, 3.0)
        note = await _wait_notice(link_oper, rf"TLS negotiation failed to {PEER_NAME}", CLOSE_MAX)
        assert "timed out" in note, note
        assert time.monotonic() - start <= CLOSE_MAX
        _assert_no_spin(samples, "outbound server sent a truncated flight")
    finally:
        await srv.stop()


# delay=0: the failure is already on the wire when the hub's connect step
# runs its first negotiate (detected in completed_connection()).
# delay=1: the hub has parked waiting for the server flight and the
# failure arrives as a later read event (detected in the ET_READ arm).
# Both must be reported to opers immediately, never via the 5 s deadline.
@pytest.mark.parametrize("delay", [0.0, 1.0], ids=["during-connect", "after-connect"])
async def test_outbound_garbage_server_fails_fast(ircd_tls_network, link_oper, delay):
    srv = SidecarBogusServer("garbage", delay=delay)
    port = await srv.start()
    try:
        await _connect_out(link_oper, port)
        await srv.wait_event("accepted", 10.0)
        start = time.monotonic()
        note = await _wait_notice(link_oper, rf"TLS negotiation failed to {PEER_NAME}", 6.0)
        assert "timed out" not in note, note
        assert time.monotonic() - start < delay + 3.0, note
    finally:
        await srv.stop()


@pytest.mark.parametrize("delay", [0.0, 1.0], ids=["during-connect", "after-connect"])
async def test_outbound_server_closes(ircd_tls_network, link_oper, delay):
    srv = SidecarBogusServer("close", delay=delay)
    port = await srv.start()
    try:
        await _connect_out(link_oper, port)
        await srv.wait_event("accepted", 10.0)
        start = time.monotonic()
        # Depending on timing the EOF is seen by the TLS layer (unexpected
        # eof), by the connect step, or as a socket reset on a later event;
        # every variant must reach the oper who issued the CONNECT.
        note = await _wait_notice(
            link_oper,
            rf"(TLS negotiation failed to {PEER_NAME}|Connection failed to {PEER_NAME}"
            rf"|Link with {PEER_NAME} canceled)",
            6.0,
        )
        assert "timed out" not in note, note
        assert time.monotonic() - start < delay + 3.0, note
    finally:
        await srv.stop()


async def test_outbound_full_handshake_delivers_pass_and_server(ircd_tls_network, link_oper):
    """Control: against a well-behaved foreign TLS stack the hub completes
    the handshake and sends PASS + SERVER over the encrypted link."""
    srv = SidecarBogusServer("complete", cert="tlspeer")
    port = await srv.start()
    try:
        await _connect_out(link_oper, port)
        await srv.wait_event("line", 10.0)
        await asyncio.sleep(0.5)
        await srv.wait_event("line", 1.0)
        lines = srv.app_lines
        assert any(l.startswith("PASS ") for l in lines), lines
        assert any(l.startswith("SERVER tls-hub.test.net ") for l in lines), lines
    finally:
        await srv.stop()
        # The hub drops the link once our server goes away.
        await _notices(link_oper, r".", 1.0)
