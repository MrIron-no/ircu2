"""Network-wide delayed-join reveal via the P11 ``REVEAL`` (``RV``) token.

Channel mode ``+D`` hides a member's JOIN until it reveals itself by speaking,
setting the topic, or gaining ``+o``/``+v``.  ``MODE`` and ``TOPIC`` converge
on their own because they propagate to every server; a channel *message* is
relayed only to servers that have a member on the channel, so an off-path
server would never learn of a messaging-caused reveal.  ``REVEAL`` (doc/P11.md
8.12) closes that gap: the home server broadcasts the token to every P11 link.

These stub-level tests pin the emit side (a local speak emits ``RV`` to a P11
peer but not a P10 peer; mode/topic reveals emit no token) and the receive
side (an incoming ``RV`` reveals a hidden member, honouring the TS race
guard).  The real off-path convergence is proved in
``burst_state/test_deljoin_reveal_multiserver.py``.
"""

from __future__ import annotations

import asyncio
import itertools

import pytest

from p11_server import P11Server, strip_msg_tags

pytestmark = pytest.mark.single_server

_sync_seq = itertools.count(1)

# A stub announces its client capacity as a numnick mask; 63 (2**6 - 1) gives
# each introduced user its own slot (see test_burst_deljoin.py for why 64
# ghosts).
STUB_CAPACITY = 63


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


async def _link(hub, protocol: int, numeric: int = 6) -> P11Server:
    """Link a stub server of the given protocol and finish the handshake."""
    stub = P11Server(name="notulined.test.net", numeric=numeric,
                     password="testpass", server_flags="", protocol=protocol,
                     max_clients=STUB_CAPACITY)
    await stub.connect(hub["host"], hub["server_port"])
    await stub.handshake()
    return stub


def _burst_line(stub: P11Server, chan: str) -> str:
    """The BURST line for ``chan`` among everything the stub has read."""
    for line in stub.received:
        parts = strip_msg_tags(line).split()
        if len(parts) >= 3 and parts[1] == "B" and parts[2].lower() == chan.lower():
            return strip_msg_tags(line)
    raise AssertionError(
        f"no BURST for {chan} seen; lines={[strip_msg_tags(l) for l in stub.received]!r}"
    )


def _burst_ts(stub: P11Server, chan: str) -> int:
    return int(_burst_line(stub, chan).split()[3])


async def _recv_token(stub: P11Server, token: str, timeout: float = 5.0):
    """Read stub lines until one whose P10 token is ``token``; else None.

    ``_recv`` answers PINGs and tracks NICKs on the way, so the stub link
    stays alive while we wait.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        try:
            line = await stub._recv(timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError):
            return None
        parts = strip_msg_tags(line).split()
        if len(parts) >= 2 and parts[1] == token:
            return strip_msg_tags(line)


async def _hidden_join(make_client, chan: str, opnick: str, hidnick: str):
    """Create ``chan`` +D with an op and one hidden (silent) member."""
    op = await make_client(opnick)
    await op.send(f"JOIN {chan}")
    await op.wait_for("JOIN", timeout=5.0)
    await op.send(f"MODE {chan} +D")
    await op.wait_for("MODE", timeout=5.0)

    hid = await make_client(hidnick)
    await hid.send(f"JOIN {chan}")
    await hid.wait_for("JOIN", timeout=5.0)
    return op, hid


def _bare(name: str) -> str:
    return name.lstrip("@+!")


async def _sync(client):
    """Flush pending and buffered replies so the next query reads its own.

    JOIN answers with its own names list (353 + 366), so a NAMES issued
    afterwards would otherwise collect that stale pair instead.
    """
    token = f"sync{next(_sync_seq)}"
    await client.send(f"PING :{token}")
    while True:
        msg = await client.wait_for("PONG", timeout=5.0)
        if msg.params and msg.params[-1] == token:
            break
    client._buffer.clear()


async def _names(client, chan: str) -> list[str]:
    await _sync(client)
    await client.send(f"NAMES {chan}")
    msgs = await client.collect_until("366", timeout=5.0)
    names: list[str] = []
    for msg in msgs:
        if msg.command == "353":
            names.extend(msg.params[-1].split())
    return names


# --------------------------------------------------------------------------
# emit side
# --------------------------------------------------------------------------


async def test_local_speak_emits_reveal_token_to_p11(ircd_hub, make_client):
    """A local hidden member speaking emits ``RV`` to a P11 peer."""
    chan = "#rv1"
    op, hid = await _hidden_join(make_client, chan, "rv1op", "rv1u")

    stub = await _link(ircd_hub, 11)
    try:
        hid_nn = stub.get_user_numnick("rv1u")
        assert hid_nn, f"numnick for rv1u not learned: {list(stub.users)!r}"
        ts = _burst_ts(stub, chan)

        await hid.send(f"PRIVMSG {chan} :hi")

        line = await _recv_token(stub, "RV", timeout=6.0)
        assert line is not None, "no RV token reached the P11 peer"
        parts = line.split()
        assert parts[0] == hid_nn, f"RV source is not rv1u's numnick: {line!r}"
        assert parts[2].lower() == chan, f"RV channel wrong: {line!r}"
        assert parts[3] == str(ts), f"RV ts wrong (want {ts}): {line!r}"
    finally:
        await stub.disconnect()


async def test_no_reveal_token_to_p10(ircd_hub, make_client):
    """A P10 peer never receives ``RV`` (it falls back to inference)."""
    chan = "#rv2"
    op, hid = await _hidden_join(make_client, chan, "rv2op", "rv2u")

    stub = await _link(ircd_hub, 10)
    try:
        assert stub.get_user_numnick("rv2u"), "numnick for rv2u not learned"
        await hid.send(f"PRIVMSG {chan} :hi")

        line = await _recv_token(stub, "RV", timeout=2.5)
        assert line is None, f"P10 peer received an RV token: {line!r}"
    finally:
        await stub.disconnect()


async def test_mode_reveal_emits_no_token(ircd_hub, make_client):
    """A ``+v`` reveal travels with MODE, not with a REVEAL token."""
    chan = "#rv3"
    op, hid = await _hidden_join(make_client, chan, "rv3op", "rv3u")

    stub = await _link(ircd_hub, 11)
    try:
        assert stub.get_user_numnick("rv3u"), "numnick for rv3u not learned"
        await op.send(f"MODE {chan} +v rv3u")

        # The MODE ('M') relay must arrive, but no RV token.
        got_mode = False
        got_rv = False
        loop = asyncio.get_event_loop()
        deadline = loop.time() + 3.0
        while loop.time() < deadline:
            try:
                line = await stub._recv(timeout=deadline - loop.time())
            except (asyncio.TimeoutError, TimeoutError):
                break
            parts = strip_msg_tags(line).split()
            if len(parts) >= 2 and parts[1] == "M" and len(parts) > 2 \
                    and parts[2].lower() == chan:
                got_mode = True
            if len(parts) >= 2 and parts[1] == "RV":
                got_rv = True
        assert got_mode, "the +v MODE relay never reached the P11 peer"
        assert not got_rv, "a mode reveal wrongly emitted an RV token"
    finally:
        await stub.disconnect()


async def test_topic_reveal_emits_no_token(ircd_hub, make_client):
    """A topic-set reveal travels with TOPIC, not with a REVEAL token."""
    chan = "#rv4"
    op, hid = await _hidden_join(make_client, chan, "rv4op", "rv4u")

    stub = await _link(ircd_hub, 11)
    try:
        assert stub.get_user_numnick("rv4u"), "numnick for rv4u not learned"
        await hid.send(f"TOPIC {chan} :x")

        got_topic = False
        got_rv = False
        loop = asyncio.get_event_loop()
        deadline = loop.time() + 3.0
        while loop.time() < deadline:
            try:
                line = await stub._recv(timeout=deadline - loop.time())
            except (asyncio.TimeoutError, TimeoutError):
                break
            parts = strip_msg_tags(line).split()
            if len(parts) >= 2 and parts[1] == "T" and len(parts) > 2 \
                    and parts[2].lower() == chan:
                got_topic = True
            if len(parts) >= 2 and parts[1] == "RV":
                got_rv = True
        assert got_topic, "the TOPIC relay never reached the P11 peer"
        assert not got_rv, "a topic reveal wrongly emitted an RV token"
    finally:
        await stub.disconnect()


# --------------------------------------------------------------------------
# receive side
# --------------------------------------------------------------------------


async def test_incoming_reveal_token_reveals_member(ircd_hub, make_client):
    """An incoming ``RV`` reveals a hidden member introduced by the peer."""
    chan = "#rv5"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa5")
        await stub._send(f"{stub.server_numnick} B {chan} 1700000000 +D {sa}:d")
        await asyncio.sleep(0.5)

        client = await make_client("rv5watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa5" not in names, f"hidden member listed before reveal: {names!r}"

        await stub._send(f"{sa} RV {chan} 1700000000")
        join = await client.wait_for("JOIN", timeout=5.0)
        assert join.prefix and join.prefix.startswith("sa5!"), (
            f"reveal JOIN came from {join.prefix!r}"
        )
        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa5" in names, f"member still hidden after RV: {names!r}"
    finally:
        await stub.disconnect()


async def test_reveal_token_stale_ts_ignored(ircd_hub, make_client):
    """An ``RV`` with a newer TS than ours lost the race and is ignored."""
    chan = "#rv6"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa6")
        await stub._send(f"{stub.server_numnick} B {chan} 1700000000 +D {sa}:d")
        await asyncio.sleep(0.5)

        client = await make_client("rv6watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa6" not in names, f"hidden member listed before reveal: {names!r}"

        # TS newer than our creation time (1700000000) -> ignored.
        await stub._send(f"{sa} RV {chan} 1700000100")
        with pytest.raises(asyncio.TimeoutError):
            await client.wait_for("JOIN", timeout=2.5)

        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa6" not in names, f"stale RV wrongly revealed member: {names!r}"
    finally:
        await stub.disconnect()


# --------------------------------------------------------------------------
# review fix-up: REVEAL is #-only, and the relay forwards the received TS
# --------------------------------------------------------------------------


async def _two_p11_stubs(hub) -> tuple[P11Server, P11Server]:
    """Link two P11 stubs (A=notulined #5, B=uworldonly #6) to the hub.

    Both names have Connect blocks in ircd-hub.conf.  A relayed token from A
    must reach B, so both links are up before we act.
    """
    stub_a = P11Server(name="notulined.test.net", numeric=5,
                       password="testpass", server_flags="", protocol=11,
                       max_clients=STUB_CAPACITY)
    await stub_a.connect(hub["host"], hub["server_port"])
    await stub_a.handshake()

    stub_b = P11Server(name="uworldonly.test.net", numeric=6,
                       password="testpass", server_flags="", protocol=11,
                       max_clients=STUB_CAPACITY)
    await stub_b.connect(hub["host"], hub["server_port"])
    await stub_b.handshake()

    return stub_a, stub_b


async def _watch_violations(oper):
    """Ensure protocol_violation() wallops reach this oper (umode +g)."""
    await oper.send(f"MODE {oper.nick} +g")
    await asyncio.sleep(0.3)
    await oper.send(f"MODE {oper.nick}")
    msg = await oper.wait_for("221", timeout=5.0)
    assert "g" in msg.params[-1], f"oper is not on +g: {msg.params!r}"


async def _wait_for_wallops(client, needle: str, timeout: float = 6.0) -> str:
    """Wait for a WALLOPS whose text contains ``needle``; else assert."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    seen: list[str] = []
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise AssertionError(
                f"no WALLOPS containing {needle!r} arrived; saw {seen!r}"
            )
        try:
            msg = await client.wait_for("WALLOPS", timeout=remaining)
        except asyncio.TimeoutError:
            raise AssertionError(
                f"no WALLOPS containing {needle!r} arrived; saw {seen!r}"
            )
        text = msg.params[-1] if msg.params else ""
        seen.append(text)
        if needle in text:
            return text


async def _recv_token_for_chan(stub, token, chan, timeout=2.0):
    """First line whose P10 token is ``token`` and names ``chan``; else None."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        try:
            line = await stub._recv(timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError):
            return None
        parts = strip_msg_tags(line).split()
        if len(parts) >= 3 and parts[1] == token \
                and parts[2].lower() == chan.lower():
            return strip_msg_tags(line)


async def test_local_channel_speak_emits_no_reveal_token(ircd_hub, make_client):
    """A speak on a LOCAL (&) +D channel reveals locally but emits no RV.

    A ``&`` channel is local to the hub, so no token may cross S2S; the local
    reveal (JOIN to the channel members) still happens on the hub itself.
    """
    chan = "&rvlocal"
    op, hid = await _hidden_join(make_client, chan, "rvlocop", "rvlocu")

    stub = await _link(ircd_hub, 11)
    try:
        await hid.send(f"PRIVMSG {chan} :hi")
        # No RV naming the local channel may reach the P11 peer.
        line = await _recv_token_for_chan(stub, "RV", chan, timeout=2.5)
        assert line is None, f"local channel wrongly emitted an RV token: {line!r}"
    finally:
        await stub.disconnect()


async def test_incoming_reveal_for_local_channel_is_rejected(ircd_hub,
                                                             make_client, oper):
    """An incoming ``RV`` for a ``&`` channel is a protocol violation."""
    await _watch_violations(oper)

    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sarvloc")
        await stub._send(f"{sa} RV &whatever 1700000000")

        text = await _wait_for_wallops(oper, "Bad REVEAL")
        assert "Protocol Violation" in text, text

        # The hub survives the violation and still answers a later command.
        client = await make_client("rvlocwatch")
        await client.send("PING :rvloc-alive")
        pong = await client.wait_for("PONG", timeout=5.0)
        assert pong.params and pong.params[-1] == "rvloc-alive", pong.params
    finally:
        await stub.disconnect()


async def test_relay_forwards_received_timestamp(ircd_hub, make_client):
    """The onward relay forwards the received TS, not the hub's local one.

    The hub's ``#rvts`` is created "now" (a large ``T_local``).  Stub A bursts
    a hidden member onto that existing channel, then reveals it with an
    earlier ``T_earlier`` (still <= ``T_local``, so the race guard accepts it).
    Stub B must see exactly ``T_earlier`` relayed, not the hub's ``T_local``.
    """
    chan = "#rvts"
    owner = await make_client("rvtsown")
    await owner.send(f"JOIN {chan}")
    await owner.wait_for("JOIN", timeout=5.0)
    await owner.send(f"MODE {chan} +D")
    await owner.wait_for("MODE", timeout=5.0)

    stub_a, stub_b = await _two_p11_stubs(ircd_hub)
    try:
        t_local = _burst_ts(stub_a, chan)
        t_earlier = t_local - 50

        sa = await stub_a.introduce_user("sarvts")
        # Merge a hidden member onto the existing channel at its own TS.
        await stub_a._send(
            f"{stub_a.server_numnick} B {chan} {t_local} +D {sa}:d")
        await asyncio.sleep(0.5)

        # Ignore everything B has seen so far; wait for the relayed RV.
        await stub_b.drain_messages(timeout=1.0)

        await stub_a._send(f"{sa} RV {chan} {t_earlier}")

        line = await _recv_token_for_chan(stub_b, "RV", chan, timeout=6.0)
        assert line is not None, "the relayed RV token never reached stub B"
        parts = line.split()
        assert parts[0] == sa, f"relayed RV source wrong: {line!r}"
        assert int(parts[3]) == t_earlier, (
            f"relay forwarded ts {parts[3]}, want received {t_earlier} "
            f"(not local {t_local}): {line!r}"
        )
    finally:
        await stub_a.disconnect()
        await stub_b.disconnect()
