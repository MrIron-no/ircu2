"""Hidden (delayed-join) members travel as an explicit ``d`` group in BURST.

Channel mode ``+D`` hides a new join until the member speaks.  P10 has no way
to say which members are hidden, so a receiver infers it: every status-less
member of a ``+D`` channel is hidden.  P11 says it outright with a ``d``
member specifier (doc/P11.md 8.1), which makes the hidden set exact even when
the two sides disagree about ``+D``.

These tests pin both directions: what the hub emits to a P11 and to a P10
peer, and what it does with a ``d`` it receives under each of the three
processing cases (P11 + our TS equal/older, P11 + our TS newer, P10).
"""

from __future__ import annotations

import asyncio
import itertools

import pytest

from p11_server import P11Server, strip_msg_tags

pytestmark = pytest.mark.single_server

# A stub announces its client capacity as a numnick mask, and the ircd uses
# that value verbatim as the slot mask for the link's users.  Only a mask of
# the form 2**n - 1 gives each of our users its own slot; the library default
# (64) folds every user onto slot 0, so the second introduction ghosts the
# first.  63 keeps sa/sb distinct.
STUB_CAPACITY = 63

_sync_seq = itertools.count(1)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


async def _link(hub, protocol: int, numeric: int = 5) -> P11Server:
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


def _member_field(line: str) -> str:
    """The member list of a BURST line (the tests use modes without args)."""
    tokens = line.split()
    rest = tokens[4:]
    if rest and rest[0].startswith("+"):
        rest = rest[1:]
    assert rest and not rest[0].startswith(":"), f"no member list in {line!r}"
    return rest[0]


def _members(line: str) -> list[str]:
    return _member_field(line).split(",")


def _bare(name: str) -> str:
    """A NAMES entry without its @/+/! status prefix."""
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
    """The nicks in the RPL_NAMREPLY (353) replies for ``chan``."""
    await _sync(client)
    await client.send(f"NAMES {chan}")
    msgs = await client.collect_until("366", timeout=5.0)
    names: list[str] = []
    for msg in msgs:
        if msg.command == "353":
            names.extend(msg.params[-1].split())
    return names


async def _chan_modes(client, chan: str) -> str:
    """The mode letters of the RPL_CHANNELMODEIS (324) reply for ``chan``."""
    await _sync(client)
    await client.send(f"MODE {chan}")
    msg = await client.wait_for("324", timeout=5.0)
    return next((p for p in msg.params if p.startswith("+")), "")


async def _watch_violations(oper):
    """Make sure protocol_violation() wallops reach this client.

    They go to umode +g (WALL_DESYNCH -> SendDebug), which OPER already
    grants; the explicit MODE is then a no-op and draws no echo, so the
    state is confirmed with RPL_UMODEIS instead.
    """
    await oper.send(f"MODE {oper.nick} +g")
    await asyncio.sleep(0.3)
    await oper.send(f"MODE {oper.nick}")
    msg = await oper.wait_for("221", timeout=5.0)
    assert "g" in msg.params[-1], f"oper is not on +g: {msg.params!r}"


async def _collect_wallops(client, seconds: float = 1.5) -> list[str]:
    """Every WALLOPS text that arrives in the next ``seconds``."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + seconds
    texts: list[str] = []
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return texts
        try:
            msg = await client.wait_for("WALLOPS", timeout=remaining)
        except asyncio.TimeoutError:
            return texts
        texts.append(msg.params[-1] if msg.params else "")


async def _wait_for_wallops(client, needle: str, timeout: float = 6.0) -> str:
    """Wait for a WALLOPS whose text contains ``needle``."""
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


async def _hidden_channel(make_client, chan: str, tag: str):
    """A +D channel with one op, one hidden member and one revealed member."""
    op1 = await make_client(f"{tag}op")
    await op1.send(f"JOIN {chan}")
    await op1.wait_for("JOIN", timeout=5.0)
    await op1.send(f"MODE {chan} +D")
    await op1.wait_for("MODE", timeout=5.0)

    hid1 = await make_client(f"{tag}hid")
    await hid1.send(f"JOIN {chan}")
    await hid1.wait_for("JOIN", timeout=5.0)

    rev1 = await make_client(f"{tag}rev")
    await rev1.send(f"JOIN {chan}")
    await rev1.wait_for("JOIN", timeout=5.0)
    await rev1.send(f"PRIVMSG {chan} :hello")
    # The reveal reaches the op as a JOIN; wait for it so the channel is
    # settled before we link the observing server.
    await op1.wait_for("JOIN", timeout=5.0)

    return op1, hid1, rev1


# --------------------------------------------------------------------------
# emit
# --------------------------------------------------------------------------


async def test_emit_d_group_to_p11_stub(ircd_hub, make_client):
    """A P11 peer gets the hidden member in its own group, marked ``:d``."""
    chan = "#dj1"
    op1, hid1, rev1 = await _hidden_channel(make_client, chan, "dj1")

    stub = await _link(ircd_hub, 11)
    try:
        line = _burst_line(stub, chan)
        op_nn = stub.get_user_numnick(op1.nick)
        hid_nn = stub.get_user_numnick(hid1.nick)
        rev_nn = stub.get_user_numnick(rev1.nick)
        assert op_nn and hid_nn and rev_nn, (
            f"numnicks not learned from the burst: {list(stub.users)!r}"
        )

        # Groups in wire order: none, d, op.
        assert _members(line) == [rev_nn, f"{hid_nn}:d", f"{op_nn}:o"], (
            f"unexpected member list in {line!r}"
        )
    finally:
        await stub.disconnect()


async def test_no_d_group_to_p10_stub(ircd_hub, make_client):
    """A P10 peer sees the hidden member bare, in the status-less group."""
    chan = "#dj2"
    op1, hid1, rev1 = await _hidden_channel(make_client, chan, "dj2")

    stub = await _link(ircd_hub, 10)
    try:
        line = _burst_line(stub, chan)
        op_nn = stub.get_user_numnick(op1.nick)
        hid_nn = stub.get_user_numnick(hid1.nick)
        rev_nn = stub.get_user_numnick(rev1.nick)
        assert op_nn and hid_nn and rev_nn

        assert ":d" not in line, f"P10 peer received a d specifier: {line!r}"
        assert _members(line) == [rev_nn, hid_nn, f"{op_nn}:o"], (
            f"unexpected member list in {line!r}"
        )
    finally:
        await stub.disconnect()


# --------------------------------------------------------------------------
# parse
# --------------------------------------------------------------------------


async def test_d_from_p11_stub_hides_member(ircd_hub, make_client):
    """``:d`` on a P11 link hides that member and only that member."""
    chan = "#dj3"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa3")
        sb = await stub.introduce_user("sb3")
        await stub._send(f"{stub.server_numnick} B {chan} 1700000000 +D {sa},{sb}:d")
        await asyncio.sleep(0.5)

        client = await make_client("dj3watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa3" in names, f"visible member missing from NAMES: {names!r}"
        assert "sb3" not in names, f"hidden member listed in NAMES: {names!r}"

        # Speaking reveals the hidden member: JOIN first, then the message.
        await stub.send_privmsg(sb, chan, "now visible")
        join = await client.wait_for("JOIN", timeout=5.0)
        assert join.prefix and join.prefix.startswith("sb3!"), (
            f"reveal JOIN came from {join.prefix!r}"
        )
        msg = await client.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "now visible"
    finally:
        await stub.disconnect()


async def test_d_on_non_D_channel_sets_wasdeljoins(ircd_hub, make_client):
    """A ``d`` member on a channel that is not +D sets the local +d flag."""
    chan = "#dj4"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa4")
        sb = await stub.introduce_user("sb4")
        await stub._send(f"{stub.server_numnick} B {chan} 1700000000 +t {sa},{sb}:d")
        await asyncio.sleep(0.5)

        client = await make_client("dj4watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        modes = await _chan_modes(client, chan)
        assert "d" in modes, f"+d (has hidden members) not shown: {modes!r}"

        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa4" in names, f"visible member missing from NAMES: {names!r}"
        assert "sb4" not in names, f"hidden member listed in NAMES: {names!r}"

        await stub.send_privmsg(sb, chan, "now visible")
        await client.wait_for("JOIN", timeout=5.0)
        await client.wait_for("PRIVMSG", timeout=5.0)

        modes = await _chan_modes(client, chan)
        assert "d" not in modes, f"+d not cleared after the reveal: {modes!r}"
    finally:
        await stub.disconnect()


async def test_d_ignored_when_our_ts_is_newer_not_plus_D(ircd_hub, make_client):
    """Our channel wins: ``d`` is ignored like o/v, and we are not +D."""
    chan = "#dj5"
    client = await make_client("dj5own")
    await client.send(f"JOIN {chan}")
    await client.wait_for("JOIN", timeout=5.0)

    stub = await _link(ircd_hub, 11)
    try:
        ts = int(_burst_line(stub, chan).split()[3])
        sa = await stub.introduce_user("sa5")
        sb = await stub.introduce_user("sb5")
        await stub._send(
            f"{stub.server_numnick} B {chan} {ts + 100} +D {sa},{sb}:d"
        )
        await asyncio.sleep(0.5)

        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa5" in names and "sb5" in names, (
            f"members of the losing burst are hidden: {names!r}"
        )
        modes = await _chan_modes(client, chan)
        assert "D" not in modes and "d" not in modes, (
            f"the losing burst's +D was applied: {modes!r}"
        )
    finally:
        await stub.disconnect()


async def test_d_ignored_when_our_ts_is_newer_plus_D(ircd_hub, make_client):
    """Our +D channel wins: every member of the losing burst is hidden."""
    chan = "#dj6"
    client = await make_client("dj6own")
    await client.send(f"JOIN {chan}")
    await client.wait_for("JOIN", timeout=5.0)
    await client.send(f"MODE {chan} +D")
    await client.wait_for("MODE", timeout=5.0)

    stub = await _link(ircd_hub, 11)
    try:
        ts = int(_burst_line(stub, chan).split()[3])
        sa = await stub.introduce_user("sa6")
        sb = await stub.introduce_user("sb6")
        await stub._send(
            f"{stub.server_numnick} B {chan} {ts + 100} +D {sa},{sb}:d"
        )
        await asyncio.sleep(0.5)

        names = [_bare(n) for n in await _names(client, chan)]
        assert "sa6" not in names and "sb6" not in names, (
            f"members of the losing burst are visible on our +D channel: {names!r}"
        )
    finally:
        await stub.disconnect()


async def test_d_combined_with_status_is_status(ircd_hub, make_client, oper):
    """``:od`` means op: the d is dropped, not treated as an unknown flag."""
    chan = "#dj7"
    await _watch_violations(oper)
    await _collect_wallops(oper, seconds=0.5)

    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa7")
        await stub._send(f"{stub.server_numnick} B {chan} 1700000000 +t {sa}:od")
        await asyncio.sleep(0.5)

        client = await make_client("dj7watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        names = await _names(client, chan)
        assert "@sa7" in names, f"combined specifier lost the op: {names!r}"

        violations = [w for w in await _collect_wallops(oper, seconds=1.5)
                      if "Protocol Violation" in w]
        assert not violations, (
            "':od' was reported as a protocol violation: " + "; ".join(violations)
        )
    finally:
        await stub.disconnect()


async def test_d_from_p10_stub_is_protocol_violation(ircd_hub, oper):
    """``d`` has no meaning on a P10 link: it is an invalid flag."""
    chan = "#dj8"
    await _watch_violations(oper)
    await _collect_wallops(oper, seconds=0.5)

    stub = await _link(ircd_hub, 10)
    try:
        sa = await stub.introduce_user("sa8")
        await stub._send(f"{stub.server_numnick} B {chan} 1700000000 +t {sa}:d")

        text = await _wait_for_wallops(oper, "Invalid flag 'd'")
        assert "Protocol Violation" in text, text

        # The link survives the violation.
        await stub._send(f"{stub.server_numnick} G :dj8-alive")
        pong = await stub.wait_for_token("Z", timeout=5.0)
        assert "dj8-alive" in pong, pong
    finally:
        await stub.disconnect()
