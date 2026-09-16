"""Bans travel with their setter and set time on a P11 link.

``struct Ban`` has always stored who set a ban and when, and ``RPL_BANLIST``
(367) reports both, but the ``%`` section of a P10 ``BURST`` carries bare
masks.  A receiver therefore invents ``who = "*"`` and ``when = now`` for
every ban it learns over a net burst, so the two values differ on every
server of the network and change again on each split/heal.

P11 sends ``<mask> <ts> <who>`` triples instead (doc/P11.md 8.1).  These
tests pin the emitted form on both link protocols, the receiver's framing
validation and repairs, the deterministic merge that keeps a ban's metadata
converging when both sides already know the mask, and the fact that a
metadata-only change is silent toward local clients.
"""

from __future__ import annotations

import asyncio
import itertools
import time

import pytest

from p11_server import P11Server, strip_msg_tags

pytestmark = pytest.mark.single_server

# A stub announces its client capacity as a numnick mask and the ircd uses it
# verbatim as the slot mask for the link's users; only 2**n - 1 gives each
# introduced user its own slot.
STUB_CAPACITY = 63

# include/ircd_defs.h
NICKLEN = 15

# include/ircd.h: any timestamp older than this is bogus and is repaired.
OLDEST_TS = 780000000

_sync_seq = itertools.count(1)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


async def _link(hub, protocol: int, numeric: int = 5,
                name: str = "notulined.test.net") -> P11Server:
    """Link a stub server of the given protocol and finish the handshake."""
    stub = P11Server(name=name, numeric=numeric, password="testpass",
                     server_flags="", protocol=protocol,
                     max_clients=STUB_CAPACITY)
    await stub.connect(hub["host"], hub["server_port"])
    await stub.handshake()
    return stub


async def _sync(client):
    """Flush pending and buffered replies so the next query reads its own."""
    token = f"sync{next(_sync_seq)}"
    await client.send(f"PING :{token}")
    while True:
        msg = await client.wait_for("PONG", timeout=10.0)
        if msg.params and msg.params[-1] == token:
            break
    client._buffer.clear()


async def _ban_list(client, chan: str) -> list[tuple[str, str, str]]:
    """The (mask, who, ts) triples of the 367 replies for ``chan``."""
    await _sync(client)
    await client.send(f"MODE {chan} b")
    bans: list[tuple[str, str, str]] = []
    while True:
        msg = await client.recv(timeout=5.0)
        if msg.command == "367":
            bans.append((msg.params[2], msg.params[3], msg.params[4]))
        elif msg.command == "368":
            break
    return bans


def _burst_lines(stub: P11Server, chan: str) -> list[str]:
    """Every BURST line for ``chan`` the stub has read, tags stripped."""
    lines = []
    for line in stub.received:
        payload = strip_msg_tags(line)
        parts = payload.split()
        if len(parts) >= 3 and parts[1] == "B" and parts[2].lower() == chan.lower():
            lines.append(payload)
    return lines


def _burst_line(stub: P11Server, chan: str) -> str:
    """The single BURST line for ``chan``."""
    lines = _burst_lines(stub, chan)
    assert lines, (
        f"no BURST for {chan} seen; lines="
        f"{[strip_msg_tags(l) for l in stub.received]!r}"
    )
    return lines[0]


def _burst_ts(stub: P11Server, chan: str) -> str:
    """The channel creation time the hub reported for ``chan``."""
    return _burst_line(stub, chan).split()[3]


def _ban_section(line: str) -> str:
    """The text after the ``:%`` of a BURST line, or "" when there is none."""
    idx = line.find(":%")
    return line[idx + 2:] if idx >= 0 else ""


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
        except (asyncio.TimeoutError, TimeoutError):
            return texts
        texts.append(msg.params[-1] if msg.params else "")


async def _wait_for_violation(oper, needle: str, timeout: float = 6.0) -> str:
    """Wait for a protocol-violation wallops whose text contains ``needle``."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    seen: list[str] = []
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            msg = await oper.wait_for("WALLOPS", timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError):
            break
        text = msg.params[-1] if msg.params else ""
        seen.append(text)
        if "Protocol Violation" in text and needle in text:
            return text
    raise AssertionError(
        f"no 'Protocol Violation' wallops containing {needle!r}; saw {seen!r}"
    )


async def _assert_no_mode(client, chan: str, seconds: float = 2.0):
    """Fail if a MODE for ``chan`` reaches ``client`` within ``seconds``."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + seconds
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return
        try:
            msg = await client.recv(timeout=remaining)
        except (asyncio.TimeoutError, TimeoutError):
            return
        if (msg.command == "MODE" and msg.params
                and msg.params[0].lower() == chan.lower()):
            raise AssertionError(
                f"metadata-only ban update produced a MODE: {msg.params!r}"
            )


async def _set_ban(client, chan: str, mask: str):
    """Set one ban and wait for the echo."""
    await client.send(f"MODE {chan} +b {mask}")
    await client.wait_for("MODE", timeout=5.0)


async def _channel_with_ban(make_client, chan: str, nick: str, mask: str):
    """A channel with one client and one ban; returns (client, ban_ts)."""
    client = await make_client(nick)
    await client.send(f"JOIN {chan}")
    await client.wait_for("JOIN", timeout=5.0)
    await _set_ban(client, chan, mask)

    bans = await _ban_list(client, chan)
    assert len(bans) == 1 and bans[0][0] == mask, f"ban not set: {bans!r}"
    assert bans[0][1] == nick, f"unexpected setter: {bans!r}"
    return client, bans[0][2]


# --------------------------------------------------------------------------
# emit
# --------------------------------------------------------------------------


async def test_emit_triples_to_p11_stub(ircd_hub, make_client):
    """A P11 peer gets ``<mask> <ts> <who>`` for every ban."""
    chan, mask = "#bm1", "*!*@spam.example"
    client, ts = await _channel_with_ban(make_client, chan, "bm1set", mask)

    stub = await _link(ircd_hub, 11)
    try:
        line = _burst_line(stub, chan)
        assert line.endswith(f":%{mask} {ts} bm1set"), (
            f"P11 peer did not get the ban triple: {line!r}"
        )
    finally:
        await stub.disconnect()


async def test_emit_mask_only_to_p10_stub(ircd_hub, make_client):
    """A P10 peer gets the bare mask, exactly as 2.10.12 sends it."""
    chan, mask = "#bm2", "*!*@spam.example"
    client, ts = await _channel_with_ban(make_client, chan, "bm2set", mask)

    stub = await _link(ircd_hub, 10)
    try:
        line = _burst_line(stub, chan)
        assert line.endswith(f":%{mask}"), (
            f"P10 peer did not get a mask-only ban list: {line!r}"
        )
        section = _ban_section(line)
        assert ts not in section and "bm2set" not in section, (
            f"P10 peer received ban metadata: {line!r}"
        )
    finally:
        await stub.disconnect()


# --------------------------------------------------------------------------
# parse
# --------------------------------------------------------------------------


async def test_parse_triples_from_p11_stub(ircd_hub, make_client):
    """A triple from a P11 peer is stored verbatim."""
    chan = "#bm3"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa3")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@x.example 1700000100 zed"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm3watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [
            ("*!*@x.example", "zed", "1700000100")
        ]
    finally:
        await stub.disconnect()


async def test_comma_in_mask_is_one_ban(ircd_hub, make_client):
    """Space, not comma, delimits the ban list: a comma stays in the mask."""
    chan = "#bm4"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa4")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@a,b.example 1700000100 zed"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm4watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [
            ("*!*@a,b.example", "zed", "1700000100")
        ]
    finally:
        await stub.disconnect()


async def test_arity_mismatch_rejects_section_keeps_members(ircd_hub, make_client,
                                                            oper):
    """A token count that is not a multiple of three drops the whole list."""
    chan = "#bm5"
    await _watch_violations(oper)
    await _collect_wallops(oper, seconds=0.5)

    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa5")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example 1700000100 zed *!*@two.example 1700000100"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm5watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [], "a framing error applied bans"

        await _sync(client)
        await client.send(f"NAMES {chan}")
        msgs = await client.collect_until("366", timeout=5.0)
        names: list[str] = []
        for msg in msgs:
            if msg.command == "353":
                names.extend(n.lstrip("@+!") for n in msg.params[-1].split())
        assert "sa5" in names, f"members were dropped with the ban list: {names!r}"

        await _wait_for_violation(oper, "not a multiple of 3")
    finally:
        await stub.disconnect()


async def test_non_numeric_ts_rejects_section(ircd_hub, make_client, oper):
    """A ``<ts>`` that is not all digits drops the whole list."""
    chan = "#bm6"
    await _watch_violations(oper)
    await _collect_wallops(oper, seconds=0.5)

    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa6")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example abc zed"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm6watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [], "a bogus ts applied the ban"
        # The peer's own bytes are never echoed into a network-wide wallops:
        # the violation reports the length of the offending field instead.
        text = await _wait_for_violation(
            oper, "Invalid ban timestamp (3 bytes, not numeric)")
        assert "abc" not in text, (
            f"the raw peer bytes reached the wallops after all: {text!r}"
        )
    finally:
        await stub.disconnect()


async def test_out_of_range_ts_becomes_now(ircd_hub, make_client):
    """A ts below OLDEST_TS is repaired, not a reason to drop the ban."""
    chan = "#bm7"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa7")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example 5 zed"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm7watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        bans = await _ban_list(client, chan)
        assert len(bans) == 1, f"the ban was dropped over its ts: {bans!r}"
        mask, who, ts = bans[0]
        assert (mask, who) == ("*!*@one.example", "zed"), f"unexpected ban: {bans!r}"
        assert abs(int(ts) - time.time()) < 30, f"ts was not repaired: {ts!r}"
    finally:
        await stub.disconnect()


async def test_future_ts_becomes_now(ircd_hub, make_client):
    """A ts more than 60s in the future is repaired, not a reason to drop it.

    Mirrors test_out_of_range_ts_becomes_now, at the other end of the valid
    range (doc/P11.md 8.1 receiver-validation rule 4).
    """
    chan = "#bm14"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa14")
        future_ts = int(time.time()) + 3600
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example {future_ts} zed"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm14watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        bans = await _ban_list(client, chan)
        assert len(bans) == 1, f"the ban was dropped over its future ts: {bans!r}"
        mask, who, ts = bans[0]
        assert (mask, who) == ("*!*@one.example", "zed"), f"unexpected ban: {bans!r}"
        assert abs(int(ts) - time.time()) < 30, f"future ts was not repaired: {ts!r}"
    finally:
        await stub.disconnect()


async def test_long_who_is_truncated(ircd_hub, make_client):
    """A ``<who>`` longer than NICKLEN is truncated, not rejected."""
    chan = "#bm8"
    long_who = "abcdefghijklmnopqrst"
    assert len(long_who) > NICKLEN

    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa8")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example 1700000100 {long_who}"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm8watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [
            ("*!*@one.example", long_who[:NICKLEN], "1700000100")
        ]
    finally:
        await stub.disconnect()


async def test_p10_stub_ban_has_unknown_metadata(ircd_hub, make_client):
    """A P10 link cannot say who set a ban: the receiver invents the values."""
    chan = "#bm9"
    stub = await _link(ircd_hub, 10)
    try:
        sa = await stub.introduce_user("sa9")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm9watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        bans = await _ban_list(client, chan)
        assert len(bans) == 1, f"the P10 ban was lost: {bans!r}"
        mask, who, ts = bans[0]
        assert (mask, who) == ("*!*@one.example", "*"), f"unexpected ban: {bans!r}"
        assert abs(int(ts) - time.time()) < 30, f"unexpected ts: {ts!r}"
    finally:
        await stub.disconnect()


# --------------------------------------------------------------------------
# merge
# --------------------------------------------------------------------------


async def test_metadata_update_is_silent_and_wins_by_lower_ts(ircd_hub, make_client):
    """A lower ``when`` overwrites ours in place, with no MODE to clients."""
    chan, mask = "#bm10", "*!*@m.example"
    client, ts = await _channel_with_ban(make_client, chan, "bm10set", mask)
    older = int(ts) - 100

    stub = await _link(ircd_hub, 11)
    try:
        cts = _burst_ts(stub, chan)
        await stub._send(
            f"{stub.server_numnick} B {chan} {cts} :%{mask} {older} older"
        )
        await _assert_no_mode(client, chan, seconds=2.0)

        assert await _ban_list(client, chan) == [(mask, "older", str(older))]
    finally:
        await stub.disconnect()


async def test_known_setter_beats_star(ircd_hub, make_client):
    """An unknown setter never wins, however much older its timestamp."""
    chan, mask = "#bm11", "*!*@m.example"
    client, ts = await _channel_with_ban(make_client, chan, "bm11set", mask)
    older = int(ts) - 100

    stub = await _link(ircd_hub, 11)
    try:
        cts = _burst_ts(stub, chan)
        await stub._send(
            f"{stub.server_numnick} B {chan} {cts} :%{mask} {older} *"
        )
        await asyncio.sleep(1.0)

        assert await _ban_list(client, chan) == [(mask, "bm11set", ts)]
    finally:
        await stub.disconnect()


async def test_equal_ts_smaller_who_wins(ircd_hub, make_client):
    """With equal timestamps the strcmp()-smaller setter is the tie-break."""
    chan, mask = "#bm12", "*!*@m.example"
    client, ts = await _channel_with_ban(make_client, chan, "bm12set", mask)

    stub = await _link(ircd_hub, 11)
    try:
        cts = _burst_ts(stub, chan)
        await stub._send(
            f"{stub.server_numnick} B {chan} {cts} :%{mask} {ts} aaa"
        )
        await asyncio.sleep(1.0)

        assert await _ban_list(client, chan) == [(mask, "aaa", ts)]
    finally:
        await stub.disconnect()


# --------------------------------------------------------------------------
# continuation
# --------------------------------------------------------------------------


async def test_line_continuation_keeps_all_bans(ircd_hub, make_client):
    """Triples spill onto continuation lines without losing a ban."""
    chan = "#bm13"
    # pretty_mask() cuts a host longer than HOSTLEN (63) off at the *start*,
    # so the part that makes each mask unique has to be at the end or all
    # fourteen would collapse onto one another.  63 = 47 + len(".host-NN.example").
    pad = "a" * 47
    masks = [f"*!*@{pad}.host-{n:02d}.example" for n in range(1, 15)]
    assert all(len(m) == 67 for m in masks), "masks must stay within HOSTLEN"

    client = await make_client("bm13set")
    await client.send(f"JOIN {chan}")
    await client.wait_for("JOIN", timeout=5.0)

    # MAXMODEPARAMS is 6, so five masks per MODE stay well inside both the
    # parameter and the line limit.  parse.c charges a local client
    # "2 + length/120" seconds of flood penalty per message and stops reading
    # from it 10 seconds ahead, so each of these ~360 byte MODEs costs four
    # seconds and has to be slept off or the following PING never lands.
    for start in range(0, len(masks), 5):
        chunk = masks[start:start + 5]
        await client.send(f"MODE {chan} +{'b' * len(chunk)} {' '.join(chunk)}")
        await client.wait_for("MODE", timeout=5.0)
        await asyncio.sleep(4.5)

    accepted = {mask for mask, _who, _ts in await _ban_list(client, chan)}
    assert len(accepted) == len(masks), (
        f"the server accepted only {len(accepted)} of {len(masks)} bans: "
        f"missing {sorted(set(masks) - accepted)!r}"
    )

    stub = await _link(ircd_hub, 11)
    try:
        await stub.drain_messages(timeout=1.0)
        lines = _burst_lines(stub, chan)
        assert len(lines) >= 2, (
            f"expected the burst to be split; got {len(lines)} line(s): {lines!r}"
        )

        triples: list[tuple[str, str, str]] = []
        for line in lines:
            section = _ban_section(line)
            if not section:
                continue
            tokens = section.split()
            assert len(tokens) % 3 == 0, f"ragged ban section in {line!r}"
            for i in range(0, len(tokens), 3):
                triples.append(tuple(tokens[i:i + 3]))

        assert {t[0] for t in triples} == accepted, (
            f"burst masks {sorted(t[0] for t in triples)!r} != "
            f"channel masks {sorted(accepted)!r}"
        )
        assert len(triples) == len(accepted), f"duplicated bans: {triples!r}"
        for mask, ts, who in triples:
            assert ts.isdigit(), f"non-numeric ts for {mask}: {ts!r}"
            assert who == "bm13set", f"wrong setter for {mask}: {who!r}"
    finally:
        await stub.disconnect()


async def test_ts_exactly_oldest_ts_is_kept(ircd_hub, make_client):
    """OLDEST_TS itself is in range: the boundary is ``<``, not ``<=``.

    The companion of test_out_of_range_ts_becomes_now: one second below this
    value is repaired, this value is not.
    """
    chan = "#bm15"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa15")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example {OLDEST_TS} zed"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm15watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [
            ("*!*@one.example", "zed", str(OLDEST_TS))
        ]
    finally:
        await stub.disconnect()


async def test_ts_below_oldest_ts_becomes_now(ircd_hub, make_client):
    """One second below OLDEST_TS is out of range and is repaired."""
    chan = "#bm16"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa16")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example {OLDEST_TS - 1} zed"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm16watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        bans = await _ban_list(client, chan)
        assert len(bans) == 1, f"the ban was dropped over its ts: {bans!r}"
        mask, who, ts = bans[0]
        assert (mask, who) == ("*!*@one.example", "zed"), f"unexpected ban: {bans!r}"
        assert abs(int(ts) - time.time()) < 30, f"ts was not repaired: {ts!r}"
    finally:
        await stub.disconnect()


# --------------------------------------------------------------------------
# setter validation
# --------------------------------------------------------------------------


async def test_who_with_invalid_nick_chars_becomes_star(ircd_hub, make_client):
    """A setter that is not a valid nick degrades to the unknown setter.

    ``<who>`` is echoed in RPL_BANLIST and relayed onward verbatim, so a peer
    must not be able to park arbitrary bytes in it.  Anything that is not a
    nick is stored as ``*``; the ban itself is still kept.
    """
    chan = "#bm17"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa17")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example 1700000100 bad#nick"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm17watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [
            ("*!*@one.example", "*", "1700000100")
        ]
    finally:
        await stub.disconnect()


async def test_who_star_is_kept(ircd_hub, make_client):
    """The control case: ``*`` is the unknown setter and is not a nick.

    It has to survive the nick-character check that rewrites everything else.
    """
    chan = "#bm18"
    stub = await _link(ircd_hub, 11)
    try:
        sa = await stub.introduce_user("sa18")
        await stub._send(
            f"{stub.server_numnick} B {chan} 1700000000 +t {sa} "
            f":%*!*@one.example 1700000100 *"
        )
        await asyncio.sleep(0.5)

        client = await make_client("bm18watch")
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN", timeout=5.0)

        assert await _ban_list(client, chan) == [
            ("*!*@one.example", "*", "1700000100")
        ]
    finally:
        await stub.disconnect()
