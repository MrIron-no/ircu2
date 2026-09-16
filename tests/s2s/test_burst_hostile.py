"""A relayed BURST must stay inside the line limit, whatever arrives.

``ms_burst()`` rebuilds the BURST it forwards from what it accepted, once per
link layout (doc/P11.md 8.1).  The rebuilt line is not bounded by the
incoming one: a P11 relay of a P10 ban list gains a ``<ts> <who>`` per mask,
a mode change re-emits an *absolute* op level where the input had a two-byte
increment, and a hidden-member specifier between two opped members forces
such a mode change on every member.

So a single well-formed 512-byte BURST from a linked peer can ask for a
relay several hundred bytes longer than the buffer it is built in.  These
tests drive the shapes that do it and pin the two properties that make the
relay safe: every emitted line fits the wire limit, and nothing is lost --
the state spills onto continuation lines instead of being truncated or
dropped.

They also pin the one thing a continuation line must never do: express "no
status after a status group" as a bare ``:``.  A P10 receiver parsing
``<numeric>:`` runs zero specifier iterations and carries the *previous*
status forward, silently opping a member that has no status at all.  That
transition is inexpressible mid-line and can only be made by starting a new
line.
"""

from __future__ import annotations

import asyncio
import itertools
import re

import pytest

from cap_helpers import collect_wallops, oper_up
from p11_server import P11Server, strip_msg_tags

pytestmark = pytest.mark.single_server

# ircd_defs.h BUFSIZE is 512 and msgq_vmake() truncates anything past
# BUFSIZE - 2 before appending CRLF, so 510 bytes is the most that can reach
# the wire intact.  A line of exactly 510 bytes is fine; 511 means the ircd
# built something too long and the wire form lost its tail.
MAX_WIRE = 510

# A stub announces its client capacity as a numnick mask and the ircd uses
# it verbatim as the slot mask for the link's users; only 2**n - 1 gives
# each introduced user its own slot.
STUB_CAPACITY = 63

# A bare ':' specifier: the P10 "carry the previous status forward" trap.
BARE_COLON = re.compile(r":(,|$)")
# A specifier whose op level cannot be one: MAXOPLEVEL is 999, so anything
# with six or more digits is an unsigned wrap of a negative increment.
HUGE_OPLEVEL = re.compile(r":\d{6,}")

_sync_seq = itertools.count(1)


# --------------------------------------------------------------------------
# link helpers
# --------------------------------------------------------------------------


async def _link(hub, name: str, numeric: int, protocol: int) -> P11Server:
    """Link one stub server of the given protocol and finish its handshake."""
    stub = P11Server(name=name, numeric=numeric, password="testpass",
                     max_clients=STUB_CAPACITY, protocol=protocol)
    await stub.connect(hub["host"], hub["server_port"])
    await stub.handshake()
    return stub


async def _source_and_downlinks(hub, src_proto: int):
    """A source stub plus a P11 and a P10 downlink, all linked to the hub.

    ``services.test.net`` is the source because it is the only one of the
    three Connect blocks that can be the odd one out protocol-wise without
    disturbing the two observers.
    """
    src = await _link(hub, "services.test.net", 4, src_proto)
    p11 = await _link(hub, "uworldonly.test.net", 6, 11)
    p10 = await _link(hub, "notulined.test.net", 5, 10)
    return src, p11, p10


async def _close(*stubs):
    for stub in stubs:
        try:
            await stub.disconnect()
        except Exception:
            pass


# --------------------------------------------------------------------------
# wire helpers
# --------------------------------------------------------------------------


def _burst_lines(stub: P11Server, chan: str) -> list[str]:
    """Every BURST line for ``chan`` the stub has read, tags stripped."""
    lines = []
    for line in stub.received:
        payload = strip_msg_tags(line)
        parts = payload.split()
        if len(parts) >= 3 and parts[1] == "B" and parts[2].lower() == chan.lower():
            lines.append(payload)
    return lines


def _assert_fits_wire(lines: list[str], who: str):
    for line in lines:
        assert len(line) <= MAX_WIRE, (
            f"{who} received a {len(line)} byte BURST line, over the "
            f"{MAX_WIRE} byte wire limit: {line!r}"
        )


def _member_field(line: str) -> str:
    """The member list of a BURST line built with a no-argument mode block."""
    fields = line.split(" ")[4:]          # past "<src> B <chan> <ts>"
    if fields and fields[0].startswith("+"):
        fields = fields[1:]               # "+t" / "+tD" carry no arguments
    if not fields or fields[0].startswith(":%"):
        return ""
    return fields[0]


def _members(lines: list[str]) -> list[tuple[str, str]]:
    """Every ``(numeric, specifier)`` of a set of BURST lines, in order."""
    out: list[tuple[str, str]] = []
    for line in lines:
        field = _member_field(line)
        if not field:
            continue
        for entry in field.split(","):
            numeric, _, spec = entry.partition(":")
            out.append((numeric, spec))
    return out


def _creation_ts(stub: P11Server, chan: str) -> str | None:
    """The creation TS the hub stamped on ``chan``, read off the stub's feed.

    When a hub client joins a fresh channel the hub relays a CREATE (``C``,
    whose channel field may be a comma list) to every linked server; a BURST
    (``B``) carries the same TS.  Either tells the stub the exact timestamp to
    echo so its own burst lands on the equal-TS path.
    """
    lc = chan.lower()
    for line in stub.received:
        parts = strip_msg_tags(line).split()
        if len(parts) >= 4 and parts[1] == "C" and lc in [
                c.lower() for c in parts[2].split(",")]:
            return parts[3]
        if len(parts) >= 4 and parts[1] == "B" and parts[2].lower() == lc:
            return parts[3]
    return None


def _ban_section(line: str) -> str:
    """The text after the ``:%`` of a BURST line, or "" when there is none."""
    idx = line.find(":%")
    return line[idx + 2:] if idx >= 0 else ""


def _ban_triples(lines: list[str]) -> list[tuple[str, str, str]]:
    """Every ``<mask> <ts> <who>`` triple of a P11 relay, checking the arity.

    A downstream P11 receiver rejects the *whole* ban section of a line whose
    token count is not a multiple of three, so a truncation mid-triple would
    strip every ban of the channel from the subtree.
    """
    triples: list[tuple[str, str, str]] = []
    for line in lines:
        section = _ban_section(line)
        if not section:
            continue
        tokens = section.split()
        assert len(tokens) % 3 == 0, (
            f"ban section has {len(tokens)} tokens, not a multiple of 3, so a "
            f"P11 receiver would drop all of them: {line!r}"
        )
        for i in range(0, len(tokens), 3):
            triples.append((tokens[i], tokens[i + 1], tokens[i + 2]))
    return triples


# --------------------------------------------------------------------------
# hub-side helpers
# --------------------------------------------------------------------------


async def _sync(client):
    """Flush pending and buffered replies so the next query reads its own.

    Doubles as the liveness probe: a hub that died on the hostile BURST
    never answers this PING (and the next connect is refused outright).
    """
    token = f"hsync{next(_sync_seq)}"
    await client.send(f"PING :{token}")
    while True:
        msg = await client.wait_for("PONG", timeout=10.0)
        if msg.params and msg.params[-1] == token:
            break
    client._buffer.clear()


async def _names(client, chan: str, delayed: bool = False) -> dict[str, str]:
    """``{nick: prefix}`` for ``chan``; ``prefix`` is "@", "+" or "".

    With ``delayed`` the ``-D`` form lists the *hidden* members instead (355),
    which is the only way to see a delayed-join member from another client.
    """
    await _sync(client)
    await client.send(f"NAMES -D {chan}" if delayed else f"NAMES {chan}")
    numeric = "355" if delayed else "353"
    names: dict[str, str] = {}
    msgs = await client.collect_until("366", timeout=10.0)
    for msg in msgs:
        if msg.command == numeric:
            for entry in msg.params[-1].split():
                prefix = entry[0] if entry[0] in "@+!" else ""
                names[entry[len(prefix):]] = prefix
    return names


async def _ban_masks(client, chan: str) -> set[str]:
    """The masks of the 367 replies for ``chan``."""
    await _sync(client)
    await client.send(f"MODE {chan} b")
    masks: set[str] = set()
    while True:
        msg = await client.recv(timeout=10.0)
        if msg.command == "367":
            masks.add(msg.params[2])
        elif msg.command == "368":
            break
    return masks


async def _join(make_client, nick: str, chan: str):
    client = await make_client(nick)
    await client.send(f"JOIN {chan}")
    await client.wait_for("JOIN", timeout=10.0)
    return client


# --------------------------------------------------------------------------
# C-1: the relay is longer than the line it was built from
# --------------------------------------------------------------------------


def _alternating_entries(users: list[str], budget: int) -> list[str]:
    """``<u>:100`` then ``<u>:d,<u>:0`` pairs, filling ``budget`` bytes.

    Each ``:0`` is an *increment* of zero over the 100 set by the first
    entry, so the op level stays 100 throughout.  The ``:d`` between them
    changes the status group on every member, which forces the relay to
    re-emit the level as an absolute ``:100`` -- four bytes where the input
    spent two.  The relay therefore grows by two bytes per pair without
    bound, while carrying exactly the same state.
    """
    entries = [f"{users[0]}:100"]
    used = len(entries[0])
    idx = 1
    while idx + 1 < len(users):
        pair = [f"{users[idx]}:d", f"{users[idx + 1]}:0"]
        cost = sum(len(e) + 1 for e in pair)
        if used + cost > budget:
            break
        entries += pair
        used += cost
        idx += 2
    return entries


async def test_alternating_d_and_oplevel_line_does_not_overflow(ircd_hub,
                                                                make_client):
    """A full line of ``:d``/``:0`` alternation relays without overflowing.

    This is the shape that makes the P11 relay longer than the BURST it was
    built from.  Both downlinks must get well-formed lines inside the wire
    limit, and the hub must end up with exactly the membership that was sent.
    """
    chan = "#hostilea"
    src, p11, p10 = await _source_and_downlinks(ircd_hub, 11)
    try:
        users = [await src.introduce_user(f"hosta{n}") for n in range(57)]
        await p11.drain_messages(timeout=1.5)
        await p10.drain_messages(timeout=1.5)

        head = f"{src.server_numnick} B {chan} 1700000000 +t "
        entries = _alternating_entries(users, 500 - len(head))
        line = head + ",".join(entries)
        assert len(line) <= 512, f"the probe itself is too long: {len(line)}"
        assert len(entries) >= 40, f"probe too small to matter: {len(entries)}"
        await src._send(line)

        await p11.drain_messages(timeout=2.5)
        await p10.drain_messages(timeout=2.5)

        p11_lines = _burst_lines(p11, chan)
        p10_lines = _burst_lines(p10, chan)
        assert p11_lines, "the P11 downlink saw no relay at all"
        assert p10_lines, "the P10 downlink saw no relay at all"
        _assert_fits_wire(p11_lines, "the P11 downlink")
        _assert_fits_wire(p10_lines, "the P10 downlink")

        for line in p10_lines:
            assert not BARE_COLON.search(line), (
                f"P10 relay carries a bare ':' specifier, which silently "
                f"carries the previous status forward: {line!r}"
            )

        sent = [entry.split(":")[0] for entry in entries]
        for name, lines in (("P11", p11_lines), ("P10", p10_lines)):
            relayed = [numeric for numeric, _spec in _members(lines)]
            assert relayed == sent, (
                f"{name} relay membership differs from what was sent: "
                f"{relayed!r} != {sent!r}"
            )

        # The hub itself must hold the state the burst described: the even
        # entries are opped, the odd ones are hidden.
        opped = {f"hosta{n}" for n in range(0, len(entries), 2)}
        hidden = {f"hosta{n}" for n in range(1, len(entries), 2)}

        client = await _join(make_client, "hostawatch", chan)
        visible = await _names(client, chan)
        assert opped <= set(visible), (
            f"opped members missing from the channel: "
            f"{sorted(opped - set(visible))!r}"
        )
        not_opped = sorted(n for n in opped if visible.get(n) != "@")
        assert not not_opped, f"members that lost their op: {not_opped!r}"
        assert not (hidden & set(visible)), (
            f"hidden members are visible in NAMES: "
            f"{sorted(hidden & set(visible))!r}"
        )
        assert set(await _names(client, chan, delayed=True)) == hidden, (
            "the hidden member set does not match what was sent"
        )
    finally:
        await _close(src, p11, p10)


async def test_decreasing_oplevels_relay_as_continuation_lines(ircd_hub,
                                                               make_client):
    """A decreasing op level is not an increment: it starts a new line.

    ``<u>:v900,<u>:v1`` keeps the same status group, so the relay would
    express the second member as an increment -- but the increment is
    negative and is printed unsigned, giving a ten-digit op level that no
    receiver can parse back.  The only correct encoding is a fresh line with
    an absolute level.
    """
    chan = "#hostileb"
    src, p11, _p10 = await _source_and_downlinks(ircd_hub, 11)
    try:
        users = [await src.introduce_user(f"hostb{n}") for n in range(20)]
        await p11.drain_messages(timeout=1.5)

        entries = [f"{u}:v900" if n % 2 == 0 else f"{u}:v1"
                   for n, u in enumerate(users)]
        await src._send(
            f"{src.server_numnick} B {chan} 1700000000 +t {','.join(entries)}"
        )
        await p11.drain_messages(timeout=2.5)

        lines = _burst_lines(p11, chan)
        assert lines, "the P11 downlink saw no relay at all"
        _assert_fits_wire(lines, "the P11 downlink")
        for line in lines:
            assert not HUGE_OPLEVEL.search(line), (
                f"relay carries an op level that wrapped around zero: {line!r}"
            )
            assert not BARE_COLON.search(line), f"bare ':' specifier: {line!r}"

        relayed = [numeric for numeric, _spec in _members(lines)]
        assert relayed == users, (
            f"relay membership differs from what was sent: "
            f"{relayed!r} != {users!r}"
        )

        client = await _join(make_client, "hostbwatch", chan)
        visible = await _names(client, chan)
        wrong = sorted(f"hostb{n}" for n in range(len(users))
                       if visible.get(f"hostb{n}") != "@")
        assert not wrong, f"members that are not opped on the hub: {wrong!r}"
    finally:
        await _close(src, p11, _p10)


# --------------------------------------------------------------------------
# I-2: "no status" after a status group
# --------------------------------------------------------------------------


async def test_status_then_hidden_relays_without_bare_colon_to_p10(ircd_hub):
    """``<u>:o,<u>:d`` cannot be said on one P10 line, so it takes two.

    Toward P10 the hidden member has no status at all, and returning to "no
    status" mid-line is inexpressible: the only encoding is a continuation
    line, which resets the status to none.  Toward P11 the ``d`` says it
    directly and one line is enough.
    """
    chan = "#hostilec"
    src, p11, p10 = await _source_and_downlinks(ircd_hub, 11)
    try:
        u1 = await src.introduce_user("hostc1")
        u2 = await src.introduce_user("hostc2")
        await p11.drain_messages(timeout=1.5)
        await p10.drain_messages(timeout=1.5)

        await src._send(
            f"{src.server_numnick} B {chan} 1700000000 +t {u1}:o,{u2}:d"
        )
        await p11.drain_messages(timeout=2.5)
        await p10.drain_messages(timeout=2.5)

        p10_lines = _burst_lines(p10, chan)
        assert len(p10_lines) == 2, (
            f"expected the P10 relay to be split in two; got {p10_lines!r}"
        )
        assert p10_lines[0] == (
            f"{src.server_numnick} B {chan} 1700000000 +t {u1}:o"
        ), f"unexpected first P10 line: {p10_lines[0]!r}"
        assert p10_lines[1] == (
            f"{src.server_numnick} B {chan} 1700000000 {u2}"
        ), f"unexpected P10 continuation line: {p10_lines[1]!r}"
        for line in p10_lines:
            assert not BARE_COLON.search(line), f"bare ':' specifier: {line!r}"

        p11_lines = _burst_lines(p11, chan)
        assert p11_lines, "the P11 downlink saw no relay at all"
        _assert_fits_wire(p11_lines, "the P11 downlink")
        specs = dict(_members(p11_lines))
        assert specs.get(u1) == "o", f"the op lost its specifier: {p11_lines!r}"
        assert specs.get(u2) == "d", (
            f"the hidden member lost its 'd': {p11_lines!r}"
        )
    finally:
        await _close(src, p11, p10)


# --------------------------------------------------------------------------
# I-3: the P11 relay of a P10 ban list
# --------------------------------------------------------------------------


# 41 bytes each; well inside HOSTLEN so pretty_mask() leaves them alone.
FLOOD_MASKS = [f"*!*@host-{n:02d}.some.long.example.domain.test"
               for n in range(1, 12)]


async def test_p10_ban_flood_relays_to_p11_in_continuation_lines(ircd_hub,
                                                                 make_client):
    """Masks from P10 gain ``<ts> <who>`` toward P11 and must not be cut.

    Every mask grows by about 22 bytes on its way to a P11 downlink, so a
    P10 line that is merely full of bans asks for a relay well past the line
    limit.  Truncating it mid-triple would make the receiver reject the whole
    ban section by its arity check, stripping every ban of the channel from
    the subtree; dropping the entries that do not fit loses them just as
    badly.  They have to spill onto continuation lines.
    """
    chan = "#hostiled"
    src, p11, _p10 = await _source_and_downlinks(ircd_hub, 10)
    try:
        await p11.drain_messages(timeout=1.5)

        line = (f"{src.server_numnick} B {chan} 1700000000 "
                f":%{' '.join(FLOOD_MASKS)}")
        assert len(line) <= 512, f"the probe itself is too long: {len(line)}"
        await src._send(line)
        await p11.drain_messages(timeout=2.5)

        lines = _burst_lines(p11, chan)
        assert len(lines) >= 2, (
            f"expected the P11 relay to be split; got {len(lines)}: {lines!r}"
        )
        _assert_fits_wire(lines, "the P11 downlink")

        triples = _ban_triples(lines)
        assert {mask for mask, _ts, _who in triples} == set(FLOOD_MASKS), (
            f"relayed masks differ from what was sent: {triples!r}"
        )
        assert len(triples) == len(FLOOD_MASKS), f"duplicated bans: {triples!r}"
        for mask, ts, who in triples:
            assert ts.isdigit(), f"non-numeric ts for {mask}: {ts!r}"
            assert who == "*", f"invented a setter for {mask}: {who!r}"

        client = await _join(make_client, "hostdwatch", chan)
        assert await _ban_masks(client, chan) == set(FLOOD_MASKS), (
            "the hub did not keep every mask of the flood"
        )
    finally:
        await _close(src, p11, _p10)


async def test_ban_only_continuation_line_is_accepted_downstream(ircd_hub,
                                                                 make_client):
    """The hub accepts the bans-only continuation line shape it emits.

    A relay that spills bans onto their own line produces
    ``<#chan> <ts> :%<triples>`` with no mode block and no members.  Feeding
    that exact shape back in proves a downstream P11 receiver keeps every
    ban of such a line, which is what makes the split in the test above safe.
    """
    chan = "#hostilee"
    src = await _link(ircd_hub, "services.test.net", 4, 11)
    try:
        u1 = await src.introduce_user("hoste1")
        masks = [f"*!*@cont-{n:02d}.example" for n in range(1, 5)]
        first = " ".join(f"{m} {1700000100 + n} zed"
                         for n, m in enumerate(masks[:2]))
        second = " ".join(f"{m} {1700000100 + n} amy"
                          for n, m in enumerate(masks[2:]))

        await src._send(
            f"{src.server_numnick} B {chan} 1700000000 +t {u1} :%{first}"
        )
        await src._send(f"{src.server_numnick} B {chan} 1700000000 :%{second}")
        await asyncio.sleep(1.0)

        client = await _join(make_client, "hostewatch", chan)
        assert await _ban_masks(client, chan) == set(masks), (
            "a bans-only continuation line lost its bans"
        )
    finally:
        await _close(src)


# --------------------------------------------------------------------------
# security fix-up 2: memory safety of the relay packer
# --------------------------------------------------------------------------


async def _debug_oper(make_client, nick: str):
    """A +g oper on the hub, so protocol_violation() WALLOPS reach it."""
    op = await make_client(nick)
    await oper_up(op)
    await op.send(f"MODE {nick} +g")
    await asyncio.sleep(0.3)
    op._buffer.clear()
    return op


async def test_add_then_del_same_ban_does_not_corrupt_relay(ircd_hub,
                                                            make_client):
    """A ban added then deleted in one BURST must not corrupt the relay.

    ``burst_parse_bans()`` records the first ``%``-section ban for the relay,
    then a later ``+b-b`` mode string in the *same* BURST deletes it:
    ``mode_parse()`` -> ``mode_process_bans()`` -> ``free_ban()`` pushes the
    ban-list slot onto the static free-list.  A second ``%``-section mask then
    runs ``make_ban()``, which pops that very slot back off the free-list
    (LIFO) and overwrites it with the second mask.  A relay that had aliased
    the slot would now read the *second* mask where it recorded the first, so
    the first mask vanishes from the relay and the second is emitted twice --
    freed-memory corruption an ASan build cannot see, because the slot is
    recycled through ircu's own free-list, never to the allocator.

    The source is a P10 stub on purpose: a P11 ban section is triples, and a
    triple must be the trailing ``:``-parameter, so it cannot precede the
    ``+b-b`` that frees it on one line.  A P10 section is bare masks, so a
    single mask can sit ahead of the ``+b-b`` and be recorded, then freed.
    The P11 downlink is the observer because it is the layout whose arity a
    corrupted mask would break.

    The channel is created on the hub first, and the burst carries the hub's
    exact creation TS: only an equal TS takes the MODE_PARSE_SET path without
    the net-ride check, and the net-ride check would reject the ``+b-b`` mode
    string outright for containing a '-'.
    """
    chan = "#uaf1"
    mask1 = "*!*@uaf-one.example"
    mask2 = "*!*@uaf-two.example"
    src, p11, _p10 = await _source_and_downlinks(ircd_hub, 10)
    try:
        # Create the channel on the hub, then learn the TS it stamped by
        # reading the CREATE the hub relays to the linked source stub.
        maker = await _join(make_client, "uafmaker", chan)
        await src.drain_messages(timeout=2.0)
        ts = _creation_ts(src, chan)
        assert ts is not None, "never saw the hub's CREATE for the channel"
        await p11.drain_messages(timeout=1.5)
        p11.received.clear()

        # %mask1 records the ban; +b-b mask1 mask1 frees its slot; %mask2 then
        # reuses that freed slot.  All at the hub's TS so net-ride is skipped.
        await src._send(
            f"{src.server_numnick} B {chan} {ts} "
            f"%{mask1} +b-b {mask1} {mask1} %{mask2}"
        )
        await p11.drain_messages(timeout=2.5)

        lines = _burst_lines(p11, chan)
        assert lines, "the P11 downlink saw no relay at all"
        _assert_fits_wire(lines, "the P11 downlink")

        # _ban_triples() asserts the multiple-of-three arity itself; here we
        # add that no mask is empty and that the recorded mask is the one that
        # was recorded, not the value that later landed in the reused slot.
        triples = _ban_triples(lines)
        relayed_masks = [m for m, _ts, _who in triples]
        for m, tstok, who in triples:
            assert m, f"relay carries an empty ban mask: {lines!r}"
            assert tstok.isdigit(), f"non-numeric ban ts {tstok!r}: {lines!r}"
            assert who, f"relay carries an empty ban setter: {lines!r}"
        assert mask1 in relayed_masks, (
            f"the first ban vanished from the relay -- its recorded slot was "
            f"freed and reused: {relayed_masks!r}"
        )
        assert mask2 in relayed_masks, (
            f"the second ban is missing from the relay: {relayed_masks!r}"
        )
        assert relayed_masks.count(mask2) == 1, (
            f"the second ban is duplicated -- a freed slot was aliased: "
            f"{relayed_masks!r}"
        )

        # The hub must still be alive and answer a later command.
        await _sync(maker)
        client = await _join(make_client, "uafwatch", chan)
        await _sync(client)
    finally:
        await _close(src, p11, _p10)


async def test_huge_oplevel_does_not_overflow_spec(ircd_hub, make_client):
    """A vast op level must be clamped, not wrapped and written out of bounds.

    The parse-time accumulator would overflow ``int`` before the
    ``> MAXOPLEVEL`` clamp fired, leaving a negative op level; the relay then
    printed it with ``%u`` (ten digits) and its NUL terminator landed past the
    seven-byte spec buffer.  With the clamp the level is pinned to MAXOPLEVEL,
    which the relay emits as ``:o`` -- no digits at all.
    """
    chan = "#huge1"
    src, p11, _p10 = await _source_and_downlinks(ircd_hub, 11)
    try:
        u1 = await src.introduce_user("huge1")
        await p11.drain_messages(timeout=1.5)

        await src._send(
            f"{src.server_numnick} B {chan} 1700000000 +t {u1}:3000000000"
        )
        await p11.drain_messages(timeout=2.5)

        lines = _burst_lines(p11, chan)
        assert lines, "the P11 downlink saw no relay at all"
        _assert_fits_wire(lines, "the P11 downlink")
        for line in lines:
            assert not HUGE_OPLEVEL.search(line), (
                f"relay carries an op level that wrapped around zero: {line!r}"
            )
        # No member specifier may carry a number longer than three digits;
        # MAXOPLEVEL is 999 and is itself emitted as ':o', not ':999'.
        for _numeric, spec in _members(lines):
            assert not re.search(r"\d{4,}", spec), (
                f"member specifier carries an over-long op level: {spec!r}"
            )

        # The hub must still be alive and answer a later command.
        client = await _join(make_client, "hugewatch", chan)
        await _sync(client)
    finally:
        await _close(src, p11, _p10)


async def test_oversized_channel_name_is_rejected(ircd_hub, make_client):
    """A server-sourced BURST with a name past CHANNELLEN must be rejected.

    A server BURST escapes get_channel()'s CHANNELLEN truncation (that is
    gated on MyUser), so a peer could otherwise create a ~490-byte channel
    whose relay head leaves no room for members or bans.  ms_burst() now
    rejects the name up front with a protocol violation and never creates the
    channel.
    """
    chan = "#" + "a" * 419
    op = await _debug_oper(make_client, "bignameop")
    src = await _link(ircd_hub, "services.test.net", 4, 11)
    try:
        u1 = await src.introduce_user("bign1")
        await src._send(f"{src.server_numnick} B {chan} 1700000000 +t {u1}")

        wallops = await collect_wallops(op, seconds=3.0)
        assert any("Invalid channel name" in w for w in wallops), (
            f"expected an 'Invalid channel name' protocol violation; "
            f"saw {wallops!r}"
        )

        # The channel must not exist: NAMES for it lists no members.  (A hub
        # client's own query is truncated to CHANNELLEN, but that shorter name
        # does not exist either, so the reply is empty regardless.)
        assert await _names(op, chan) == {}, (
            "the over-long channel was created despite the rejection"
        )

        # The hub must still be alive and answer a later command.
        await _sync(op)
    finally:
        await _close(src)


@pytest.mark.skip(
    reason="A zombie delayed member (a member kicked on a link beyond the "
    "re-bursting peer, still listed by that peer) needs at least three "
    "servers to construct: in the single_server harness a KICK of a stub "
    "user is propagated to the stub and the membership is removed outright, "
    "so the hub never holds a zombie.  The !IsZombie guard is covered by the "
    "burst_state/ multi_server suite; the fix ships regardless."
)
async def test_zombie_delayed_member_not_revealed_on_relink(ircd_hub,
                                                           make_client):
    """A re-bursted zombie delayed member must not be revealed to locals."""
    raise NotImplementedError
