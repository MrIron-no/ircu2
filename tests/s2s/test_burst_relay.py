"""The relayed channel BURST must keep its exact wire form on every downlink.

ms_burst() builds the line it forwards in two variants, one per link
protocol, so that later P11 extensions (the hidden-member ``d`` specifier and
the ``<mask> <ts> <who>`` ban triples of doc/P11.md 8.1) can be added to the
P11 variant without disturbing P10 peers.  These tests pin the byte form of
both variants as it stands today: a BURST accepted from one stub must reach
the other stub unchanged apart from the hub's own source prefix.
"""

from __future__ import annotations

import re
import time

import pytest

from p11_server import P11Server, strip_msg_tags

pytestmark = pytest.mark.single_server


async def _two_stubs(hub, proto_a, proto_b) -> tuple[P11Server, P11Server]:
    """Link two stub servers to the hub and complete both handshakes.

    The capacity has to be 2**n - 1: the ircd uses the announced value
    verbatim as the link's numnick slot mask, and the relay emits the
    canonical numeric of each member it resolved, so a mask that collapses
    several numerics onto one slot would relay one member three times.
    """
    stub_a = P11Server(name="notulined.test.net", numeric=5,
                       password="testpass", server_flags="", protocol=proto_a,
                       max_clients=63)
    await stub_a.connect(hub["host"], hub["server_port"])
    await stub_a.handshake()

    stub_b = P11Server(name="uworldonly.test.net", numeric=6,
                       password="testpass", server_flags="", protocol=proto_b,
                       max_clients=63)
    await stub_b.connect(hub["host"], hub["server_port"])
    await stub_b.handshake()

    return stub_a, stub_b


async def _relayed_burst(stub_b) -> str:
    """Return the next BURST line seen by stub B, tags stripped."""
    return strip_msg_tags(await stub_b.wait_for_token("B", timeout=10.0))


def _ban_section(proto: int) -> str:
    """The ban list for one link protocol: a triple on P11, a mask on P10."""
    return (":%*!*@relay.example 1700000100 zed" if proto >= 11
            else ":%*!*@relay.example")


async def _run_relay_case(hub, proto_a, proto_b, chan):
    """Send a three-member + one-ban BURST from A and return what B saw."""
    stub_a, stub_b = await _two_stubs(hub, proto_a, proto_b)
    try:
        u1 = await stub_a.introduce_user(f"relay{proto_a}{proto_b}a")
        u2 = await stub_a.introduce_user(f"relay{proto_a}{proto_b}b")
        u3 = await stub_a.introduce_user(f"relay{proto_a}{proto_b}c")

        # Drop the hub's own burst (and the relayed NICKs) so the next B line
        # stub B sees is the relay of ours.
        await stub_b.drain_messages(timeout=1.0)

        await stub_a._send(
            f"{stub_a.server_numnick} B {chan} 1700000000 +tn "
            f"{u1},{u2}:v,{u3}:o {_ban_section(proto_a)}"
        )
        relayed = await _relayed_burst(stub_b)
        # The relay keeps the originating server's prefix (sptr), not the
        # hub's own numeric.
        expected = (
            f"{stub_a.server_numnick} B {chan} 1700000000 +tn "
            f"{u1},{u2}:v,{u3}:o {_ban_section(proto_b)}"
        )
        return relayed, expected
    finally:
        await stub_a.disconnect()
        await stub_b.disconnect()


async def test_relay_p10_to_p10_is_byte_identical(ircd_hub):
    relayed, expected = await _run_relay_case(ircd_hub, 10, 10, "#relay1")
    assert relayed == expected, f"relayed {relayed!r}, expected {expected!r}"


async def test_relay_p11_to_p11_is_byte_identical_without_extensions(ircd_hub):
    relayed, expected = await _run_relay_case(ircd_hub, 11, 11, "#relay1b")
    assert relayed == expected, f"relayed {relayed!r}, expected {expected!r}"


async def test_relay_ban_only_line(ircd_hub):
    """An empty channel carrying only bans relays its ban list unchanged."""
    chan = "#relay2"
    stub_a, stub_b = await _two_stubs(ircd_hub, 11, 11)
    try:
        await stub_b.drain_messages(timeout=1.0)

        await stub_a._send(
            f"{stub_a.server_numnick} B {chan} 1700000000 "
            f":%*!*@one.example 1700000100 zed *!*@two.example 1700000200 amy"
        )
        relayed = await _relayed_burst(stub_b)
        expected = (
            f"{stub_a.server_numnick} B {chan} 1700000000 "
            f":%*!*@one.example 1700000100 zed *!*@two.example 1700000200 amy"
        )
        assert relayed == expected, f"relayed {relayed!r}, expected {expected!r}"
    finally:
        await stub_a.disconnect()
        await stub_b.disconnect()


async def _two_stubs_with_users(hub, proto_a, proto_b):
    """Like _two_stubs, but with a capacity mask that keeps users distinct.

    The ircd uses the announced client capacity verbatim as the numnick slot
    mask, so only a 2**n - 1 value gives each introduced user its own slot.
    """
    stub_a = P11Server(name="notulined.test.net", numeric=5,
                       password="testpass", server_flags="", protocol=proto_a,
                       max_clients=63)
    await stub_a.connect(hub["host"], hub["server_port"])
    await stub_a.handshake()

    stub_b = P11Server(name="uworldonly.test.net", numeric=6,
                       password="testpass", server_flags="", protocol=proto_b,
                       max_clients=63)
    await stub_b.connect(hub["host"], hub["server_port"])
    await stub_b.handshake()

    return stub_a, stub_b


async def test_relay_translates_d_per_downlink(ircd_hub):
    """The hidden-member ``d`` is rewritten per downlink protocol.

    A P11 downlink gets the specifier verbatim; a P10 one gets the member
    bare, in the status-less group, with no specifier at all.
    """
    for proto_b, chan, tag in ((11, "#relay3", "a"), (10, "#relay3b", "b")):
        stub_a, stub_b = await _two_stubs_with_users(ircd_hub, 11, proto_b)
        try:
            u1 = await stub_a.introduce_user(f"drelay{tag}1")
            u2 = await stub_a.introduce_user(f"drelay{tag}2")
            await stub_b.drain_messages(timeout=1.0)

            await stub_a._send(
                f"{stub_a.server_numnick} B {chan} 1700000000 +D {u1},{u2}:d"
            )
            relayed = await _relayed_burst(stub_b)
            members = f"{u1},{u2}:d" if proto_b >= 11 else f"{u1},{u2}"
            expected = (
                f"{stub_a.server_numnick} B {chan} 1700000000 +D {members}"
            )
            assert relayed == expected, (
                f"P{proto_b} downlink: relayed {relayed!r}, expected {expected!r}"
            )
        finally:
            await stub_a.disconnect()
            await stub_b.disconnect()


async def test_relay_synthesises_d_from_p10_uplink_on_plus_D_channel(ircd_hub):
    """A P10 uplink cannot say ``d``; the hub infers it from ``+D``.

    A P10 peer has no hidden-member group, so every member of a ``+D``
    channel arrives bare in the status-less group (doc/P11.md 8.1, P10
    case).  Relaying that toward a P11 downlink must put those members
    back in the hidden group, i.e. synthesise the ``d`` specifier.
    """
    chan = "#relay5"
    stub_a, stub_b = await _two_stubs_with_users(ircd_hub, 10, 11)
    try:
        u1 = await stub_a.introduce_user("p10d1")
        u2 = await stub_a.introduce_user("p10d2")
        await stub_b.drain_messages(timeout=1.0)

        await stub_a._send(
            f"{stub_a.server_numnick} B {chan} 1700000000 +D {u1},{u2}"
        )
        relayed = await _relayed_burst(stub_b)
        # Both members are hidden, so the whole list is the hidden group and
        # the specifier rides on its first member, carrying to the second.
        expected = (
            f"{stub_a.server_numnick} B {chan} 1700000000 +D {u1}:d,{u2}"
        )
        assert relayed == expected, (
            f"relayed {relayed!r}, expected {expected!r}"
        )
    finally:
        await stub_a.disconnect()
        await stub_b.disconnect()


async def test_relay_no_d_from_p10_uplink_on_minus_D_channel(ircd_hub):
    """The control case: without ``+D`` nothing is inferred.

    The same bare member list on a channel that is not ``+D`` relays to a
    P11 downlink with no specifier at all.
    """
    chan = "#relay6"
    stub_a, stub_b = await _two_stubs_with_users(ircd_hub, 10, 11)
    try:
        u1 = await stub_a.introduce_user("p10n1")
        u2 = await stub_a.introduce_user("p10n2")
        await stub_b.drain_messages(timeout=1.0)

        await stub_a._send(
            f"{stub_a.server_numnick} B {chan} 1700000000 +t {u1},{u2}"
        )
        relayed = await _relayed_burst(stub_b)
        expected = (
            f"{stub_a.server_numnick} B {chan} 1700000000 +t {u1},{u2}"
        )
        assert relayed == expected, (
            f"relayed {relayed!r}, expected {expected!r}"
        )
    finally:
        await stub_a.disconnect()
        await stub_b.disconnect()


async def test_relay_translates_bans_per_downlink(ircd_hub):
    """Ban metadata is rewritten per downlink protocol.

    A P11 downlink gets the ``<mask> <ts> <who>`` triple of doc/P11.md 8.1;
    a P10 one gets the bare mask.  In the other direction a ban learned over
    a P10 link has no metadata to carry, so the hub synthesises the values it
    stored for it: its own current time and an unknown setter.
    """
    for proto_b, chan, tag in ((11, "#relay7", "a"), (10, "#relay7b", "b")):
        stub_a, stub_b = await _two_stubs_with_users(ircd_hub, 11, proto_b)
        try:
            u1 = await stub_a.introduce_user(f"brelay{tag}1")
            await stub_b.drain_messages(timeout=1.0)

            await stub_a._send(
                f"{stub_a.server_numnick} B {chan} 1700000000 +t {u1} "
                f":%*!*@r.example 1700000100 zed"
            )
            relayed = await _relayed_burst(stub_b)
            bans = (":%*!*@r.example 1700000100 zed" if proto_b >= 11
                    else ":%*!*@r.example")
            expected = (
                f"{stub_a.server_numnick} B {chan} 1700000000 +t {u1} {bans}"
            )
            assert relayed == expected, (
                f"P{proto_b} downlink: relayed {relayed!r}, expected {expected!r}"
            )
        finally:
            await stub_a.disconnect()
            await stub_b.disconnect()


async def test_relay_synthesises_ban_metadata_from_p10_uplink(ircd_hub):
    """A mask-only ban from a P10 uplink gains ``<now> *`` toward P11."""
    chan = "#relay8"
    stub_a, stub_b = await _two_stubs_with_users(ircd_hub, 10, 11)
    try:
        u1 = await stub_a.introduce_user("p10b1")
        await stub_b.drain_messages(timeout=1.0)

        before = int(time.time())
        await stub_a._send(
            f"{stub_a.server_numnick} B {chan} 1700000000 +t {u1} "
            f":%*!*@r2.example"
        )
        relayed = await _relayed_burst(stub_b)
        pattern = (
            rf"^{re.escape(stub_a.server_numnick)} B {chan} 1700000000 \+t "
            rf"{re.escape(u1)} :%\*!\*@r2\.example (\d+) \*$"
        )
        match = re.match(pattern, relayed)
        assert match, f"relayed {relayed!r} does not match {pattern!r}"
        assert abs(int(match.group(1)) - before) < 60, (
            f"synthesised ts is not the hub's current time: {relayed!r}"
        )
    finally:
        await stub_a.disconnect()
        await stub_b.disconnect()


async def _three_stubs(hub):
    """A P11 source plus a P10 and a P11 downlink, all linked to the hub.

    ``services.test.net`` is the source; the two observers are the other two
    Connect blocks of tests/docker/ircd-hub.conf.  All three announce the
    same 2**n - 1 capacity so every introduced user gets its own slot.
    """
    src = P11Server(name="services.test.net", numeric=4, password="testpass",
                    protocol=11, max_clients=63)
    await src.connect(hub["host"], hub["server_port"])
    await src.handshake()

    p10 = P11Server(name="notulined.test.net", numeric=5, password="testpass",
                    server_flags="", protocol=10, max_clients=63)
    await p10.connect(hub["host"], hub["server_port"])
    await p10.handshake()

    p11 = P11Server(name="uworldonly.test.net", numeric=6, password="testpass",
                    server_flags="", protocol=11, max_clients=63)
    await p11.connect(hub["host"], hub["server_port"])
    await p11.handshake()

    return src, p10, p11


def _burst_lines_for(stub: P11Server, chan: str) -> list[str]:
    """Every BURST line for ``chan`` the stub has read, tags stripped."""
    lines = []
    for line in stub.received:
        payload = strip_msg_tags(line)
        parts = payload.split()
        if len(parts) >= 3 and parts[1] == "B" and parts[2].lower() == chan.lower():
            lines.append(payload)
    return lines


async def test_mixed_p10_and_p11_downlinks_get_their_own_variant_from_one_burst(
        ircd_hub):
    """One incoming BURST produces one line per downlink, in its own layout.

    The P11 downlink gets the hidden-member ``d`` and the ban triple; the P10
    one gets the member bare and the mask alone.  Neither gets a second line:
    the state fits on one, so the continuation machinery must stay out of the
    way.
    """
    chan = "#relay9"
    src, p10, p11 = await _three_stubs(ircd_hub)
    try:
        u1 = await src.introduce_user("mixrelay1")
        u2 = await src.introduce_user("mixrelay2")
        await p10.drain_messages(timeout=1.0)
        await p11.drain_messages(timeout=1.0)

        await src._send(
            f"{src.server_numnick} B {chan} 1700000000 +tD {u1}:d,{u2}:o "
            f":%*!*@mixed.example 1700000100 zed"
        )
        # A second line, if any, would arrive right after the first; drain a
        # full second so that "exactly one" is a real assertion.
        await p11.drain_messages(timeout=1.0)
        await p10.drain_messages(timeout=1.0)

        p11_lines = _burst_lines_for(p11, chan)
        p10_lines = _burst_lines_for(p10, chan)

        assert p11_lines == [
            f"{src.server_numnick} B {chan} 1700000000 +tD {u1}:d,{u2}:o "
            f":%*!*@mixed.example 1700000100 zed"
        ], f"P11 downlink saw {p11_lines!r}"
        assert p10_lines == [
            f"{src.server_numnick} B {chan} 1700000000 +tD {u1},{u2}:o "
            f":%*!*@mixed.example"
        ], f"P10 downlink saw {p10_lines!r}"
    finally:
        for stub in (src, p10, p11):
            await stub.disconnect()
