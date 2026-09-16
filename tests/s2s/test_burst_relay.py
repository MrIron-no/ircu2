"""The relayed channel BURST must keep its exact wire form on every downlink.

ms_burst() builds the line it forwards in two variants, one per link
protocol, so that later P11 extensions (the hidden-member ``d`` specifier and
the ``<mask> <ts> <who>`` ban triples of doc/P11.md 8.1) can be added to the
P11 variant without disturbing P10 peers.  These tests pin the byte form of
both variants as it stands today: a BURST accepted from one stub must reach
the other stub unchanged apart from the hub's own source prefix.
"""

from __future__ import annotations

import pytest

from p11_server import P11Server, strip_msg_tags

pytestmark = pytest.mark.single_server


async def _two_stubs(hub, proto_a, proto_b) -> tuple[P11Server, P11Server]:
    """Link two stub servers to the hub and complete both handshakes."""
    stub_a = P11Server(name="notulined.test.net", numeric=5,
                       password="testpass", server_flags="", protocol=proto_a)
    await stub_a.connect(hub["host"], hub["server_port"])
    await stub_a.handshake()

    stub_b = P11Server(name="uworldonly.test.net", numeric=6,
                       password="testpass", server_flags="", protocol=proto_b)
    await stub_b.connect(hub["host"], hub["server_port"])
    await stub_b.handshake()

    return stub_a, stub_b


async def _relayed_burst(stub_b) -> str:
    """Return the next BURST line seen by stub B, tags stripped."""
    return strip_msg_tags(await stub_b.wait_for_token("B", timeout=10.0))


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
            f"{u1},{u2}:v,{u3}:o :%*!*@relay.example"
        )
        relayed = await _relayed_burst(stub_b)
        # The relay keeps the originating server's prefix (sptr), not the
        # hub's own numeric.
        expected = (
            f"{stub_a.server_numnick} B {chan} 1700000000 +tn "
            f"{u1},{u2}:v,{u3}:o :%*!*@relay.example"
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
            f":%*!*@one.example *!*@two.example"
        )
        relayed = await _relayed_burst(stub_b)
        expected = (
            f"{stub_a.server_numnick} B {chan} 1700000000 "
            f":%*!*@one.example *!*@two.example"
        )
        assert relayed == expected, f"relayed {relayed!r}, expected {expected!r}"
    finally:
        await stub_a.disconnect()
        await stub_b.disconnect()
