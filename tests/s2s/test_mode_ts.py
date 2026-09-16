"""P11 channel MODE timestamp handling (issue #114).

On a P11 link the trailing channel timestamp of an S2S MODE (`M`) is a
mandatory, positional parameter, validated as all-digits.  A P11 MODE
that carries no valid timestamp is a protocol violation and is dropped
(neither applied nor propagated) rather than allowed to poison
``creationtime`` or diverge from peers.  A P10 link keeps the lenient
legacy heuristic, so a P10 peer -- which may legitimately omit the TS
and have it added on propagation -- is never dropped.
"""

from __future__ import annotations

import asyncio

import pytest

from p11_server import P11Server

pytestmark = pytest.mark.single_server


async def _link(hub, numeric=5, protocol=None) -> P11Server:
    kwargs = dict(name="notulined.test.net", numeric=numeric,
                  password="testpass", server_flags="")
    if protocol is not None:
        kwargs["protocol"] = protocol
    srv = P11Server(**kwargs)
    await srv.connect(hub["host"], hub["server_port"])
    return srv


async def _creationtime(client, chan):
    await client.send(f"MODE {chan}")
    ct = await client.wait_for("329", timeout=5.0)
    return int(ct.params[-1])


async def _channel_modes(client, chan):
    """Return the channel's mode letters (RPL_CHANNELMODEIS, 324)."""
    await client.send(f"MODE {chan}")
    m = await client.wait_for("324", timeout=5.0)
    return m.params[2] if len(m.params) > 2 else ""


async def test_mode_p11_numnick_arg_is_dropped(ircd_hub, make_client):
    """A P11 MODE whose final argument is a digit-leading numnick (no real
    TS) is dropped: the numnick is not applied as the timestamp, and the
    mode itself is not applied either."""
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("modepoison1")
        chan = "#modepoison"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")

        orig = await _creationtime(client, chan)
        assert orig > 1000000000, orig

        await srv._send(f"{srv.server_numnick} M {chan} +m 3AAAB")
        await asyncio.sleep(0.5)

        assert await _creationtime(client, chan) == orig
        assert "m" not in await _channel_modes(client, chan)
    finally:
        await srv.disconnect()


async def test_mode_p11_missing_ts_is_dropped(ircd_hub, make_client):
    """A P11 MODE that carries no timestamp at all is dropped: the mode is
    not applied."""
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("modemissing1")
        chan = "#modemissing"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")

        await srv._send(f"{srv.server_numnick} M {chan} +m")
        await asyncio.sleep(0.5)

        assert "m" not in await _channel_modes(client, chan)
    finally:
        await srv.disconnect()


async def test_mode_p10_missing_ts_still_applied(ircd_hub, make_client):
    """A P10 link keeps the lenient heuristic: a MODE from a P10 peer with
    no timestamp is applied, not dropped.  This is the guarantee that the
    P11 drop does not break a legacy (e.g. service) peer that omits the TS."""
    srv = await _link(ircd_hub, protocol=10)
    try:
        await srv.handshake()
        client = await make_client("modep10a")
        chan = "#modep10"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")

        await srv._send(f"{srv.server_numnick} M {chan} +m")
        await asyncio.sleep(0.5)

        assert "m" in await _channel_modes(client, chan)
    finally:
        await srv.disconnect()
