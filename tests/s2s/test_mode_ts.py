"""P11 channel MODE timestamp handling (issue #114).

On a P11 link the trailing channel timestamp of an S2S MODE (`M`) is a
mandatory, positional parameter, validated as all-digits.  This prevents
the legacy heuristic ("the final argument, if it starts with a digit")
from mistaking an unconsumed mode argument -- e.g. a numnick beginning
with a digit -- for the timestamp and poisoning ``creationtime``.
"""

from __future__ import annotations

import asyncio

import pytest

from p10_server import P10Server

pytestmark = pytest.mark.single_server


async def _link(hub, name="notulined.test.net", numeric=5) -> P10Server:
    srv = P10Server(name=name, numeric=numeric, password="testpass", server_flags="")
    await srv.connect(hub["host"], hub["server_port"])
    return srv


async def _creationtime(client, chan):
    await client.send(f"MODE {chan}")
    ct = await client.wait_for("329", timeout=5.0)
    return int(ct.params[-1])


async def test_mode_p11_numnick_arg_does_not_poison_creationtime(ircd_hub, make_client):
    """A P11 server sends a MODE whose only leftover argument is a
    digit-leading numnick (an unconsumed argument, no trailing TS).  On P11
    the TS is validated as all-digits, so "3AAAB" is rejected as a protocol
    violation rather than parsed as atoi("3AAAB") == 3 and written over
    creationtime."""
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("modepoison1")
        chan = "#modepoison"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")

        orig = await _creationtime(client, chan)
        assert orig > 1000000000, orig  # a real, recent timestamp

        # +m takes no argument, so the digit-leading numnick is the leftover
        # final argument the heuristic would misread as the channel TS.
        await srv._send(f"{srv.server_numnick} M {chan} +m 3AAAB")
        await asyncio.sleep(0.5)

        assert await _creationtime(client, chan) == orig
    finally:
        await srv.disconnect()


async def test_mode_p11_valid_ts_is_applied(ircd_hub, make_client):
    """Control: a P11 server MODE carrying a valid, older all-digit channel
    TS updates creationtime (the earlier timestamp wins)."""
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("modets1")
        chan = "#modets"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")

        orig = await _creationtime(client, chan)
        older = orig - 100

        await srv._send(f"{srv.server_numnick} M {chan} +m {older}")
        await asyncio.sleep(0.5)

        assert await _creationtime(client, chan) == older
    finally:
        await srv.disconnect()
