"""Regression probe: MODE -k old +k new in one command (local chanop).

Discriminating version: after the change, the channel must require key2.
A joiner with NO key must be rejected (475); a joiner with key2 must succeed.
If the +k step silently failed, the channel would have no key and the no-key
joiner would wrongly get in.
"""
from __future__ import annotations

import asyncio
import pytest
from irc_client import IRCClient

pytestmark = pytest.mark.single_server


async def _try_join(client, chan, key=None):
    line = f"JOIN {chan} {key}" if key else f"JOIN {chan}"
    await client.send(line)
    try:
        while True:
            m = await client.recv(timeout=3.0)
            if m.command == "JOIN":
                return "JOIN"
            if m.command == "475":
                return "475"
    except (asyncio.TimeoutError, TimeoutError):
        return "TIMEOUT"


async def test_key_change_in_one_command(ircd_hub, make_client):
    op = await make_client("keyop2")
    chan = "#keychange2"
    await op.send(f"JOIN {chan}")
    await op.wait_for("JOIN")
    await op.send(f"MODE {chan} +k key1")
    await op.wait_for("MODE")

    await op.send(f"MODE {chan} -k key1 +k key2")
    await asyncio.sleep(1.0)

    nokey = await make_client("keynone2")
    r_nokey = await _try_join(nokey, chan)      # must be 475 if key2 is set
    withkey = await make_client("keywith2")
    r_withkey = await _try_join(withkey, chan, "key2")

    assert r_nokey == "475", f"no-key join not rejected -> +k did not take: {r_nokey}"
    assert r_withkey == "JOIN", f"key2 join failed: {r_withkey}"
