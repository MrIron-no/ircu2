"""Regression: rekeying in a single MODE command (issue: deferred-commit).

A local chanop doing `MODE #chan -k old +k new` (or -U/+U) in one command must
end up with the new key.  mode_parse() stages parametric modes into a working
copy and commits after the loop, so a helper must validate an add against the
staged state (the old key already removed by the -k earlier in the same
command), not the still-live channel -- otherwise the +k is rejected and the
channel is left with no key at all.
"""

from __future__ import annotations

import pytest

from common import join

pytestmark = pytest.mark.single_server


async def _key(client, chan):
    """The channel key (RPL_CHANNELMODEIS argument), or None if unkeyed."""
    await client.send(f"MODE {chan}")
    m = await client.wait_for("324", timeout=5.0)
    modes = m.params[2] if len(m.params) > 2 else ""
    if "k" not in modes:
        return None
    return m.params[3] if len(m.params) > 3 else ""


async def test_rekey_in_single_command_keeps_new_key(make_client):
    op = await make_client("rekeyop")
    chan = "#rekey"
    await join(op, chan)

    await op.send(f"MODE {chan} +k oldkey")
    await op.wait_for("MODE")
    assert await _key(op, chan) == "oldkey"

    # Remove the old key and add a new one in a single command.
    await op.send(f"MODE {chan} -k oldkey +k newkey")
    await op.wait_for("MODE")

    assert await _key(op, chan) == "newkey", "rekey lost the key"
