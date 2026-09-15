"""Channel MODE across a P11/P10 network (P11 issue #114).

A is a P10 release, B and C are P11 working-tree servers. Every server
appends its own channel timestamp when it propagates a MODE, so a mode
that crosses the version boundary always carries a valid TS and is
applied on both sides. These tests confirm there is no "set on one,
unset on the other" desync in either direction.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.nf_compat


async def _modes(client, chan):
    await client.send(f"MODE {chan}")
    m = await client.wait_for("324", timeout=5.0)
    return m.params[2] if len(m.params) > 2 else ""


async def _run(setter_srv, watcher_srv, chan, setter_nick, watcher_nick):
    setter = IRCClient()
    await setter.connect(setter_srv["host"], setter_srv["port"])
    await setter.register(setter_nick, "u", "mode setter")
    watcher = IRCClient()
    await watcher.connect(watcher_srv["host"], watcher_srv["port"])
    await watcher.register(watcher_nick, "u", "mode watcher")
    try:
        await setter.send(f"JOIN {chan}")
        await setter.wait_for("JOIN")
        await watcher.send(f"JOIN {chan}")
        await watcher.wait_for("JOIN")
        await asyncio.sleep(0.5)

        await setter.send(f"MODE {chan} +m")
        await setter.wait_for("MODE")
        await asyncio.sleep(0.5)

        assert "m" in await _modes(watcher, chan)
        assert "m" in await _modes(setter, chan)
    finally:
        for cl in (setter, watcher):
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            await cl.disconnect()


async def test_mode_from_p10_reaches_p11_no_desync(ircd_nf_compat):
    """A mode set on the P10 release (A) is applied on the P11 server (C).
    A adds the channel TS on propagation, so the P11 side receives a valid
    TS and does not drop it."""
    await _run(ircd_nf_compat["a"], ircd_nf_compat["c"], "#p10mode",
               "p10setter", "p11watch")


async def test_mode_from_p11_reaches_p10_no_desync(ircd_nf_compat):
    """A mode set on a P11 server (C) is applied on the P10 release (A)."""
    await _run(ircd_nf_compat["c"], ircd_nf_compat["a"], "#p11mode",
               "p11setter", "p10watch")
