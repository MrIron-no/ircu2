"""Off-path convergence of a messaging delayed-join reveal across real ircds.

``s2s/test_deljoin_reveal.py`` pins the ``REVEAL`` (``RV``) wire form against a
scripted stub on a single link.  It cannot show the bug the token exists to
fix: a channel *message* is relayed only to servers that have a member on the
channel (doc/P11.md 9.1), so a server with no member of its own on a ``+D``
channel never learns that a hidden member revealed itself by speaking and
keeps it hidden forever.  ``MODE``/``TOPIC`` reveals converge without a token
because those commands already reach every server.

These tests drive the standard three-server network (hub + leaf1 + leaf2) and
prove that a hub member's messaging reveal reaches an *off-path* leaf1 (no
leaf1 member on the channel at reveal time) via ``REVEAL``, while a member
that has only ever been silent stays hidden until it too speaks.
"""

from __future__ import annotations

import asyncio

import pytest

from common import drain, join, wait_for_join
from irc_client import IRCClient
from tls.helpers import oper_up

pytestmark = [pytest.mark.multi_server, pytest.mark.asyncio]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


async def _client(server: dict, nick: str) -> IRCClient:
    c = IRCClient()
    await c.connect(server["host"], server["port"])
    await c.register(nick, "testuser", "Test User")
    return c


async def _oper_client(server: dict, nick: str) -> IRCClient:
    c = await _client(server, nick)
    msg = await oper_up(c)
    assert msg.command == "381", f"OPER failed for {nick}: {msg}"
    return c


def _bare(name: str) -> str:
    return name.lstrip("@+!")


async def _names(client: IRCClient, chan: str) -> list[str]:
    await client.send(f"NAMES {chan}")
    msgs = await client.collect_until("366", timeout=5.0)
    names: list[str] = []
    for msg in msgs:
        if msg.command == "353":
            names.extend(msg.params[-1].split())
    return names


async def _poll_names(client: IRCClient, chan: str, want: str,
                      present: bool = True, timeout: float = 30.0) -> list[str]:
    """Poll NAMES until ``want`` is (or is not) present, or time out."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    last: list[str] = []
    while True:
        last = [_bare(n) for n in await _names(client, chan)]
        if (want in last) == present:
            return last
        if loop.time() >= deadline:
            state = "present" if present else "absent"
            raise AssertionError(
                f"{want!r} never became {state} in {chan} NAMES; last={last!r}"
            )
        await asyncio.sleep(1.0)


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------


@pytest.mark.timeout(120)
async def test_reveal_converges_on_offpath_server(ircd_network):
    """A hub member's speak reveals it on leaf1 even with no leaf1 member.

    Before the REVEAL token, leaf1 (off the channel's message delivery path)
    would keep the speaker hidden.  A member that only ever stayed silent
    must remain hidden.
    """
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    chan = "#mrv1"
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        c = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(c)
        return c

    try:
        hop = await mk(hub, "mrv1hop")
        await join(hop, chan)
        await hop.send(f"MODE {chan} +D")
        await hop.wait_for("MODE", timeout=5.0)

        # Two hidden hub members; NO leaf1 member on the channel yet, so
        # leaf1 is off the message delivery path for their PRIVMSGs.
        hhid = await mk(hub, "mrv1hhid")
        await join(hhid, chan)  # hidden: hop gets no JOIN
        hspk = await mk(hub, "mrv1hspk")
        await join(hspk, chan)  # hidden

        # hspk reveals itself by speaking.  The reveal is confirmed locally
        # on the hub (hop sees the JOIN); the RV token to leaf1 is a separate
        # unsynchronized S2S event, so leaf1 is polled below.
        await hspk.send(f"PRIVMSG {chan} :hello")
        await hop.wait_for("JOIN", timeout=5.0)   # hspk's reveal on the hub
        await hop.wait_for("PRIVMSG", timeout=5.0)

        # Now bring a leaf1 client onto the channel and observe its state.
        lwatch = await mk(leaf1, "mrv1lwatch")
        await join(lwatch, chan)

        # hspk must be revealed on leaf1 (only possible via the RV token),
        # and hhid, which never spoke, must still be hidden.
        names = await _poll_names(lwatch, chan, "mrv1hspk", present=True,
                                  timeout=30.0)
        assert "mrv1hhid" not in names, (
            f"silent member leaked into leaf1 NAMES: {names!r}"
        )
        assert "mrv1hop" in names, f"op missing from leaf1 NAMES: {names!r}"
    finally:
        for c in clients:
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            try:
                await c.disconnect()
            except Exception:
                pass


@pytest.mark.timeout(120)
async def test_silent_member_stays_hidden_after_join(ircd_network):
    """A never-spoken member stays hidden on leaf1 until it too speaks.

    Once a leaf1 member is on the channel, a subsequent speak by the hidden
    hub member reaches leaf1 as an ordinary channel message and is revealed
    there by per-server inference (the on-path path that still works).
    """
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    chan = "#mrv2"
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        c = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(c)
        return c

    try:
        hop = await mk(hub, "mrv2hop")
        await join(hop, chan)
        await hop.send(f"MODE {chan} +D")
        await hop.wait_for("MODE", timeout=5.0)

        hhid = await mk(hub, "mrv2hhid")
        await join(hhid, chan)   # hidden, will speak later
        hspk = await mk(hub, "mrv2hspk")
        await join(hspk, chan)   # hidden, reveals now
        await hspk.send(f"PRIVMSG {chan} :hello")
        await hop.wait_for("JOIN", timeout=5.0)
        await hop.wait_for("PRIVMSG", timeout=5.0)

        lwatch = await mk(leaf1, "mrv2lwatch")
        await join(lwatch, chan)

        # hspk revealed via RV; hhid, silent so far, is still hidden.
        await _poll_names(lwatch, chan, "mrv2hspk", present=True, timeout=30.0)
        names = [_bare(n) for n in await _names(lwatch, chan)]
        assert "mrv2hhid" not in names, (
            f"silent member visible on leaf1 before it spoke: {names!r}"
        )

        # Now hhid speaks; leaf1 has a member (lwatch), so it is on the
        # delivery path and reveals hhid by inference.
        await drain(lwatch, 0.5)
        await hhid.send(f"PRIVMSG {chan} :now")
        await wait_for_join(lwatch, chan, "mrv2hhid", timeout=10.0)
        msg = await lwatch.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "now", f"unexpected reveal PRIVMSG: {msg!r}"
    finally:
        for c in clients:
            try:
                await c.send("QUIT :cleanup")
            except Exception:
                pass
            try:
                await c.disconnect()
            except Exception:
                pass
