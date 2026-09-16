"""Real A(prod P10)<->B(tree) netsplit/relink round trips for P11 BURST.

The rest of ``pr_network_features_compat/`` checks steady-state suppression
and translation on an already-linked chain.  These tests specifically cross
the P10 boundary at the moment metadata can be lost or gained: a real
SQUIT + oper CONNECT between the production P10 release **A** and this
tree's **B**, with observers on the P11 leaf **C** and on A itself
(doc/P11.md 8.1's ban-triple layout and its "Hidden (delayed-join) members"
processing bullet, exercised against a real 2.10.12 binary instead of a
scripted stub).
"""

from __future__ import annotations

import asyncio
import itertools
import time

import pytest

from common import drain, join, sender_nick, wait_for_join
from irc_client import IRCClient
from tls.helpers import links_contains, oper_up

pytestmark = pytest.mark.nf_compat

A_NAME = "a.prod.test.net"
B_NAME = "b.test.net"

_sync_seq = itertools.count(1)


# --------------------------------------------------------------------------
# client / oper helpers
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


# --------------------------------------------------------------------------
# channel state helpers
# --------------------------------------------------------------------------


async def _sync(client: IRCClient) -> None:
    token = f"sync{next(_sync_seq)}"
    await client.send(f"PING :{token}")
    while True:
        msg = await client.wait_for("PONG", timeout=10.0)
        if msg.params and msg.params[-1] == token:
            break
    client._buffer.clear()


async def _ban_list(client: IRCClient, chan: str) -> list[tuple[str, str, str]]:
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


async def _names(client: IRCClient, chan: str) -> list[str]:
    await _sync(client)
    await client.send(f"NAMES {chan}")
    msgs = await client.collect_until("366", timeout=5.0)
    names: list[str] = []
    for msg in msgs:
        if msg.command == "353":
            names.extend(msg.params[-1].split())
    return names


def _bare(name: str) -> str:
    return name.lstrip("@+!")


async def _wait_mode_from(
    client: IRCClient, chan: str, source_nick: str, timeout: float = 5.0
):
    """Wait for a MODE echo on ``chan`` genuinely sourced from ``source_nick``.

    Plain ``wait_for("MODE")`` matches the first MODE of any kind for any
    channel, including an unrelated (and, across a P10 boundary, possibly
    delayed) MODE relayed from a different user -- a live ban set just
    before a split can still be arriving from the *other* setter when this
    client's own command is sent, and a self-issued channel MODE is always
    echoed with the setting user's own nick!user@host prefix, never the
    server's, so that is what disambiguates it.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError(
                f"no MODE on {chan} from {source_nick} arrived in time"
            )
        msg = await client.wait_for("MODE", timeout=remaining)
        if (
            msg.params
            and msg.params[0].lower() == chan.lower()
            and msg.prefix
            and msg.prefix.split("!", 1)[0] == source_nick
        ):
            return msg


async def _wait_own_mode(client: IRCClient, chan: str, timeout: float = 5.0):
    """Wait for ``client``'s own MODE echo on ``chan`` (see _wait_mode_from)."""
    return await _wait_mode_from(client, chan, client.nick, timeout=timeout)


# --------------------------------------------------------------------------
# split / heal (A <-> B only; C stays linked to B throughout)
# --------------------------------------------------------------------------


async def _wait_linked(c: IRCClient, peer: str, timeout: float = 45.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        await drain(c, 1.0)
        if await links_contains(c, peer, timeout=5.0):
            return
    raise TimeoutError(f"{peer} never reappeared in LINKS")


async def _wait_unlinked(c: IRCClient, peer: str, timeout: float = 30.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        await drain(c, 1.0)
        if not await links_contains(c, peer, timeout=5.0):
            return
    raise TimeoutError(f"{peer} still in LINKS")


async def _split(b_op: IRCClient, a_op: IRCClient) -> None:
    if await links_contains(b_op, A_NAME):
        await b_op.send(f"SQUIT {A_NAME} :test")
    await _wait_unlinked(b_op, A_NAME)
    await _wait_unlinked(a_op, B_NAME)


async def _heal(b_op: IRCClient, a_op: IRCClient, a_port: int) -> None:
    """Idempotent: CONNECT only if not already linked."""
    if not await links_contains(b_op, A_NAME):
        await b_op.send(f"CONNECT {A_NAME} {a_port}")
    await _wait_linked(b_op, A_NAME)
    await _wait_linked(a_op, B_NAME)
    await drain(b_op, 2.0)
    await drain(a_op, 2.0)


# --------------------------------------------------------------------------
# 5. a ban set on the P11 side (C) reaches the P10 release (A) as a mask
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_ban_from_p11_side_reaches_p10_release_as_mask(ircd_nf_compat):
    a, b, c = ircd_nf_compat["a"], ircd_nf_compat["b"], ircd_nf_compat["c"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        cl = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(cl)
        return cl

    try:
        b_op = await mk(b, "nfbop5", True)
        a_op = await mk(a, "nfaop5", True)
        chan = "#nfb1"

        ca = await mk(c, "ca1")
        await join(ca, chan)
        aa = await mk(a, "aa1")
        await join(aa, chan)
        await ca.wait_for("JOIN", timeout=10.0)  # aa's join arrives via B

        await _split(b_op, a_op)
        try:
            mask = "*!*@nf.example"
            await ca.send(f"MODE {chan} +b {mask}")
            await ca.wait_for("MODE", timeout=5.0)
        finally:
            await _heal(b_op, a_op, a["server_port"])

        await asyncio.sleep(2.0)
        bans = await _ban_list(aa, chan)
        assert len(bans) == 1 and bans[0][0] == mask, (
            f"the P11-set ban did not reach the P10 release as a mask: {bans!r}"
        )
    finally:
        for cl in clients:
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            try:
                await cl.disconnect()
            except Exception:
                pass


# --------------------------------------------------------------------------
# 6. a ban set on the P10 release (A) degrades to a fabricated triple on
#    the P11 side (C)
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_ban_from_p10_release_degrades_on_p11_side(ircd_nf_compat):
    a, b, c = ircd_nf_compat["a"], ircd_nf_compat["b"], ircd_nf_compat["c"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        cl = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(cl)
        return cl

    try:
        b_op = await mk(b, "nfbop6", True)
        a_op = await mk(a, "nfaop6", True)
        chan = "#nfb2"

        ca = await mk(c, "ca2")
        await join(ca, chan)
        aa = await mk(a, "aa2")
        await join(aa, chan)
        await ca.wait_for("JOIN", timeout=10.0)

        # aa joined an existing channel, so it has no ops yet and needs
        # them to set its own ban below; confirm the grant actually reached
        # A (not just C's own echo) before splitting.
        await ca.send(f"MODE {chan} +o aa2")
        await _wait_own_mode(ca, chan)
        await _wait_mode_from(aa, chan, "ca2", timeout=10.0)

        await _split(b_op, a_op)
        try:
            mask = "*!*@nfa.example"
            before = int(time.time())
            await aa.send(f"MODE {chan} +b {mask}")
            await _wait_own_mode(aa, chan)
        finally:
            await _heal(b_op, a_op, a["server_port"])

        await asyncio.sleep(2.0)
        bans = await _ban_list(ca, chan)
        assert len(bans) == 1, f"the P10-set ban did not reach C: {bans!r}"
        bmask, who, ts = bans[0]
        assert bmask == mask, f"unexpected mask: {bans!r}"
        assert who == "*", (
            f"expected an unknown setter across the degraded P10->P11 path: "
            f"{bans!r}"
        )
        assert abs(int(ts) - before) < 60, (
            f"fabricated ts is not close to now: {bans!r}"
        )
    finally:
        for cl in clients:
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            try:
                await cl.disconnect()
            except Exception:
                pass


# --------------------------------------------------------------------------
# 7. a hidden (+D) member on the P10 release stays hidden on the P11 side
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_hidden_member_on_p10_release_stays_hidden_on_p11_side(ircd_nf_compat):
    a, b, c = ircd_nf_compat["a"], ircd_nf_compat["b"], ircd_nf_compat["c"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        cl = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(cl)
        return cl

    try:
        b_op = await mk(b, "nfbop7", True)
        a_op = await mk(a, "nfaop7", True)
        chan = "#nfb3"

        aa = await mk(a, "aa3")
        await join(aa, chan)
        await aa.send(f"MODE {chan} +D")
        await aa.wait_for("MODE", timeout=5.0)

        ahid = await mk(a, "ahid3")
        await join(ahid, chan)  # hidden, never speaks

        ca = await mk(c, "ca3")
        await join(ca, chan)
        pre_names = [_bare(n) for n in await _names(ca, chan)]
        assert "ahid3" not in pre_names, (
            f"pre-split NAMES on C leaked the hidden member: {pre_names!r}"
        )

        await _split(b_op, a_op)
        try:
            pass
        finally:
            await _heal(b_op, a_op, a["server_port"])

        drained = await drain(ca, 5.0)
        post_names = [_bare(n) for n in await _names(ca, chan)]
        assert "ahid3" not in post_names, (
            f"hidden member on the P10 release leaked into NAMES on C after "
            f"relink: {post_names!r}"
        )

        join_nicks = {sender_nick(m) for m in drained if m.command == "JOIN"}
        assert "ahid3" not in join_nicks, (
            f"hidden member's JOIN crossed the P10->P11 relink to C: {drained!r}"
        )

        await ahid.send(f"PRIVMSG {chan} :now")
        await wait_for_join(ca, chan, "ahid3", timeout=5.0)
        msg = await ca.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "now", f"unexpected reveal PRIVMSG: {msg!r}"
    finally:
        for cl in clients:
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            try:
                await cl.disconnect()
            except Exception:
                pass


# --------------------------------------------------------------------------
# adversarial: a known setter already on the P11 side must not be corrupted
# to '*' merely because the P10 release re-syncs the same mask across a
# split/heal.  Ban merge rule 1 ("a known setter always beats '*'") is a
# brand-new receiver-side algorithm in this tree; A's old code has no such
# merge at all, so this is the one direction where full 3-way convergence
# is NOT expected -- what must hold is that A can never *downgrade* what
# the tree-code servers already know.
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_known_setter_on_p11_side_survives_p10_resync(ircd_nf_compat):
    a, b, c = ircd_nf_compat["a"], ircd_nf_compat["b"], ircd_nf_compat["c"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        cl = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(cl)
        return cl

    try:
        b_op = await mk(b, "nfbop8", True)
        a_op = await mk(a, "nfaop8", True)
        chan = "#nfb4"
        mask = "*!*@known.example"

        ca = await mk(c, "ca4")
        await join(ca, chan)
        aa = await mk(a, "aa4")
        await join(aa, chan)
        await ca.wait_for("JOIN", timeout=10.0)

        # Set while fully linked: the live relay carries the real setter
        # identity everywhere via numnick lookup, no metadata is lost yet
        # (metadata loss is purely a BURST-time phenomenon -- see the module
        # docstring's tests 5-7 and doc/P11.md 8.1).
        await ca.send(f"MODE {chan} +b {mask}")
        await _wait_own_mode(ca, chan)
        ca_bans = await _ban_list(ca, chan)
        assert len(ca_bans) == 1 and ca_bans[0][0] == mask, f"setup: {ca_bans!r}"
        assert ca_bans[0][1] == "ca4", f"setup: unexpected setter: {ca_bans!r}"
        tc = ca_bans[0][2]

        await asyncio.sleep(2.0)  # let the live relay settle on A too

        # No action is needed on A at all: whatever A believes about this
        # mask, it can only ever contribute a bare mask over the wire
        # (doc/P11.md 8.1's P10 layout has no setter/ts fields), so simply
        # cycling the link is enough to prove B and C's own already-known
        # metadata isn't clobbered by A's unconditional full-state resync
        # on reconnect.
        await _split(b_op, a_op)
        await _heal(b_op, a_op, a["server_port"])

        await asyncio.sleep(2.0)

        c_bans = await _ban_list(ca, chan)
        assert c_bans == [(mask, "ca4", tc)], (
            f"C's known setter was corrupted by the P10 resync: {c_bans!r}"
        )

        bb = await mk(b, "bb8")
        await join(bb, chan)
        b_bans = await _ban_list(bb, chan)
        assert b_bans == [(mask, "ca4", tc)], (
            f"B's known setter was corrupted by the P10 resync: {b_bans!r}"
        )
    finally:
        for cl in clients:
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            try:
                await cl.disconnect()
            except Exception:
                pass
