"""Real hub<->leaf1 netsplit/relink round trips for the P11 BURST changes.

``s2s/test_burst_deljoin.py``, ``s2s/test_burst_ban_metadata.py`` and
``s2s/test_burst_relay.py`` pin the wire form and the receiver logic against
a scripted ``P11Server`` stub on a single, never-restarted link.  They can
never show what happens when a *real* ircd link actually drops and comes
back: whether a ban set purely locally while the network is split still
carries its metadata home, whether two servers that independently set the
same ban while split converge deterministically once they can talk again,
and whether a hidden (``+D``) member's visibility survives a netsplit and
heal intact on both a real P11 uplink and a real P11 downlink.

These tests drive an actual SQUIT + oper CONNECT between the hub and leaf1
of the standard three-server test network (doc/P11.md 8.1, 15.1 row `D`).
"""

from __future__ import annotations

import asyncio
import itertools

import pytest

from common import drain, join, sender_nick, wait_for_join
from irc_client import IRCClient
from tls.helpers import links_contains, oper_up

pytestmark = [pytest.mark.multi_server, pytest.mark.asyncio]

HUB_NAME = "hub.test.net"
LEAF1_NAME = "leaf1.test.net"

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
# channel state helpers (mirrors s2s/test_burst_ban_metadata.py's own copies;
# these read observable client-facing state, not stub-server wire lines)
# --------------------------------------------------------------------------


async def _sync(client: IRCClient) -> None:
    """Flush pending/buffered replies so the next query reads its own."""
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


async def _chan_modes(client: IRCClient, chan: str) -> str:
    await _sync(client)
    await client.send(f"MODE {chan}")
    msg = await client.wait_for("324", timeout=5.0)
    return next((p for p in msg.params if p.startswith("+")), "")


async def _wait_chan_mode_letter(
    client: IRCClient, chan: str, letter: str, timeout: float = 10.0
) -> None:
    """Poll until ``letter`` shows up in the channel's mode string.

    A cross-server MODE relay is a separate, unsynchronized event from
    whatever locally confirmed the mode change on the *other* server, so a
    client on the receiving side can otherwise race it.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        modes = await _chan_modes(client, chan)
        if letter in modes:
            return
        if loop.time() >= deadline:
            raise TimeoutError(
                f"{letter!r} never appeared in {chan} modes on this link "
                f"(last seen: {modes!r})"
            )
        await asyncio.sleep(0.5)


def _mode_lines_for(msgs: list, chan: str) -> list:
    return [
        m for m in msgs
        if m.command == "MODE" and m.params and m.params[0].lower() == chan.lower()
    ]


def _ban_mode_lines_for(msgs: list, chan: str) -> list:
    """MODE lines for ``chan`` that touch the ban ('b') flag specifically.

    A netsplit heal legitimately re-announces op status (and JOINs) for
    members who dropped off and rejoined via the burst; that is unrelated,
    expected recovery noise, not a sign that a *ban* metadata-only merge
    leaked to clients (doc/P11.md 8.1: "a metadata-only change is silent").
    """
    out = []
    for m in _mode_lines_for(msgs, chan):
        modestr = m.params[1] if len(m.params) > 1 else ""
        if "b" in modestr:
            out.append(m)
    return out


# --------------------------------------------------------------------------
# split / heal
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


async def _split(hub_op: IRCClient, leaf_op: IRCClient) -> None:
    if await links_contains(hub_op, LEAF1_NAME):
        await hub_op.send(f"SQUIT {LEAF1_NAME} :test")
    await _wait_unlinked(hub_op, LEAF1_NAME)
    await _wait_unlinked(leaf_op, HUB_NAME)


async def _heal(hub_op: IRCClient, leaf_op: IRCClient, leaf_port: int) -> None:
    """Idempotent: CONNECT only if not already linked."""
    if not await links_contains(hub_op, LEAF1_NAME):
        await hub_op.send(f"CONNECT {LEAF1_NAME} {leaf_port}")
    await _wait_linked(hub_op, LEAF1_NAME)
    await _wait_linked(leaf_op, HUB_NAME)
    # Let the burst settle before either side is used as an oper socket again.
    await drain(hub_op, 2.0)
    await drain(leaf_op, 2.0)


# --------------------------------------------------------------------------
# 1. a ban set purely during the split arrives with metadata on heal
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_ban_set_during_split_arrives_with_metadata(ircd_network):
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        c = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(c)
        return c

    try:
        hub_op = await mk(hub, "rl1hubop", True)
        leaf_op = await mk(leaf1, "rl1leafop", True)
        chan = "#rl1"

        hb1 = await mk(hub, "hb1")
        await join(hb1, chan)
        lb1 = await mk(leaf1, "lb1")
        await join(lb1, chan)
        await hb1.wait_for("JOIN", timeout=5.0)  # lb1's remote join

        await _split(hub_op, leaf_op)
        try:
            mask = "*!*@split.example"
            await hb1.send(f"MODE {chan} +b {mask}")
            await hb1.wait_for("MODE", timeout=5.0)
            bans = await _ban_list(hb1, chan)
            assert len(bans) == 1 and bans[0][0] == mask, f"ban not set: {bans!r}"
            assert bans[0][1] == "hb1", f"unexpected setter: {bans!r}"
            ts = bans[0][2]
        finally:
            await _heal(hub_op, leaf_op, leaf1["server_port"])

        await asyncio.sleep(2.0)
        leaf_bans = await _ban_list(lb1, chan)
        assert leaf_bans == [(mask, "hb1", ts)], (
            f"ban set during the split did not arrive with its metadata: "
            f"{leaf_bans!r} (expected who=hb1, ts={ts})"
        )
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


# --------------------------------------------------------------------------
# 2. both sides ban the same mask during the split; the merge is
#    deterministic and repeated splits/heals don't perturb it or show a MODE
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_same_mask_both_sides_converges_and_is_stable(ircd_network):
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        c = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(c)
        return c

    try:
        hub_op = await mk(hub, "rl2hubop", True)
        leaf_op = await mk(leaf1, "rl2leafop", True)
        chan = "#rl2"
        mask = "*!*@both.example"

        hb2 = await mk(hub, "hb2")
        await join(hb2, chan)
        lb2 = await mk(leaf1, "lb2")
        await join(lb2, chan)
        await hb2.wait_for("JOIN", timeout=5.0)

        # lb2 joined an existing channel, so it has no ops yet; it needs
        # them to set its own ban below.  Wait for the grant to actually
        # arrive on leaf1 (not just hub's own echo) before splitting.
        await hb2.send(f"MODE {chan} +o lb2")
        await hb2.wait_for("MODE", timeout=5.0)
        await lb2.wait_for("MODE", timeout=5.0)

        await _split(hub_op, leaf_op)
        try:
            await hb2.send(f"MODE {chan} +b {mask}")
            await hb2.wait_for("MODE", timeout=5.0)
            hub_bans = await _ban_list(hb2, chan)
            assert len(hub_bans) == 1 and hub_bans[0][0] == mask, (
                f"ban not set on hub: {hub_bans!r}"
            )
            t1 = hub_bans[0][2]

            await asyncio.sleep(1.5)

            await lb2.send(f"MODE {chan} +b {mask}")
            await lb2.wait_for("MODE", timeout=5.0)
            leaf_bans = await _ban_list(lb2, chan)
            assert len(leaf_bans) == 1 and leaf_bans[0][0] == mask, (
                f"ban not set on leaf1: {leaf_bans!r}"
            )
            t2 = leaf_bans[0][2]
            assert int(t2) > int(t1), (
                f"test setup: leaf ts must be later than hub ts, got t1={t1} t2={t2}"
            )
        finally:
            await _heal(hub_op, leaf_op, leaf1["server_port"])

        hub_msgs = await drain(hb2, 3.0)
        leaf_msgs = await drain(lb2, 3.0)
        assert not _ban_mode_lines_for(hub_msgs, chan), (
            f"metadata-only ban convergence produced a ban MODE on the hub: {hub_msgs!r}"
        )
        assert not _ban_mode_lines_for(leaf_msgs, chan), (
            f"metadata-only ban convergence produced a ban MODE on leaf1: {leaf_msgs!r}"
        )

        for c, tag in ((hb2, "hub"), (lb2, "leaf1")):
            merged = await _ban_list(c, chan)
            assert merged == [(mask, "hb2", t1)], (
                f"{tag} did not converge on the lower (hub) timestamp: {merged!r}"
            )

        # Split and heal again with no further changes: the merge must be
        # stable, not drift or re-announce itself on every resync.
        await _split(hub_op, leaf_op)
        await _heal(hub_op, leaf_op, leaf1["server_port"])

        hub_msgs2 = await drain(hb2, 3.0)
        leaf_msgs2 = await drain(lb2, 3.0)
        assert not _ban_mode_lines_for(hub_msgs2, chan), (
            f"second heal produced a ban MODE on the hub: {hub_msgs2!r}"
        )
        assert not _ban_mode_lines_for(leaf_msgs2, chan), (
            f"second heal produced a ban MODE on leaf1: {leaf_msgs2!r}"
        )
        for c, tag in ((hb2, "hub"), (lb2, "leaf1")):
            merged = await _ban_list(c, chan)
            assert merged == [(mask, "hb2", t1)], (
                f"{tag} was not stable across a second heal: {merged!r}"
            )
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


# --------------------------------------------------------------------------
# 3. hidden and revealed members survive a real netsplit and heal
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_hidden_and_revealed_members_survive_relink(ircd_network):
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        c = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(c)
        return c

    try:
        hub_op = await mk(hub, "rl3hubop", True)
        leaf_op = await mk(leaf1, "rl3leafop", True)
        chan = "#rl3"

        hb3 = await mk(hub, "hb3")
        await join(hb3, chan)
        await hb3.send(f"MODE {chan} +D")
        await hb3.wait_for("MODE", timeout=5.0)

        # lb3 joins *before* hid3/rev3 exist. ircu's channel-message fanout
        # to other servers is member-driven (doc/P11.md 8.1's BURST is the
        # only *unconditional* full-state sync): with no leaf1-side member
        # yet, hub would have nobody to route hid3/rev3's live JOINs and
        # rev3's reveal towards, and this test would trivially "pass" by
        # leaf1 never hearing of them at all rather than by correctly
        # hiding/revealing them. A hidden member still counts as a routing
        # destination even though it is not shown to other local clients,
        # so lb3 establishes that route regardless of +D.
        lb3 = await mk(leaf1, "lb3")
        await join(lb3, chan)

        hid3 = await mk(hub, "hid3")
        await join(hid3, chan)  # hidden: hb3 gets no JOIN for this

        rev3 = await mk(hub, "rev3")
        await join(rev3, chan)
        await rev3.send(f"PRIVMSG {chan} :hi")
        await hb3.wait_for("JOIN", timeout=5.0)  # rev3's reveal
        await hb3.wait_for("PRIVMSG", timeout=5.0)
        # The reveal is confirmed locally on the hub, but its S2S relay to
        # leaf1 is a separate, unsynchronized event; give it a moment before
        # leaf1 is queried for NAMES.
        await asyncio.sleep(1.5)

        pre_names = [_bare(n) for n in await _names(lb3, chan)]
        assert "rev3" in pre_names and "hid3" not in pre_names, (
            f"pre-split NAMES wrong (live S2S relay of hidden/reveal state): "
            f"{pre_names!r}"
        )

        await _split(hub_op, leaf_op)  # leaf1 sees the netsplit QUITs
        try:
            pass
        finally:
            await _heal(hub_op, leaf_op, leaf1["server_port"])

        drained = await drain(lb3, 5.0)
        post_names = [_bare(n) for n in await _names(lb3, chan)]
        assert "rev3" in post_names and "hb3" in post_names, (
            f"post-relink NAMES missing visible members: {post_names!r}"
        )
        assert "hid3" not in post_names, (
            f"hidden member leaked into NAMES after relink: {post_names!r}"
        )

        join_nicks = {sender_nick(m) for m in drained if m.command == "JOIN"}
        assert "rev3" in join_nicks, (
            f"no JOIN for the revealed member during the relink burst: {drained!r}"
        )
        assert "hid3" not in join_nicks, (
            f"hidden member's JOIN leaked during the relink burst: {drained!r}"
        )

        await hid3.send(f"PRIVMSG {chan} :now")
        await wait_for_join(lb3, chan, "hid3", timeout=5.0)
        msg = await lb3.wait_for("PRIVMSG", timeout=5.0)
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


# --------------------------------------------------------------------------
# 4. a lingering hidden member (channel went -D but the member never spoke)
#    survives a real netsplit and heal
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_lingering_hidden_member_on_minus_D_survives_relink(ircd_network):
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        c = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(c)
        return c

    try:
        hub_op = await mk(hub, "rl4hubop", True)
        leaf_op = await mk(leaf1, "rl4leafop", True)
        chan = "#rl4"

        hb4 = await mk(hub, "hb4")
        await join(hb4, chan)
        await hb4.send(f"MODE {chan} +D")
        await hb4.wait_for("MODE", timeout=5.0)

        hid4 = await mk(hub, "hid4")
        await join(hid4, chan)  # hidden, never speaks

        await hb4.send(f"MODE {chan} -D")
        await hb4.wait_for("MODE", timeout=5.0)

        hub_modes = await _chan_modes(hb4, chan)
        assert "d" in hub_modes and "D" not in hub_modes, (
            f"expected lingering +d (not +D) on the hub: {hub_modes!r}"
        )

        lb4 = await mk(leaf1, "lb4")
        await join(lb4, chan)
        pre_names = [_bare(n) for n in await _names(lb4, chan)]
        assert "hid4" not in pre_names, (
            f"hidden member visible on leaf1 before the split: {pre_names!r}"
        )

        await _split(hub_op, leaf_op)
        try:
            pass
        finally:
            await _heal(hub_op, leaf_op, leaf1["server_port"])

        drained = await drain(lb4, 5.0)
        post_names = [_bare(n) for n in await _names(lb4, chan)]
        assert "hid4" not in post_names, (
            f"hidden member leaked into NAMES after relink: {post_names!r}"
        )

        leaf_modes = await _chan_modes(lb4, chan)
        assert "d" in leaf_modes and "D" not in leaf_modes, (
            f"leaf1's +d (lingering hidden) flag wrong after relink: {leaf_modes!r}"
        )

        join_nicks = {sender_nick(m) for m in drained if m.command == "JOIN"}
        assert "hid4" not in join_nicks, (
            f"hidden member's JOIN leaked during the relink burst: {drained!r}"
        )

        await hid4.send(f"PRIVMSG {chan} :now")
        await wait_for_join(lb4, chan, "hid4", timeout=5.0)
        msg = await lb4.wait_for("PRIVMSG", timeout=5.0)
        assert msg.params[-1] == "now", f"unexpected reveal PRIVMSG: {msg!r}"

        leaf_modes_after = await _chan_modes(lb4, chan)
        assert "d" not in leaf_modes_after, (
            f"+d not cleared on leaf1 after the last hidden member spoke: "
            f"{leaf_modes_after!r}"
        )
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


# --------------------------------------------------------------------------
# adversarial: the mirror image of #3/#4 — the hidden member is on the LEAF
# and the observer is on the HUB, so the hub is the BURST *receiver* for the
# :d specifier instead of the sender.
# --------------------------------------------------------------------------


@pytest.mark.timeout(300)
async def test_hidden_member_on_leaf_survives_relink_observed_from_hub(ircd_network):
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    clients: list[IRCClient] = []

    async def mk(server, nick, is_oper=False):
        c = await (_oper_client(server, nick) if is_oper else _client(server, nick))
        clients.append(c)
        return c

    try:
        hub_op = await mk(hub, "rl6hubop", True)
        leaf_op = await mk(leaf1, "rl6leafop", True)
        chan = "#rl6"

        # lb6 joins the channel as an ordinary (non-hidden) member *before*
        # +D is set, so its own join is a ordinary visible JOIN; a join to
        # an already-+D channel would itself be hidden (doc/P11.md 8.3),
        # which would defeat using it as the always-visible reference member.
        hb6 = await mk(hub, "hb6")
        await join(hb6, chan)
        lb6 = await mk(leaf1, "lb6")
        await join(lb6, chan)
        await hb6.wait_for("JOIN", timeout=5.0)  # lb6's remote join

        await hb6.send(f"MODE {chan} +D")
        await hb6.wait_for("MODE", timeout=5.0)
        # Confirm +D actually reached leaf1 before splitting: this MODE's
        # S2S relay is a separate, unsynchronized event from hub's own echo.
        await _wait_chan_mode_letter(lb6, chan, "D")

        await _split(hub_op, leaf_op)
        try:
            # A brand-new hidden member joins on leaf1's side of the split.
            lhid6 = await mk(leaf1, "lhid6")
            await join(lhid6, chan)  # hidden locally too: lb6 sees no JOIN
        finally:
            await _heal(hub_op, leaf_op, leaf1["server_port"])

        drained = await drain(hb6, 5.0)
        names = [_bare(n) for n in await _names(hb6, chan)]
        assert "lhid6" not in names, (
            f"hidden member joined on the leaf leaked into NAMES on the hub "
            f"after relink: {names!r}"
        )

        join_nicks = {sender_nick(m) for m in drained if m.command == "JOIN"}
        assert "lhid6" not in join_nicks, (
            f"leaf-side hidden member's JOIN leaked to the hub: {drained!r}"
        )

        await lhid6.send(f"PRIVMSG {chan} :now")
        await wait_for_join(hb6, chan, "lhid6", timeout=5.0)
        msg = await hb6.wait_for("PRIVMSG", timeout=5.0)
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
