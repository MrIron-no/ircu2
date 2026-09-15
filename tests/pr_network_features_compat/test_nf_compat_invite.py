"""INVITE target addressing across a P11/P10 network (P11 issue #115).

Topology (see ircd_nf_compat): A is a P10 release, B and C are P11
working-tree servers. On a P11 link the S2S INVITE addresses its target
by numnick (resolved with findNUser); on a P10 link it still uses the
nickname. These tests drive both paths end to end and confirm the
invitee is delivered the invite in either case.
"""

from __future__ import annotations

import pytest

from cap_helpers import make_cap_client
from irc_client import IRCClient

pytestmark = pytest.mark.nf_compat


async def _op_on(server, nick):
    """A client that creates a channel and is therefore its operator."""
    op = await make_cap_client(server["host"], server["port"], nick)
    return op


async def test_invite_to_p11_invitee_over_p11_link(ircd_nf_compat):
    """Op on C (P11) invites a user on B (P11). Delivered over the P11 B--C
    link, addressed by numnick, and the invitee receives it."""
    b = ircd_nf_compat["b"]
    c = ircd_nf_compat["c"]
    chan = "#p11inv_b"

    invitee = IRCClient()
    await invitee.connect(b["host"], b["port"])
    await invitee.register("p11inviteeB", "u", "P11 invitee on B")

    op = await _op_on(c, "cinvop1")
    try:
        await op.send(f"JOIN {chan}")
        await op.wait_for("JOIN")
        await op.send(f"INVITE p11inviteeB {chan}")
        await op.wait_for("341")

        msg = await invitee.wait_for_user_msg("INVITE", timeout=5.0)
        joined = " ".join(msg.params).lower()
        assert "p11inviteeb" in joined, msg.raw
        assert chan.lower() in joined, msg.raw
    finally:
        for cl in (op, invitee):
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            await cl.disconnect()


async def test_invite_to_p10_invitee_falls_back_to_nickname(ircd_nf_compat):
    """Op on C (P11) invites a user on A (P10). The invite crosses the P10
    A--B link, which cannot carry a numnick target, so it is addressed by
    nickname; the invitee on A still receives it."""
    a = ircd_nf_compat["a"]
    c = ircd_nf_compat["c"]
    chan = "#p11inv_a"

    invitee = IRCClient()
    await invitee.connect(a["host"], a["port"])
    await invitee.register("p10inviteeA", "u", "P10 invitee on A")

    op = await _op_on(c, "cinvop2")
    try:
        await op.send(f"JOIN {chan}")
        await op.wait_for("JOIN")
        await op.send(f"INVITE p10inviteeA {chan}")
        await op.wait_for("341")

        msg = await invitee.wait_for_user_msg("INVITE", timeout=5.0)
        joined = " ".join(msg.params).lower()
        assert "p10inviteea" in joined, msg.raw
        assert chan.lower() in joined, msg.raw
    finally:
        for cl in (op, invitee):
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            await cl.disconnect()


async def test_invite_from_p10_inviter_to_p11_invitee(ircd_nf_compat):
    """The reverse compat direction: a client on A (the P10 release) invites
    a user on C (P11). A sends a nickname INVITE; the P11 servers must
    resolve the P10 sender's nickname (FindUser) and re-address the invite
    by numnick onward over the P11 links. The invitee on C receives it."""
    a = ircd_nf_compat["a"]
    c = ircd_nf_compat["c"]
    chan = "#p10inv_from_a"

    invitee = IRCClient()
    await invitee.connect(c["host"], c["port"])
    await invitee.register("p11inviteeC", "u", "P11 invitee on C")

    op = IRCClient()
    await op.connect(a["host"], a["port"])
    await op.register("ap10op", "u", "P10 op on A")
    try:
        await op.send(f"JOIN {chan}")
        await op.wait_for("JOIN")
        await op.send(f"INVITE p11inviteeC {chan}")
        await op.wait_for("341")

        msg = await invitee.wait_for_user_msg("INVITE", timeout=5.0)
        joined = " ".join(msg.params).lower()
        assert "p11inviteec" in joined, msg.raw
        assert chan.lower() in joined, msg.raw
    finally:
        for cl in (op, invitee):
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            await cl.disconnect()
