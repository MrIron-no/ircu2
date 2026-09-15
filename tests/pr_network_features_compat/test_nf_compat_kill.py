"""KILL across a P11/P10 network (P11 issue #121).

A is a P10 release, B and C are P11 working-tree servers.  On a P11 link a
KILL carries the path and reason as separate parameters; on a P10 link they
share the trailing parameter.  A KILL that crosses the version boundary is
re-rendered per hop, so the victim is removed and the reason survives in
either direction.  These tests OPER on one end and kill a user on the other,
observing the QUIT (with its reason) on a bystander who shares a channel with
the victim.
"""

from __future__ import annotations

import asyncio

import pytest

from irc_client import IRCClient

pytestmark = pytest.mark.nf_compat

REASON = "DISTINCTIVE_NF_KILL_REASON"


async def _oper(client):
    await client.send("OPER testoper operpass")
    await client.wait_for("381", timeout=5.0)


async def _run(oper_srv, victim_srv, chan, oper_nick, victim_nick, watch_nick):
    oper = IRCClient()
    await oper.connect(oper_srv["host"], oper_srv["port"])
    await oper.register(oper_nick, "u", "kill oper")

    victim = IRCClient()
    await victim.connect(victim_srv["host"], victim_srv["port"])
    await victim.register(victim_nick, "u", "kill victim")

    watcher = IRCClient()
    await watcher.connect(victim_srv["host"], victim_srv["port"])
    await watcher.register(watch_nick, "u", "kill watcher")
    try:
        await _oper(oper)
        await victim.send(f"JOIN {chan}")
        await victim.wait_for("JOIN")
        await watcher.send(f"JOIN {chan}")
        await watcher.wait_for("JOIN")
        await asyncio.sleep(0.5)

        await oper.send(f"KILL {victim_nick} :{REASON}")

        q = await watcher.wait_for("QUIT", timeout=5.0)
        assert victim_nick.lower() in (q.prefix or "").lower(), q.raw
        assert REASON in " ".join(q.params), q.raw
    finally:
        for cl in (oper, victim, watcher):
            try:
                await cl.send("QUIT :cleanup")
            except Exception:
                pass
            await cl.disconnect()


async def test_kill_from_p11_oper_to_p10_victim(ircd_nf_compat):
    """An oper on C (P11) kills a user on A (the P10 release).  The kill
    crosses the C--B (P11) then B--A (P10) hops, re-rendered into the P10
    combined form at the boundary; the victim is removed and the reason is
    intact for a bystander on A."""
    await _run(ircd_nf_compat["c"], ircd_nf_compat["a"], "#nfkill_a",
               "ckilloper", "akillvictim", "akillwatch")


async def test_kill_from_p10_oper_to_p11_victim(ircd_nf_compat):
    """The reverse compat direction: an oper on A (P10) kills a user on C
    (P11).  A emits the P10 combined form; B re-renders it into the P11 split
    form onward to C.  The victim on C is removed and the reason is intact for
    a bystander on C."""
    await _run(ircd_nf_compat["a"], ircd_nf_compat["c"], "#nfkill_c",
               "akilloper", "ckillvictim", "ckillwatch")
