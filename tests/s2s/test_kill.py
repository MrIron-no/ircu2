"""P11 KILL (D) path/reason syntax (issue #121).

On a P11 link the kill path is its own parameter and the reason is the
trailing parameter, so a long path cannot truncate the reason.  On a P10
link both share the trailing parameter (``<path> <reason>``), split on the
first space.  These tests inject a KILL from a linked server and confirm
the victim is removed with the full reason intact in either form.
"""

from __future__ import annotations

import asyncio

import pytest

from p11_server import P11Server

pytestmark = pytest.mark.single_server

REASON = "DISTINCTIVE_KILL_REASON_END"
LONGPATH = "!".join(f"hop{i}.a.rather.long.server.name.example.test.net"
                    for i in range(6))


async def _link(hub, numeric=5, protocol=None) -> P11Server:
    kwargs = dict(name="notulined.test.net", numeric=numeric,
                  password="testpass", server_flags="")
    if protocol is not None:
        kwargs["protocol"] = protocol
    srv = P11Server(**kwargs)
    await srv.connect(hub["host"], hub["server_port"])
    return srv


async def _kill_and_check(srv, watcher, chan, kill_line):
    victim = await srv.introduce_user("killvictim")
    await srv.send_join(victim, chan)
    await asyncio.sleep(0.5)

    await srv._send(kill_line.format(srv=srv.server_numnick, victim=victim))

    q = await watcher.wait_for("QUIT", timeout=5.0)
    assert "killvictim" in (q.prefix or "").lower(), q.raw
    assert REASON in " ".join(q.params), q.raw


async def test_p11_kill_delivers_full_reason(ircd_hub, make_client):
    """A P11 KILL splits path and reason, so a long path leaves the reason
    intact."""
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        chan = "#killp11"
        watcher = await make_client("killwatch11")
        await watcher.send(f"JOIN {chan}")
        await watcher.wait_for("JOIN")
        await _kill_and_check(
            srv, watcher, chan,
            "{srv} D {victim} " + LONGPATH + " :" + REASON)
    finally:
        await srv.disconnect()


async def test_p10_kill_delivers_reason(ircd_hub, make_client):
    """A P10 KILL packs path and reason in the trailing parameter, split on
    the first space; the reason is still delivered."""
    srv = await _link(ircd_hub, protocol=10)
    try:
        await srv.handshake()
        chan = "#killp10"
        watcher = await make_client("killwatch10")
        await watcher.send(f"JOIN {chan}")
        await watcher.wait_for("JOIN")
        await _kill_and_check(
            srv, watcher, chan,
            "{srv} D {victim} :" + LONGPATH + " " + REASON)
    finally:
        await srv.disconnect()


async def test_kill_relayed_to_p10_downlink_uses_combined_form(ircd_hub):
    """A KILL entering on a P11 link is relayed to a P10 downlink in the P10
    combined form: the path and reason share one trailing parameter (no ':'
    between them), whereas a P11 downlink would receive them split."""
    src = await _link(ircd_hub, numeric=5)                       # P11 source
    spy = P11Server(name="uworldonly.test.net", numeric=6,
                    password="testpass", server_flags="",
                    protocol=10)                                 # P10 observer
    await spy.connect(ircd_hub["host"], ircd_hub["server_port"])
    try:
        await src.handshake()
        await spy.handshake()
        victim = await src.introduce_user("relayvictim")
        await asyncio.sleep(0.5)
        await spy.drain_messages(0.3)
        spy.received.clear()

        await src._send(f"{src.server_numnick} D {victim} {LONGPATH} :{REASON}")
        await asyncio.sleep(0.5)
        await spy.drain_messages(0.5)

        kill_lines = [l for l in spy.received
                      if REASON in l and l.split()[1:2] == ["D"]]
        assert kill_lines, spy.received[-6:]
        line = kill_lines[0]
        # P10 combined form: the reason shares the trailing parameter with the
        # path (space-separated, a single leading ':'), not split off with its
        # own ':' as the P11 form would be.
        assert f" {REASON}" in line and f":{REASON}" not in line, line
        # The path is capped (KILLPATHLEN), so even a long path cannot squeeze
        # the reason out: it survives intact at the end of the line.
        assert line.rstrip().endswith(REASON), line
    finally:
        await src.disconnect()
        await spy.disconnect()
