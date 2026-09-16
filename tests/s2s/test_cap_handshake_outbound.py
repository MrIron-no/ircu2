"""P11 link capability handshake, connector side and whole network
(doc/P11.md, "Link capabilities").

Connector side: the hub is told to CONNECT to a stub running in the accepting
role in a sidecar container (cap_sidecar.py).  The hub must send its CAP line
only after it has seen the stub's SERVER, wait for the stub's CAP before
bursting, refuse a wrong first line, send nothing CAP-related to a P10
acceptor, and report a second CONNECT during the wait as already in
progress.

Network: hub plus two autoconnecting leaves, all P11, must log the negotiated
(empty) set on every link, and crossed connects must converge to one link.
"""

from __future__ import annotations

import asyncio
import re
import time

import pytest
import pytest_asyncio

from cap_helpers import oper_up
from s2s.cap_sidecar import SidecarCapStub, SIDECAR_PORT, SIDECAR_SERVER_NAME
from conftest import docker_exec
from debug_support import docker_logs
from irc_client import IRCClient
from p11_server import server_numeric

NETWORK_LOG = "/tmp/ircd-network.log"
STUB_NUM = server_numeric(6)          # cap_stub_main.py default --numeric 6


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _network_log(server: dict) -> str:
    result = docker_exec(server["container"], "cat", NETWORK_LOG)
    return result.stdout if result.returncode == 0 else ""


async def _wait_for_log(server: dict, needle: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        text = _network_log(server)
        if needle in text:
            return text
        await asyncio.sleep(0.5)
    return text


async def _snomask_oper(hub: dict, nick: str) -> IRCClient:
    c = IRCClient()
    await c.connect(hub["host"], hub["port"])
    await c.register(nick, "oper", "CAP link oper")
    await oper_up(c)
    await c.send(f"MODE {nick} +s +65535")
    await asyncio.sleep(0.2)
    return c


async def _wait_notice(oper: IRCClient, pattern: str, seconds: float) -> str:
    rx = re.compile(pattern)
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"no server notice matching {pattern!r}")
        try:
            msg = await oper.recv(timeout=remaining)
        except asyncio.TimeoutError:
            continue
        if msg.command == "NOTICE" and rx.search(msg.params[-1]):
            return msg.params[-1]


async def _links(oper: IRCClient, timeout: float = 5.0) -> list[str]:
    """Server names from a LINKS reply."""
    await oper.send("LINKS")
    names: list[str] = []
    deadline = time.monotonic() + timeout
    while True:
        msg = await oper.recv(timeout=max(0.1, deadline - time.monotonic()))
        if msg.command == "364":
            names.append(msg.params[1].lower())
        elif msg.command == "365":
            return names


async def _wait_links(oper: IRCClient, name: str, present: bool, timeout: float) -> list[str]:
    deadline = time.monotonic() + timeout
    names: list[str] = []
    while time.monotonic() < deadline:
        names = await _links(oper)
        if (name.lower() in names) == present:
            return names
        await asyncio.sleep(0.5)
    raise AssertionError(f"{name} {'still' if present is False else 'not'} in LINKS: {names}")


@pytest_asyncio.fixture
async def link_oper(ircd_hub):
    oper = await _snomask_oper(ircd_hub, "caplinkop")
    yield oper
    try:
        await oper.disconnect()
    except Exception:
        pass


async def _connect_out(oper: IRCClient) -> None:
    await oper.send(f"CONNECT {SIDECAR_SERVER_NAME} {SIDECAR_PORT}")


async def _stop_and_unlink(stub: SidecarCapStub, oper: IRCClient) -> None:
    """Remove the sidecar and wait until the hub has dropped the link."""
    await stub.stop()
    try:
        await _wait_links(oper, SIDECAR_SERVER_NAME, present=False, timeout=15.0)
    except (AssertionError, asyncio.TimeoutError, ConnectionError):
        pass


# ---------------------------------------------------------------------------
# connector side (hub -> sidecar stub)
# ---------------------------------------------------------------------------


@pytest.mark.single_server
async def test_outbound_sends_cap_only_after_peer_server(ircd_hub, link_oper):
    stub = SidecarCapStub(caps="draft/foo")
    await stub.start()
    try:
        await _connect_out(link_oper)
        await stub.wait_event("accepted", 10.0)
        await stub.wait_line("out", f"{STUB_NUM} EA", 20.0)      # handshake complete

        lines_in = stub.lines_in
        assert lines_in[0].startswith("PASS "), lines_in[:4]
        assert lines_in[1].startswith("SERVER "), lines_in[:4]
        assert lines_in[2] == "CAP :", lines_in[:4]
        assert not lines_in[3].startswith("CAP"), lines_in[:5]   # burst follows

        # The hub sent CAP only after our SERVER went out.
        order = stub.lines
        our_server = next(i for i, (d, t) in enumerate(order) if d == "out" and t.startswith("SERVER "))
        hub_cap = next(i for i, (d, t) in enumerate(order) if d == "in" and t == "CAP :")
        assert hub_cap > our_server, order[: hub_cap + 1]

        needle = f"CAP: {SIDECAR_SERVER_NAME} offered [draft/foo] negotiated []"
        text = await _wait_for_log(ircd_hub, needle, 5.0)
        assert needle in text, text[-2000:]
    finally:
        await _stop_and_unlink(stub, link_oper)


@pytest.mark.single_server
async def test_outbound_wrong_first_line_is_violation(ircd_hub, link_oper):
    stub = SidecarCapStub(first_line="PING :x")
    await stub.start()
    try:
        await _connect_out(link_oper)
        await stub.wait_event("accepted", 10.0)
        # An outbound link still in handshake is closed with a SQUIT carrying
        # the reason (an inbound one would get ERROR :Closing Link).
        err = await stub.wait_line_containing("in", "Protocol violation: expected CAP after SERVER, got PING", 15.0)
        assert err["text"].startswith((":hub.test.net SQUIT", "ERROR :Closing Link")), err
        note = await _wait_notice(link_oper, rf"Protocol violation from {SIDECAR_SERVER_NAME}", 10.0)
        assert "expected CAP after SERVER, got PING" in note, note
        assert not any(t.startswith(f"{STUB_NUM} EB") for t in stub.lines_out), stub.lines
    finally:
        await _stop_and_unlink(stub, link_oper)


@pytest.mark.single_server
async def test_outbound_to_p10_peer_sends_no_cap(ircd_hub, link_oper):
    stub = SidecarCapStub(protocol=10)
    await stub.start()
    try:
        await _connect_out(link_oper)
        await stub.wait_event("accepted", 10.0)
        await stub.wait_line("out", f"{STUB_NUM} EA", 20.0)
        lines_in = stub.lines_in
        assert lines_in[0].startswith("PASS "), lines_in[:3]
        assert lines_in[1].startswith("SERVER "), lines_in[:3]
        assert not any(t.startswith("CAP") for t in lines_in), lines_in[:5]
        assert len(lines_in) > 2 and not lines_in[2].startswith("CAP"), lines_in[:4]
    finally:
        await _stop_and_unlink(stub, link_oper)


@pytest.mark.single_server
async def test_connect_during_cap_wait_is_refused(ircd_hub, link_oper):
    stub = SidecarCapStub(cap_delay=4.0)
    await stub.start()
    try:
        await _connect_out(link_oper)
        await stub.wait_event("accepted", 10.0)
        await asyncio.sleep(1.0)
        await _connect_out(link_oper)
        note = await _wait_notice(link_oper, rf"Connection to {SIDECAR_SERVER_NAME} already in progress", 5.0)
        assert note
        await stub.wait_line("out", f"{STUB_NUM} EA", 25.0)
        await stub.refresh()
        assert stub.accepted == 1, stub.events
    finally:
        await _stop_and_unlink(stub, link_oper)


# ---------------------------------------------------------------------------
# whole network (hub + two leaves, all P11)
# ---------------------------------------------------------------------------


@pytest.mark.multi_server
async def test_network_links_negotiate_cap(ircd_network):
    hub, leaf1, leaf2 = ircd_network["hub"], ircd_network["leaf1"], ircd_network["leaf2"]
    for server, peer in ((hub, "leaf1.test.net"), (hub, "leaf2.test.net"),
                         (leaf1, "hub.test.net"), (leaf2, "hub.test.net")):
        needle = f"CAP: {peer} offered [] negotiated []"
        text = await _wait_for_log(server, needle, 30.0)
        assert needle in text, f"{server['name']}: {text[-2000:]}"


@pytest.mark.multi_server
async def test_crossed_connects_converge(ircd_network, make_client):
    hub, leaf1 = ircd_network["hub"], ircd_network["leaf1"]
    hub_op = await make_client("xcaphub")
    await oper_up(hub_op)
    leaf_op = await make_client("xcapleaf", host=leaf1["host"], port=leaf1["port"])
    await oper_up(leaf_op)

    for attempt in range(3):
        await hub_op.send(f"SQUIT {leaf1['name']} :crossed-connect test {attempt}")
        await _wait_links(hub_op, leaf1["name"], present=False, timeout=15.0)
        await _wait_links(leaf_op, hub["name"], present=False, timeout=15.0)

        await asyncio.gather(
            hub_op.send(f"CONNECT {leaf1['name']} {leaf1['server_port']}"),
            leaf_op.send(f"CONNECT {hub['name']} {hub['server_port']}"),
        )

        hub_links = await _wait_links(hub_op, leaf1["name"], present=True, timeout=15.0)
        leaf_links = await _wait_links(leaf_op, hub["name"], present=True, timeout=15.0)
        await asyncio.sleep(1.0)
        hub_links = await _links(hub_op)
        leaf_links = await _links(leaf_op)
        assert hub_links.count(leaf1["name"]) == 1, hub_links
        assert leaf_links.count(hub["name"]) == 1, leaf_links

    for server in (hub, leaf1):
        assert "Unknown numeric nick" not in docker_logs(server["container"]), server["name"]
        assert "Unknown numeric nick" not in _network_log(server), server["name"]
