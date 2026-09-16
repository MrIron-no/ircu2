"""P11 link capability handshake, acceptor side (doc/P11.md, "Link
capabilities").

The stub connects to the hub as a P11 (or P10) server.  On a P11 link the
hub must send exactly one unprefixed ``CAP :<list>`` line between its
SERVER line and its burst, wait for ours, intersect and log, and refuse
anything else in that slot.  A P10 peer must never see a CAP line.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from common import set_feature
from conftest import docker_exec
from p10_server import P10Server

pytestmark = pytest.mark.single_server

NETWORK_LOG = "/tmp/ircd-network.log"


def _network_log(hub) -> str:
    """Return the hub's network-subsystem log file, "" if not written yet."""
    result = docker_exec(hub["container"], "cat", NETWORK_LOG)
    return result.stdout if result.returncode == 0 else ""


async def _wait_for_log(hub, needle: str, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        text = _network_log(hub)
        if needle in text:
            return text
        await asyncio.sleep(0.25)
    return text


def _stub(**kwargs) -> P10Server:
    defaults = dict(name="services.test.net", numeric=4, password="testpass")
    defaults.update(kwargs)
    return P10Server(**defaults)


async def _read_until_closed(srv: P10Server, timeout: float) -> list[str]:
    """Read raw lines until the hub closes the connection; return them."""
    lines: list[str] = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"hub did not close the link; got {lines}")
        try:
            lines.append(await srv.read_raw_line(timeout=remaining))
        except ConnectionError:
            return lines


async def _begin(srv: P10Server, hub) -> None:
    """Connect and send PASS + SERVER without reading anything back."""
    await srv.connect(hub["host"], hub["server_port"])
    now = int(time.time())
    await srv._send(f"PASS :{srv.password}")
    await srv._send(
        f"SERVER {srv.name} 1 {now} {now} J{srv.protocol} {srv._numnick_mask} "
        f"+{srv.server_flags} :{srv.description}"
    )


async def test_hub_sends_empty_cap_between_server_and_burst(ircd_hub):
    srv = _stub()
    try:
        await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
        await srv.handshake()
        assert srv.peer_protocol == 11, srv.peer_protocol
        assert srv.peer_cap_line == "CAP :", srv.peer_cap_line
        assert srv.handshake_order[:3] == ["SERVER", "CAP", "BURST"], srv.handshake_order
    finally:
        await srv.disconnect()


async def test_peer_caps_intersect_to_empty_and_are_logged(ircd_hub):
    srv = _stub(caps="draft/foo bar=1")
    try:
        await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
        await srv.handshake()
        needle = "CAP: services.test.net offered [draft/foo bar=1] negotiated []"
        text = await _wait_for_log(ircd_hub, needle)
        assert needle in text, text[-2000:]
    finally:
        await srv.disconnect()


async def test_wrong_first_line_closes_link(ircd_hub):
    srv = _stub(first_line="PING :x")
    try:
        await _begin(srv, ircd_hub)
        # Read PASS/SERVER/CAP from the hub; our PING goes out when its
        # SERVER is seen.  Then the hub must refuse and close.
        lines: list[str] = []
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                line = await srv.read_raw_line(timeout=deadline - time.monotonic())
            except ConnectionError:
                break
            lines.append(line)
            await srv._observe_handshake_line(line)
        joined = "\n".join(lines)
        assert "ERROR :Closing Link" in joined, joined
        assert "Protocol violation: expected CAP after SERVER, got PING" in joined, joined
        assert not any(srv._get_token(l) == "EB" for l in lines), "hub burst anyway"
    finally:
        await srv.disconnect()


async def test_bare_cap_is_accepted(ircd_hub):
    srv = _stub(first_line="CAP")
    try:
        await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
        await srv.handshake()
        needle = "CAP: services.test.net offered [] negotiated []"
        text = await _wait_for_log(ircd_hub, needle)
        assert needle in text, text[-2000:]
    finally:
        await srv.disconnect()


async def test_silent_peer_times_out(ircd_hub, oper):
    """A P11 peer that never sends CAP is closed by CONNECTTIMEOUT.

    The default (90 s) is lowered for this test only; a permanently short
    value would cut off clients that legitimately stay unregistered for a
    long CAP negotiation (see tests/cap/test_stress.py).
    """
    await set_feature(oper, "CONNECTTIMEOUT", "10")
    srv = _stub(send_cap=False)
    try:
        started = time.monotonic()
        await _begin(srv, ircd_hub)
        lines = await _read_until_closed(srv, timeout=25.0)
        elapsed = time.monotonic() - started
        joined = "\n".join(lines)
        assert "ERROR :Closing Link" in joined, joined
        assert "Registration Timeout" in joined, joined
        # Anything much faster than the 10 s timeout would mean the strict
        # gate, not the timeout, closed the link.
        assert elapsed >= 8.0, f"closed after {elapsed:.1f}s: {joined}"
        assert not any(srv._get_token(l) == "EB" for l in lines), "hub burst anyway"
    finally:
        await srv.disconnect()
        await set_feature(oper, "CONNECTTIMEOUT", "90")


async def test_p10_peer_receives_no_cap(ircd_hub):
    srv = _stub(protocol=10)
    try:
        await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
        await srv.handshake()
        assert srv.peer_cap_line is None, srv.peer_cap_line
        assert srv.handshake_order[:2] == ["SERVER", "BURST"], srv.handshake_order
        assert not any(l.startswith("CAP") for l in srv.received), srv.received
    finally:
        await srv.disconnect()

