"""P11 retirement of the ``6`` (IPv6-capable) server flag (doc/P11.md,
"Server flags").

Client IPs are always sent in the full P10 IPv6 form.  A P11 peer implies
support and never sees the flag; a direct P10 peer must announce it or is
refused, and receives it on every SERVER line the hub sends it, its own and
the servers it introduces, whatever those servers announced themselves.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from p11_server import P11Server

pytestmark = pytest.mark.single_server


def _server_flags(lines: list[str]) -> dict[str, str]:
    """Map server name -> flag field for every SERVER line in ``lines``.

    Handles both the hub's own ``SERVER hub 1 ...`` line and tokenised
    introductions ``<num> S name hop 0 ts J11 mask +flags :info``.
    """
    flags: dict[str, str] = {}
    for line in lines:
        tok = line.split()
        if not tok:
            continue
        if tok[0] == "SERVER":
            name, field = tok[1], tok[7]
        elif len(tok) > 8 and tok[1] == "S":
            name, field = tok[2], tok[8]
        else:
            continue
        assert field.startswith("+"), line
        flags[name] = field[1:]
    return flags


async def _link(hub, **kwargs) -> P11Server:
    srv = P11Server(password="testpass", **kwargs)
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    return srv


async def _read_until_closed(srv: P11Server, timeout: float) -> list[str]:
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


async def test_p10_peer_without_ipv6_flag_is_refused(ircd_hub):
    srv = P11Server(name="services.test.net", numeric=4, password="testpass",
                    protocol=10, announce_ipv6=False)
    assert "6" not in srv.server_flags
    try:
        await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
        now = int(time.time())
        await srv._send(f"PASS :{srv.password}")
        await srv._send(
            f"SERVER {srv.name} 1 {now} {now} J10 {srv._numnick_mask} "
            f"+{srv.server_flags} :{srv.description}"
        )
        joined = "\n".join(await _read_until_closed(srv, timeout=10.0))
        assert "ERROR :Closing Link" in joined, joined
        assert "P10 peers must support IPv6 (+6)" in joined, joined
    finally:
        await srv.disconnect()


async def test_ipv6_flag_is_hardcoded_to_p10_and_absent_to_p11(ircd_hub):
    p10 = p11 = None
    try:
        # A P10 leaf links first: the hub's own line carries the flag.
        p10 = await _link(ircd_hub, name="notulined.test.net", numeric=5,
                          server_flags="", protocol=10)
        assert _server_flags(p10.received)["hub.test.net"] == "h6"

        # A P11 peer that never announced '6' links next.  Its burst shows
        # the hub and the P10 leaf (which did announce '6') without the flag.
        p11 = await _link(ircd_hub, name="services.test.net", numeric=4,
                          server_flags="s", protocol=11)
        seen = _server_flags(p11.received)
        assert seen["hub.test.net"] == "h", seen
        assert seen["notulined.test.net"] == "", seen

        # The P10 leaf is told about the P11 peer with the flag added.
        line = await p10.wait_for_token("S", timeout=5.0)
        assert _server_flags([line]) == {"services.test.net": "s6"}, line

        # A server two hops away, relayed by the hub, gets the same treatment.
        await p11.send_downstream_server("deep.test.net", numeric=6,
                                         description="Deep", flags="")
        line = await p10.wait_for_token("S", timeout=5.0)
        assert _server_flags([line]) == {"deep.test.net": "6"}, line
    finally:
        for srv in (p10, p11):
            if srv is not None:
                await srv.disconnect()
