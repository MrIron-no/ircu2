"""Raw-socket integration tests for PROXY protocol (v1/v2) user ports.

Hub topology: HUB["proxy_port"] (7003, proxy = yes) and
HUB["proxy_ws_port"] (7004, websocket = yes; proxy = yes).
"""

from __future__ import annotations

import asyncio
import random
import time

import pytest

from irc_client import IRCClient, parse_message
from pr_websocket.test_websocket_cloudflare import (
    _masked_client_frame,
    _masked_text_frame,
    _raw_ws_handshake,
    _read_one_unmasked_server_ws_frame,
)
from proxy_protocol.proxy_helpers import (
    control_host,
    expect_silent_close,
    normalize_ip,
    raw_register,
    v1_header,
    v2_header,
    whois_host,
    whois_userhost,
)
from stats_ports.test_stats_p import _oper_client, _stats_p

pytestmark = pytest.mark.single_server

HOST = "127.0.0.1"
PROXY_PORT = 7003
PROXY_WS_PORT = 7004


# ---------------------------------------------------------------------------
# Address plumbing
# ---------------------------------------------------------------------------


def _extract_nick(raw_lines: list[str]) -> str | None:
    """Pull the registered nick back out of the 001 welcome line, if present."""
    for line in raw_lines:
        msg = parse_message(line)
        if msg.command == "001" and msg.params:
            return msg.params[0]
    return None


async def _register_and_whois(observer, host, port, header, nick_prefix, **kw):
    notices, writer, raw_lines = await raw_register(host, port, header, nick_prefix, **kw)
    nick = _extract_nick(raw_lines)
    assert nick, f"never saw 001 welcome; raw lines: {raw_lines}"
    try:
        return notices, raw_lines, await whois_userhost(observer, nick)
    finally:
        writer.close()


async def test_v1_header_sets_client_ip(ircd_hub, make_client):
    observer = await make_client("v1who")
    header = v1_header("203.0.113.50", "203.0.113.1", 40001, 6667)
    _, _, (_, host) = await _register_and_whois(observer, HOST, PROXY_PORT, header, "v1ip")
    assert normalize_ip(host) == "203.0.113.50", host


async def test_v2_header_sets_client_ip(ircd_hub, make_client):
    observer = await make_client("v2who")
    header = v2_header("203.0.113.51", "203.0.113.1", 40002, 6667)
    _, _, (_, host) = await _register_and_whois(observer, HOST, PROXY_PORT, header, "v2ip")
    assert normalize_ip(host) == "203.0.113.51", host


async def test_v2_ipv6_header_sets_client_ip(ircd_hub, make_client):
    """The hub listens on IPv4; the v2 header can still claim an IPv6 family."""
    observer = await make_client("v6who")
    header = v2_header("2001:db8::50", "2001:db8::1", 40003, 6667)
    _, _, (_, host) = await _register_and_whois(observer, HOST, PROXY_PORT, header, "v2v6")
    assert normalize_ip(host) == "2001:db8::50", host


async def test_v1_header_split_across_segments(ircd_hub, make_client):
    observer = await make_client("v1split")
    header = v1_header("203.0.113.52", "203.0.113.1", 40004, 6667)
    _, _, (_, host) = await _register_and_whois(
        observer, HOST, PROXY_PORT, header, "v1sp", split_after=9
    )
    assert normalize_ip(host) == "203.0.113.52", host


async def test_v2_header_split_inside_prefix(ircd_hub, make_client):
    observer = await make_client("v2split")
    header = v2_header("203.0.113.53", "203.0.113.1", 40005, 6667)
    _, _, (_, host) = await _register_and_whois(
        observer, HOST, PROXY_PORT, header, "v2sp", split_after=7
    )
    assert normalize_ip(host) == "203.0.113.53", host


async def test_v2_tlv_is_skipped(ircd_hub, make_client):
    observer = await make_client("v2tlv")
    header = v2_header(
        "203.0.113.54", "203.0.113.1", 40006, 6667, tlv=b"\x20\x00\x04abcd"
    )
    _, _, (_, host) = await _register_and_whois(observer, HOST, PROXY_PORT, header, "v2tl")
    assert normalize_ip(host) == "203.0.113.54", host


async def test_v2_local_keeps_socket_address(ircd_hub, make_client):
    """v2 LOCAL (health check) keeps the real socket peer address."""
    observer = await make_client("v2loc")
    expected = await control_host(make_client)
    header = v2_header(cmd=0, family=1)
    _, _, (_, host) = await _register_and_whois(observer, HOST, PROXY_PORT, header, "v2lc")
    assert normalize_ip(host) == normalize_ip(expected), (host, expected)


# ---------------------------------------------------------------------------
# Ident / tilde policy
# ---------------------------------------------------------------------------


async def test_proxy_port_skips_ident_and_keeps_tilde(ircd_hub, make_client):
    observer = await make_client("identwho")
    header = v1_header("203.0.113.55", "203.0.113.1", 40007, 6667)
    notices, raw_lines, (user, _) = await _register_and_whois(
        observer, HOST, PROXY_PORT, header, "identp"
    )
    blob = "\n".join(notices)
    assert "Checking Ident" not in blob, f"proxy port must skip ident, got: {blob!r}"
    assert user.startswith("~"), f"expected tilde username, got {user!r}"


# ---------------------------------------------------------------------------
# IPcheck throttling on the claimed (proxied) address
# ---------------------------------------------------------------------------


async def _attempt_claim(port: int, ip: str, tag: str, attempt: int) -> bool:
    """Try to register claiming ``ip``. True = registered, False = closed silently."""
    header = v1_header(ip, "203.0.113.1", 41000 + attempt, 6667)
    try:
        notices, writer, raw_lines = await raw_register(
            HOST, port, header, f"{tag}{attempt}", timeout=5.0
        )
    except (ConnectionError, AssertionError, asyncio.TimeoutError):
        return False
    writer.close()
    return True


async def _set_feature(oper: IRCClient, name: str, value) -> None:
    await oper.send(f"SET {name} {value}")
    await oper.wait_for("284", timeout=5.0)


async def _reset_feature(oper: IRCClient, name: str) -> None:
    await oper.send(f"RESET {name}")
    await oper.wait_for("284", timeout=5.0)


async def test_proxy_port_throttles_on_claimed_ip(ircd_hub):
    """Repeatedly claiming the same source IP must eventually hit IPcheck.

    The hub config sets IPCHECK_CLONE_LIMIT=1000 / PERIOD=1 (permissive, for
    other suites that open many connections from one docker IP), which is
    too permissive to exercise per-IP throttling here. It is lowered with
    the oper SET command for the duration of this test only, then RESET.

    IPCHECK_CLONE_DELAY (default 600s) also suppresses all throttling until
    the server has been up that long, specifically so a restart's reconnect
    burst isn't punished -- since this container is freshly booted for the
    test run, that guard must be zeroed too or the test would never see a
    throttle no matter how low the limit is set.
    """
    oper = await _oper_client(HOST, ircd_hub["port"], "ipcsetop")
    try:
        await _set_feature(oper, "IPCHECK_CLONE_LIMIT", 3)
        await _set_feature(oper, "IPCHECK_CLONE_PERIOD", 30)
        await _set_feature(oper, "IPCHECK_CLONE_DELAY", 0)

        throttled = False
        for attempt in range(20):
            ok = await _attempt_claim(PROXY_PORT, "203.0.113.77", "thr", attempt)
            if not ok:
                throttled = True
                break
        assert throttled, "expected IPcheck to throttle repeated claims of the same IP within 20 attempts"

        # A different claimed IP must still be able to register.
        ok = await _attempt_claim(PROXY_PORT, "203.0.113.78", "throk", 0)
        assert ok, "a fresh claimed IP must not be caught by the other IP's throttle"
    finally:
        await _reset_feature(oper, "IPCHECK_CLONE_LIMIT")
        await _reset_feature(oper, "IPCHECK_CLONE_PERIOD")
        await _reset_feature(oper, "IPCHECK_CLONE_DELAY")
        await oper.disconnect()


async def test_spoofed_proxy_line_on_plain_port_is_ignored(ircd_hub, make_client):
    """A PROXY line sent to a non-proxy port is just an unknown command."""
    observer = await make_client("spoofwho")
    expected = await control_host(make_client)
    header = v1_header("203.0.113.66", "203.0.113.1", 40010, 6667)
    _, _, (_, host) = await _register_and_whois(
        observer, HOST, ircd_hub["port"], header, "spoof"
    )
    assert normalize_ip(host) == normalize_ip(expected), (host, expected)


# ---------------------------------------------------------------------------
# Rejections: silent close, zero bytes
# ---------------------------------------------------------------------------


async def test_rejects_non_proxy_first_bytes(ircd_hub):
    await expect_silent_close(HOST, PROXY_PORT, b"NICK x\r\n")


async def test_rejects_v1_unknown(ircd_hub):
    await expect_silent_close(HOST, PROXY_PORT, b"PROXY UNKNOWN\r\n")


async def test_rejects_v1_without_crlf(ircd_hub):
    # Exactly PROXY_V1_MAX (107) bytes, "PROXY " prefix, never terminated.
    payload = b"PROXY " + b"A" * (107 - len(b"PROXY "))
    assert len(payload) == 107
    await expect_silent_close(HOST, PROXY_PORT, payload)


async def test_rejects_v2_unspec_family(ircd_hub):
    header = v2_header(cmd=1, family=0, proto=1, addrlen_override=0)
    await expect_silent_close(HOST, PROXY_PORT, header)


async def test_rejects_v2_dgram(ircd_hub):
    header = v2_header("203.0.113.60", "203.0.113.61", 1234, 6667, family=1, proto=2)
    await expect_silent_close(HOST, PROXY_PORT, header)


async def test_rejects_v2_oversized_length(ircd_hub):
    header = v2_header(cmd=1, family=1, proto=1, addrlen_override=1100)
    await expect_silent_close(HOST, PROXY_PORT, header)


async def test_rejects_v1_src_unspecified(ircd_hub):
    """0.0.0.0 is a syntactically valid TCP4 address but not a usable source."""
    header = v1_header("0.0.0.0", "203.0.113.1", 40011, 6667)
    await expect_silent_close(HOST, PROXY_PORT, header)


async def test_rejects_v2_src_unspecified(ircd_hub):
    header = v2_header("0.0.0.0", "203.0.113.1", 40012, 6667)
    await expect_silent_close(HOST, PROXY_PORT, header)


async def test_rejects_v2_src_ipv6_unspecified(ircd_hub):
    header = v2_header("::", "::1", 40013, 6667)
    await expect_silent_close(HOST, PROXY_PORT, header)


async def test_rejects_silent_peer(ircd_hub):
    elapsed = await expect_silent_close(HOST, PROXY_PORT, b"", timeout=8.0)
    assert elapsed < 8.0, f"expected close near the 5s deadline, took {elapsed:.1f}s"


# ---------------------------------------------------------------------------
# Websocket + PROXY combination (port 7004)
# ---------------------------------------------------------------------------


async def _proxy_ws_register(preamble: bytes, nick: str, *, extra_headers: tuple[bytes, ...] = ()):
    reader, writer = await asyncio.open_connection(HOST, PROXY_WS_PORT)
    try:
        writer.write(preamble)
        await writer.drain()
        writer.write(_raw_ws_handshake(*extra_headers))
        await writer.drain()
        http = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        assert b"101" in http, f"expected HTTP 101 upgrade, got {http[:200]!r}"

        writer.write(_masked_text_frame(f"NICK {nick}"))
        writer.write(_masked_text_frame("USER wsproxy 0 * :proxy ws test"))
        await writer.drain()

        notices: list[str] = []
        raw_lines: list[str] = []
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            slot = min(5.0, max(0.25, deadline - time.monotonic()))
            try:
                opcode, payload = await _read_one_unmasked_server_ws_frame(reader, read_timeout=slot)
            except asyncio.TimeoutError:
                continue
            if opcode == 0x8:
                break
            if opcode == 0x9:
                writer.write(_masked_client_frame(0xA, payload))
                await writer.drain()
                continue
            if opcode != 0x1:
                continue
            line = payload.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            raw_lines.append(line)
            msg = parse_message(line)
            if msg.command == "NOTICE":
                notices.append(" ".join(msg.params))
            if msg.command.upper() == "PING":
                writer.write(_masked_text_frame(f"PONG :{msg.params[-1]}"))
                await writer.drain()
                continue
            if msg.command in ("376", "422"):
                return notices, writer, raw_lines
        raise AssertionError(f"ws proxy registration timed out; raw so far: {raw_lines}")
    except Exception:
        writer.close()
        raise


async def test_websocket_proxy_port_uses_header_ip(ircd_hub, make_client):
    observer = await make_client("wspwho")
    nick = f"wsp{random.randint(0, 999_999)}"
    header = v2_header("203.0.113.70", "203.0.113.1", 40020, 80)
    notices, writer, raw_lines = await _proxy_ws_register(header, nick)
    try:
        host = await whois_host(observer, nick)
        assert normalize_ip(host) == "203.0.113.70", host
    finally:
        writer.close()


async def test_websocket_proxy_port_ignores_cf_connecting_ip(ircd_hub, make_client):
    observer = await make_client("wspcfwho")
    nick = f"wspc{random.randint(0, 999_999)}"
    header = v2_header("203.0.113.71", "203.0.113.1", 40021, 80)
    extra = (b"CF-Connecting-IP: 203.0.113.99\r\n",)
    notices, writer, raw_lines = await _proxy_ws_register(header, nick, extra_headers=extra)
    try:
        host = await whois_host(observer, nick)
        assert normalize_ip(host) == "203.0.113.71", (
            f"proxy = yes ws port must not honor CF-Connecting-IP, got {host!r}"
        )
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# STATS P flags
# ---------------------------------------------------------------------------


async def test_stats_p_shows_proxy_flags(ircd_hub):
    client = await _oper_client(HOST, ircd_hub["port"], "statspflags")
    try:
        plines, _ = await _stats_p(client)
        by_port = {int(m.params[2]): m.params[4] for m in plines}
        assert 7003 in by_port and 7001 in by_port and 7004 in by_port, by_port

        assert "P" in by_port[7003], by_port
        assert "F" not in by_port[7003], by_port

        assert "F" in by_port[7001], by_port
        assert "P" not in by_port[7001], by_port

        assert "B" in by_port[7004], by_port
        assert "P" in by_port[7004], by_port
    finally:
        await client.disconnect()
