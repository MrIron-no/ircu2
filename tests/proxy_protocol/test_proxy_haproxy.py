"""End-to-end tests through the real HAProxy sidecar.

Confirms the address ircd records is the *origin* client's address, not the
haproxy container's own address -- i.e. that the PROXY header round-trips
correctly through a real, independent PROXY-protocol implementation, not
just the hand-built headers in test_proxy_raw.py.

haproxy.cfg listeners (see tests/docker/haproxy.cfg):
  v1_plain (7100)  -> hub plain proxy port 7003, PROXY v1
  v2_plain (7101)  -> hub plain proxy port 7003, PROXY v2
  v2_ws    (7102)  -> hub websocket proxy port 7004, PROXY v2
  v2_tls   (7103)  -> TLS hub proxy port 6702, PROXY v2, TLS passthrough
"""

from __future__ import annotations

import asyncio
import random

import pytest

from irc_client import IRCClient, parse_message
from pr_websocket.test_websocket_cloudflare import (
    _masked_client_frame,
    _masked_text_frame,
    _raw_ws_handshake,
    _read_one_unmasked_server_ws_frame,
)
from proxy_protocol.proxy_helpers import control_host, normalize_ip, whois_host
from tls_certs import client_ssl_context


async def _register_plain(host: str, port: int, nick: str) -> IRCClient:
    client = IRCClient()
    await client.connect(host, port)
    msgs = await client.register(nick, "hpuser", "haproxy test")
    assert any(m.command == "001" for m in msgs), f"registration failed: {msgs}"
    return client


@pytest.mark.single_server
async def test_haproxy_v1_reports_origin_not_proxy(ircd_hub, make_client, haproxy):
    observer = await make_client("hpv1who")
    expected = await control_host(make_client)
    nick = f"hpv1{random.randint(0, 999_999)}"
    client = await _register_plain(haproxy["host"], haproxy["v1_plain"], nick)
    try:
        host = await whois_host(observer, nick)
        assert normalize_ip(host) == normalize_ip(expected), (host, expected)
        assert normalize_ip(host) != normalize_ip(haproxy["container_ip"]), host
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


@pytest.mark.single_server
async def test_haproxy_v2_reports_origin_not_proxy(ircd_hub, make_client, haproxy):
    observer = await make_client("hpv2who")
    expected = await control_host(make_client)
    nick = f"hpv2{random.randint(0, 999_999)}"
    client = await _register_plain(haproxy["host"], haproxy["v2_plain"], nick)
    try:
        host = await whois_host(observer, nick)
        assert normalize_ip(host) == normalize_ip(expected), (host, expected)
        assert normalize_ip(host) != normalize_ip(haproxy["container_ip"]), host
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


@pytest.mark.single_server
async def test_haproxy_websocket_reports_origin(ircd_hub, make_client, haproxy):
    observer = await make_client("hpwswho")
    expected = await control_host(make_client)
    nick = f"hpws{random.randint(0, 999_999)}"

    reader, writer = await asyncio.open_connection(haproxy["host"], haproxy["v2_ws"])
    try:
        writer.write(_raw_ws_handshake())
        await writer.drain()
        http = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        assert b"101" in http, f"expected HTTP 101 upgrade, got {http[:200]!r}"

        writer.write(_masked_text_frame(f"NICK {nick}"))
        writer.write(_masked_text_frame("USER hpws 0 * :haproxy ws test"))
        await writer.drain()

        notices: list[str] = []
        deadline = asyncio.get_running_loop().time() + 30.0
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            assert remaining > 0, "haproxy websocket registration timed out"
            opcode, payload = await _read_one_unmasked_server_ws_frame(
                reader, read_timeout=min(5.0, remaining)
            )
            if opcode == 0x9:
                writer.write(_masked_client_frame(0xA, payload))
                await writer.drain()
                continue
            if opcode != 0x1:
                continue
            line = payload.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            msg = parse_message(line)
            if msg.command == "NOTICE":
                notices.append(" ".join(msg.params))
            if msg.command.upper() == "PING":
                writer.write(_masked_text_frame(f"PONG :{msg.params[-1]}"))
                await writer.drain()
                continue
            if msg.command in ("376", "422"):
                break

        blob = "\n".join(notices)
        assert "Checking Ident" not in blob, f"proxy ws port must skip ident: {blob!r}"

        host = await whois_host(observer, nick)
        assert normalize_ip(host) == normalize_ip(expected), (host, expected)
        assert normalize_ip(host) != normalize_ip(haproxy["container_ip"]), host
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _oper_up(client: IRCClient, name: str, password: str) -> None:
    await client.send(f"OPER {name} {password}")
    await client.wait_for("381", timeout=10.0)


@pytest.mark.tls_single
async def test_haproxy_tls_passthrough_keeps_fingerprint(ircd_tls_hub, haproxy):
    """TLS passed straight through haproxy: the peer cert is the real client's."""
    observer = IRCClient()
    await observer.connect(ircd_tls_hub["host"], ircd_tls_hub["port"])
    await observer.register("hptlswho", "obs", "haproxy tls observer")

    nick = f"hptls{random.randint(0, 999_999)}"
    client = IRCClient()
    ctx = client_ssl_context(cert="selfsigned")
    await client.connect_tls(haproxy["host"], haproxy["v2_tls"], ssl_context=ctx)
    msgs = await client.register(nick, "hptlsuser", "haproxy tls test")
    assert any(m.command == "001" for m in msgs), f"registration failed: {msgs}"
    try:
        await _oper_up(client, "certoper", "certpass")

        host = await whois_host(observer, nick)
        assert normalize_ip(host) != normalize_ip(haproxy["container_ip"]), host
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()
        try:
            await observer.send("QUIT :done")
        except Exception:
            pass
        await observer.disconnect()
