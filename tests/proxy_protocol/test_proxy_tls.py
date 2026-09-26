"""PROXY protocol ahead of TLS: tests/docker/ircd-tls-hub.conf port 6702
(external 16702), ``tls = yes; proxy = yes;``.

The PROXY header must be read and consumed entirely in cleartext *before*
the TLS handshake begins -- proxy_preamble_done() in ircd/s_bsd.c only
calls ircd_tls_accept() once the header is parsed.
"""

from __future__ import annotations

import asyncio
import random
import ssl

import pytest

from irc_client import IRCClient, parse_message
from proxy_protocol.proxy_helpers import (
    _start_tls_on_writer,
    normalize_ip,
    raw_register,
    v1_header,
    v2_header,
    whois_host,
)
from tls_certs import client_ssl_context

pytestmark = pytest.mark.tls_single


async def _tls_hub_observer(ircd_tls_hub, nick: str) -> IRCClient:
    client = IRCClient()
    await client.connect(ircd_tls_hub["host"], ircd_tls_hub["port"])
    await client.register(nick, "obsuser", "tls proxy observer")
    return client


def _nick_from_welcome(raw_lines: list[str]) -> str | None:
    for line in raw_lines:
        msg = parse_message(line)
        if msg.command == "001" and msg.params:
            return msg.params[0]
    return None


async def test_v2_then_tls_registers_with_header_ip(ircd_tls_hub):
    observer = await _tls_hub_observer(ircd_tls_hub, "v2tlswho")
    try:
        header = v2_header("203.0.113.80", "203.0.113.1", 40030, 6697)
        notices, writer, raw_lines = await raw_register(
            ircd_tls_hub["host"],
            ircd_tls_hub["tls_proxy_port"],
            header,
            "v2tls",
            ssl_context=client_ssl_context(),
        )
        try:
            nick = _nick_from_welcome(raw_lines)
            assert nick, f"never saw 001; raw: {raw_lines}"
            host = await whois_host(observer, nick)
            assert normalize_ip(host) == "203.0.113.80", host
        finally:
            writer.close()
    finally:
        try:
            await observer.send("QUIT :done")
        except Exception:
            pass
        await observer.disconnect()


async def test_v1_then_tls_registers(ircd_tls_hub):
    observer = await _tls_hub_observer(ircd_tls_hub, "v1tlswho")
    try:
        header = v1_header("203.0.113.81", "203.0.113.1", 40031, 6697)
        notices, writer, raw_lines = await raw_register(
            ircd_tls_hub["host"],
            ircd_tls_hub["tls_proxy_port"],
            header,
            "v1tls",
            ssl_context=client_ssl_context(),
        )
        try:
            nick = _nick_from_welcome(raw_lines)
            assert nick, f"never saw 001; raw: {raw_lines}"
            host = await whois_host(observer, nick)
            assert normalize_ip(host) == "203.0.113.81", host
        finally:
            writer.close()
    finally:
        try:
            await observer.send("QUIT :done")
        except Exception:
            pass
        await observer.disconnect()


async def test_tls_proxy_port_keeps_client_fingerprint(ircd_tls_hub):
    """proxy = yes + tls = yes must still capture and pin the client cert,
    unlike proxy = cloudflare ports."""
    nick = f"fptls{random.randint(0, 999_999)}"
    reader, writer = await asyncio.open_connection(
        ircd_tls_hub["host"], ircd_tls_hub["tls_proxy_port"]
    )
    try:
        writer.write(v1_header("203.0.113.82", "203.0.113.1", 40032, 6697))
        await writer.drain()
        await _start_tls_on_writer(writer, client_ssl_context(cert="selfsigned"))

        writer.write(f"NICK {nick}\r\n".encode())
        writer.write(b"USER fptlsuser 0 * :fingerprint test\r\n")
        await writer.drain()

        got_381 = False
        oper_sent = False
        deadline = asyncio.get_running_loop().time() + 30.0
        while asyncio.get_running_loop().time() < deadline:
            raw = await asyncio.wait_for(
                reader.readline(), timeout=deadline - asyncio.get_running_loop().time()
            )
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            msg = parse_message(line)
            if msg.command == "PING":
                writer.write(f"PONG :{msg.params[-1]}\r\n".encode())
                await writer.drain()
                continue
            if msg.command in ("376", "422") and not oper_sent:
                oper_sent = True
                writer.write(b"OPER certoper certpass\r\n")
                await writer.drain()
                continue
            if msg.command == "381":
                got_381 = True
                break
            if msg.command in ("464", "491", "532"):
                break
        assert got_381, "expected OPER success (381) with the selfsigned certfp"
    finally:
        writer.close()


async def test_tls_proxy_port_rejects_clienthello_first(ircd_tls_hub):
    """Sending the TLS ClientHello with no PROXY header must fail, silently."""
    reader, writer = await asyncio.open_connection(
        ircd_tls_hub["host"], ircd_tls_hub["tls_proxy_port"]
    )
    ctx = client_ssl_context()
    raised = None
    try:
        await asyncio.wait_for(_start_tls_on_writer(writer, ctx), timeout=8.0)
    except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError, EOFError) as exc:
        raised = exc
    assert raised is not None, (
        "expected the TLS handshake to fail when no PROXY header preceded it"
    )
    try:
        leaked = await asyncio.wait_for(reader.read(65536), timeout=0.5)
    except (asyncio.TimeoutError, ConnectionResetError, ConnectionAbortedError):
        leaked = b""
    assert leaked == b"", f"no plaintext should follow a failed handshake, got {leaked!r}"
    writer.close()
