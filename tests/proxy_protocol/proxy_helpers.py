"""Helpers for PROXY protocol (v1/v2) integration tests.

Builds raw v1/text and v2/binary HAProxy PROXY protocol headers, drives raw
registration over a socket that may need a PROXY preamble (and, optionally,
a TLS upgrade partway through), and provides small WHOIS helpers used across
the proxy_protocol test modules.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import ssl
import struct
import time

from irc_client import parse_message

# ---------------------------------------------------------------------------
# Header builders
# ---------------------------------------------------------------------------

PROXY_V2_SIG = b"\r\n\r\n\x00\r\nQUIT\n"


def v1_header(src: str, dst: str, sport: int, dport: int, proto: str | None = None) -> bytes:
    """Build a HAProxy PROXY protocol v1 (text) header line."""
    if proto is None:
        proto = "TCP6" if ipaddress.ip_address(src).version == 6 else "TCP4"
    return f"PROXY {proto} {src} {dst} {sport} {dport}\r\n".encode("ascii")


def v2_header(
    src: str | None = None,
    dst: str | None = None,
    sport: int = 0,
    dport: int = 0,
    *,
    cmd: int = 1,
    family: int | None = None,
    proto: int = 1,
    tlv: bytes = b"",
    addrlen_override: int | None = None,
) -> bytes:
    """Build a HAProxy PROXY protocol v2 (binary) header.

    ``family``: 1 = AF_INET, 2 = AF_INET6, 0 = UNSPEC, 3 = UNIX (unsupported
    here beyond triggering a rejection). Inferred from ``src`` when omitted
    and ``src`` is given. ``addrlen_override`` lets a caller lie about the
    declared address-block length (e.g. to test oversize rejection) without
    changing how many bytes are actually sent.
    """
    if family is None:
        family = 2 if src is not None and ipaddress.ip_address(src).version == 6 else 1

    ver_cmd = 0x20 | (cmd & 0x0F)
    fam_proto = ((family & 0x0F) << 4) | (proto & 0x0F)

    addr_bytes = b""
    if src is not None and dst is not None:
        if family == 1:
            addr_bytes = (
                socket.inet_pton(socket.AF_INET, src)
                + socket.inet_pton(socket.AF_INET, dst)
                + struct.pack("!HH", sport, dport)
            )
        elif family == 2:
            addr_bytes = (
                socket.inet_pton(socket.AF_INET6, src)
                + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!HH", sport, dport)
            )

    body = addr_bytes + tlv
    addrlen = addrlen_override if addrlen_override is not None else len(body)
    return PROXY_V2_SIG + bytes([ver_cmd, fam_proto]) + struct.pack("!H", addrlen) + body


# ---------------------------------------------------------------------------
# Raw registration (PROXY preamble, optional split, optional TLS upgrade)
# ---------------------------------------------------------------------------


async def _start_tls_on_writer(writer: asyncio.StreamWriter, ssl_context: ssl.SSLContext) -> None:
    """Upgrade an already-open plaintext connection to TLS in place.

    Uses ``loop.start_tls`` directly on the writer's transport (fixed for
    stream-writer use in Python 3.11+) rather than reconnecting, since the
    PROXY preamble must be sent in cleartext *before* the TLS handshake on
    proxy = yes + tls = yes ports.
    """
    loop = asyncio.get_running_loop()
    old_transport = writer.transport
    protocol = old_transport.get_protocol()
    new_transport = await loop.start_tls(old_transport, protocol, ssl_context, server_side=False)
    writer._transport = new_transport  # noqa: SLF001 - documented start_tls pattern


async def raw_register(
    host: str,
    port: int,
    preamble: bytes,
    nick: str,
    *,
    ssl_context: ssl.SSLContext | None = None,
    split_after: int | None = None,
    extra_first: bytes = b"",
    username: str = "proxyuser",
    timeout: float = 45.0,
) -> tuple[list[str], asyncio.StreamWriter, list[str]]:
    """Open a raw connection, send a PROXY preamble, optionally start TLS, register.

    ``nick`` is used as a prefix; a random suffix is appended so concurrent
    or repeated calls never collide. Returns (notice texts, the still-open
    writer, all raw lines seen). Caller is responsible for closing ``writer``.
    """
    full_nick = f"{nick}{random.randint(0, 999_999)}"
    reader, writer = await asyncio.open_connection(host, port)
    try:
        if extra_first:
            writer.write(extra_first)
            await writer.drain()

        if split_after is not None:
            writer.write(preamble[:split_after])
            await writer.drain()
            await asyncio.sleep(0.3)
            writer.write(preamble[split_after:])
            await writer.drain()
        else:
            writer.write(preamble)
            await writer.drain()

        if ssl_context is not None:
            await _start_tls_on_writer(writer, ssl_context)

        writer.write(f"NICK {full_nick}\r\n".encode())
        writer.write(f"USER {username} 0 * :proxy protocol test\r\n".encode())
        await writer.drain()

        notices: list[str] = []
        raw_lines: list[str] = []
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise AssertionError(
                    f"registration timed out for {full_nick}; raw so far: {raw_lines}"
                )
            raw = await asyncio.wait_for(reader.readline(), timeout=remaining)
            if not raw:
                raise ConnectionError(
                    f"connection closed during registration; raw so far: {raw_lines}"
                )
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            raw_lines.append(line)
            msg = parse_message(line)
            if msg.command == "PING":
                cookie = msg.params[-1] if msg.params else ""
                writer.write((f"PONG :{cookie}\r\n" if cookie else "PONG\r\n").encode())
                await writer.drain()
                continue
            if msg.command == "NOTICE":
                notices.append(" ".join(msg.params))
            if msg.command in ("432", "433", "436", "437", "464", "465"):
                raise ConnectionError(f"registration failed with {msg.command}: {line}")
            if msg.command in ("376", "422"):
                return notices, writer, raw_lines
    except Exception:
        writer.close()
        raise


# ---------------------------------------------------------------------------
# Silent-close assertion for rejected preambles
# ---------------------------------------------------------------------------


async def expect_silent_close(host: str, port: int, payload: bytes, timeout: float = 8.0) -> float:
    """Send ``payload`` (may be empty) and assert the peer closes with zero bytes back.

    Accepts either a clean EOF or ECONNRESET (an invalid first line can leave
    unread bytes at close, which some kernels turn into a reset instead of a
    graceful FIN). Returns the elapsed time so callers can also bound it.
    """
    start = time.monotonic()
    reader, writer = await asyncio.open_connection(host, port)
    data = b""
    try:
        try:
            if payload:
                writer.write(payload)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        else:
            try:
                async def _read_all() -> None:
                    nonlocal data
                    while True:
                        chunk = await reader.read(4096)
                        if not chunk:
                            return
                        data += chunk

                await asyncio.wait_for(_read_all(), timeout=timeout)
            except (ConnectionResetError, ConnectionAbortedError):
                pass
        elapsed = time.monotonic() - start
        assert data == b"", f"expected no bytes on rejection, got {data!r}"
        return elapsed
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# WHOIS helpers
# ---------------------------------------------------------------------------


async def whois_userhost(observer, nick: str) -> tuple[str, str]:
    """Return (username, host) from RPL_WHOISUSER (311)."""
    await observer.send(f"WHOIS {nick}")
    while True:
        msg = await observer.recv(timeout=10.0)
        if msg.command == "311":
            return msg.params[2], msg.params[3]
        if msg.command in ("318", "401"):
            raise AssertionError(f"WHOIS for {nick} failed: {msg}")


async def whois_host(observer, nick: str) -> str:
    _, host = await whois_userhost(observer, nick)
    return host


async def whois_user(observer, nick: str) -> str:
    user, _ = await whois_userhost(observer, nick)
    return user


async def control_host(make_client) -> str:
    """Register a plain control client on the hub's normal port and WHOIS itself.

    Gives the address docker assigns host-originated connections, which
    varies by environment (docker-proxy from the bridge gateway) but is
    stable for the duration of a test run.
    """
    nick = f"ctl{random.randint(0, 999_999)}"
    client = await make_client(nick)
    return await whois_host(client, client.nick)


def normalize_ip(host: str) -> str:
    """Normalize an address string for comparison (handles IPv6 compression)."""
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    return str(ipaddress.ip_address(candidate))
