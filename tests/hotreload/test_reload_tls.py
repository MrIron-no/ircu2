"""RELOAD and the TLS data path: kernel-offloaded sessions carried raw across
the exec, WebSocket-over-TLS clients, and the two ways a TLS connection is
deliberately shed (KILL after reload, and "session not kTLS-offloaded" at
reload time itself).

Kernel TLS (kTLS) offload is what makes a TLS session survive execv() at
all: once both directions are offloaded the record layer lives in the
kernel, not in the OpenSSL/GnuTLS library object that dies with the old
process image (specs/2026-09-10-hot-reload.md, "Solution Approach" step 7).
A session that isn't offloaded is closed gracefully with an ERROR line
*before* the dump, in the same shedding walk that squits server links --
including when the connection asking for the reload is itself that
session, which is test_tls_oper_reload_with_preflight_failure_does_not_crash
below (a path that used to crash the daemon outright).
"""

from __future__ import annotations

import asyncio
import platform
import re
import ssl

import pytest

import tls_certs
from debug_support import docker_logs
from hotreload.helpers import (
    get_hub_pid,
    hub_running,
    move_conf_away,
    ping_pong,
    restore_conf,
    set_tls_ktls,
    wait_for_reload,
)
from irc_client import IRCClient
from irc_ws_client import IRCWebSocketClient
from tls.helpers import oper_up
from tls.keyupdate_peer import KeyUpdatePeer

pytestmark = [pytest.mark.tls, pytest.mark.asyncio, pytest.mark.hotreload]

HUB_CONTAINER = "ircu-tls-hub"

# A close initiated by the server after RELOAD must never surface as a
# protocol-level TLS error to the peer -- either a clean EOF (asyncio
# collapses some close_notify deliveries to this) or an explicit
# SSLZeroReturnError/SSLEOFError is acceptable; anything else is a bug.
_CLEAN_CLOSE_EXCEPTIONS = (ConnectionError, ssl.SSLZeroReturnError, ssl.SSLEOFError)

# Kernel TLS transmit-side rekey (a TLS 1.3 KeyUpdate on an offloaded
# session) needs Linux 6.14; see ircd/tls_ktls.c. Docker containers share
# the host kernel, so a test that drives that path can only run when the
# host is 6.14 or newer.
_KTLS_TX_REKEY_MIN = (6, 14)


def _host_kernel_version() -> tuple[int, int]:
    """(major, minor) parsed from platform.release(), e.g.
    "6.12.101+deb13-amd64" -> (6, 12). Unparseable input yields (0, 0) so
    the caller treats it as "too old to be sure"."""
    rel = platform.release()
    m = re.match(r"(\d+)\.(\d+)", rel)
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


async def _disconnect_all(*clients) -> None:
    for c in clients:
        try:
            await c.disconnect()
        except Exception:
            pass


async def _read_until_error_or_close(client: IRCClient, timeout: float):
    """Read messages until either an ERROR arrives or the socket closes.

    Returns the ERROR Message, or None if the socket closed cleanly first.
    Raises AssertionError if the socket closes with anything other than a
    clean TLS shutdown.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        remaining = deadline - asyncio.get_running_loop().time()
        try:
            msg = await client.recv(timeout=max(0.1, remaining))
        except _CLEAN_CLOSE_EXCEPTIONS:
            return None
        except ssl.SSLError as exc:
            raise AssertionError(f"unclean TLS close: {exc}") from exc
        if msg.command == "ERROR":
            return msg
    raise asyncio.TimeoutError("neither ERROR nor close observed in time")


def _register_over_ctypes_peer(peer: KeyUpdatePeer, nick: str, timeout: float = 15.0) -> bytes:
    """NICK/USER to 001 over the raw ctypes TLS peer, answering the nospoof
    PING. Mirrors tls/test_tls_keyupdate.py::_register (kept local so this
    module doesn't depend on another test module's private helpers)."""
    peer.write_app(f"NICK {nick}\r\nUSER {nick} 0 * :hotreload-keyupdate\r\n".encode())
    got = b""
    answered = 0
    for _ in range(40):
        chunk = peer.read_app(timeout=timeout)
        if not chunk:
            break
        got += chunk
        for m in re.finditer(rb"PING :(\S+)", got):
            if m.end() > answered:
                peer.write_app(b"PONG :" + m.group(1) + b"\r\n")
                answered = m.end()
        if b" 001 " in got:
            return got
    raise AssertionError(f"peer did not register; saw {got[-200:]!r}")


async def test_tls_client_survives_when_offloaded(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    oper = IRCClient()
    tls_client = IRCClient()
    plain = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await tls_client.connect_tls(hub["host"], hub["tls_port"])
    await plain.connect(hub["host"], hub["port"])
    try:
        await oper.register("rlt1op", "op", "TLS Survive Oper")
        assert (await oper_up(oper)).command == "381"
        await tls_client.register("rlt1tls", "t", "TLS Survivor")
        await plain.register("rlt1plain", "p", "Plain Peer")

        await tls_client.send("JOIN #tlsreload")
        await tls_client.collect_until("366")

        await oper.send("RELOAD")
        await wait_for_reload(
            hub["host"],
            hub["port"],
            [(oper, "rlt1-op"), (plain, "rlt1-plain"), (tls_client, "rlt1-tls")],
        )

        await tls_client.send(f"PRIVMSG {plain.nick} :from-tls")
        msg = await plain.wait_for_user_msg("PRIVMSG", timeout=15.0)
        assert msg.params[-1] == "from-tls", msg

        await plain.send(f"PRIVMSG {tls_client.nick} :from-plain")
        msg2 = await tls_client.wait_for_user_msg("PRIVMSG", timeout=15.0)
        assert msg2.params[-1] == "from-plain", msg2

        await tls_client.send("QUIT :hotreload done")
        await asyncio.sleep(1.5)  # let the QUIT and any error land in the logs

        logs = docker_logs(HUB_CONTAINER, tail=300)
        assert "EIO" not in logs, logs[-4000:]
        assert "Assertion" not in logs, logs[-4000:]
        assert hub_running()
    finally:
        await _disconnect_all(oper, plain)
        try:
            await tls_client.disconnect()
        except Exception:
            pass


async def test_websocket_tls_client_survives(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    oper = IRCClient()
    plain = IRCClient()
    ws = IRCWebSocketClient()
    await oper.connect(hub["host"], hub["port"])
    await plain.connect(hub["host"], hub["port"])
    try:
        await oper.register("rlt2op", "op", "WS Survive Oper")
        assert (await oper_up(oper)).command == "381"
        await plain.register("rlt2plain", "p", "WS Plain Peer")

        ctx = tls_certs.client_ssl_context()
        await ws.connect(f"wss://{hub['host']}:{hub['wss_port']}/", ssl=ctx)
        msgs = await ws.register("rlt2ws", "w", "WS Survivor")
        assert any(m.command == "001" for m in msgs), msgs

        await ws.send("JOIN #wsreload")
        await ws.collect_until("366")

        await oper.send("RELOAD")
        await wait_for_reload(
            hub["host"], hub["port"], [(oper, "rlt2-op"), (plain, "rlt2-plain")]
        )
        await ping_pong(ws, "rlt2-ws")

        await ws.send(f"PRIVMSG {plain.nick} :from-ws")
        msg = await plain.wait_for_user_msg("PRIVMSG", timeout=15.0)
        assert msg.params[-1] == "from-ws", msg

        await plain.send(f"PRIVMSG {ws.nick} :from-plain-to-ws")
        msg2 = await ws.wait_for("PRIVMSG", timeout=15.0)
        assert msg2.params[-1] == "from-plain-to-ws", msg2
    finally:
        await _disconnect_all(oper, plain)
        try:
            await ws.disconnect()
        except Exception:
            pass


async def test_tls_close_after_reload_is_clean(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    oper = IRCClient()
    victim = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await victim.connect_tls(hub["host"], hub["tls_port"])
    try:
        await oper.register("rlt3op", "op", "TLS Kill Oper")
        assert (await oper_up(oper)).command == "381"
        await victim.register("rlt3victim", "v", "TLS Kill Victim")

        await oper.send("RELOAD")
        await wait_for_reload(
            hub["host"], hub["port"], [(oper, "rlt3-op"), (victim, "rlt3-victim")]
        )

        await oper.send(f"KILL {victim.nick} :hotreload close test")

        closed_cleanly = False
        deadline = asyncio.get_running_loop().time() + 15.0
        while asyncio.get_running_loop().time() < deadline:
            try:
                await victim.recv(timeout=5.0)
            except _CLEAN_CLOSE_EXCEPTIONS:
                closed_cleanly = True
                break
            except ssl.SSLError as exc:
                raise AssertionError(f"unclean TLS close after KILL: {exc}") from exc
            # An ERROR line (or nothing) before the close is fine; keep reading.
        assert closed_cleanly, "connection never closed cleanly after KILL"
    finally:
        await _disconnect_all(oper)
        try:
            await victim.disconnect()
        except Exception:
            pass


@pytest.mark.skipif(
    _host_kernel_version() < _KTLS_TX_REKEY_MIN,
    reason=(
        "kernel TLS-TX rekey requires Linux >= %d.%d (host is %d.%d); a "
        "post-reload TLS 1.3 KeyUpdate on an offloaded session cannot be "
        "exercised below that"
        % (_KTLS_TX_REKEY_MIN + _host_kernel_version())
    ),
)
async def test_tls_keyupdate_after_reload_closes_cleanly(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    oper = IRCClient()
    bystander = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await bystander.connect(hub["host"], hub["port"])
    peer = KeyUpdatePeer(hub["host"], hub["tls_port"])
    try:
        await oper.register("rlt4op", "op", "KeyUpdate Reload Oper")
        assert (await oper_up(oper)).command == "381"
        await bystander.register("rlt4bystander", "b", "KeyUpdate Bystander")

        def setup():
            peer.connect()
            peer.handshake()
            _register_over_ctypes_peer(peer, "rlt4peer")

        await asyncio.to_thread(setup)

        await oper.send("RELOAD")
        await wait_for_reload(
            hub["host"], hub["port"], [(oper, "rlt4-op"), (bystander, "rlt4-bystander")]
        )

        def send_keyupdate():
            rec = peer.key_update_record(requested=True)
            assert rec and rec[0] == 0x17, f"expected an encrypted record, got {rec[:8]!r}"
            peer.send_raw(rec)

        await asyncio.to_thread(send_keyupdate)

        def wait_closed() -> bool:
            # kernel TLS cannot rekey (support arrived in kernel 6.14, this
            # host runs 6.12): the server must close the connection rather
            # than hang or crash. A closed peer's read returns b'' once the
            # kernel has delivered (or synthesized) the close.
            for _ in range(10):
                if not peer.read_app(timeout=2.0):
                    return True
            return False

        closed = await asyncio.to_thread(wait_closed)
        assert closed, "connection not closed by server after post-reload KeyUpdate"

        await ping_pong(bystander, "rlt4-bystander-still-alive")
        assert hub_running()
    finally:
        await asyncio.to_thread(peer.close)
        await _disconnect_all(oper, bystander)


async def test_tls_not_offloaded_is_disconnected_gracefully(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    oper = IRCClient()
    await oper.connect(hub["host"], hub["port"])
    await oper.register("rlt5op", "op", "No kTLS Oper")
    assert (await oper_up(oper)).command == "381"

    victim = IRCClient()
    try:
        await set_tls_ktls(oper, False)
        await victim.connect_tls(hub["host"], hub["tls_port"])
        await victim.register("rlt5victim", "v", "No kTLS Victim")

        await oper.send("RELOAD")

        error = await _read_until_error_or_close(victim, timeout=20.0)
        assert error is not None, "TLS client closed without an ERROR line"
        assert "TLS session cannot be carried over" in error.raw, error

        await wait_for_reload(hub["host"], hub["port"], [(oper, "rlt5-op")])
    finally:
        await set_tls_ktls(oper, True)
        await _disconnect_all(oper)
        try:
            await victim.disconnect()
        except Exception:
            pass


async def test_tls_oper_reload_with_preflight_failure_does_not_crash(ircd_tls_network):
    """A non-offloaded TLS oper RELOADs into a pre-flight failure.

    Under the hardened contract, pre-flight runs before anything is shed:
    the failure notice reaches the TLS oper on its own still-open session
    (same as a plaintext oper would see), and the daemon keeps serving --
    no netsplit, no dropped TLS client, same PID. The oper's session is
    only shed with the "cannot be carried over" ERROR once a *subsequent*
    RELOAD's pre-flight actually passes; this test checks both halves so
    the distinction is pinned, not just the "does not crash" half that
    motivated the original regression coverage (a failed pre-flight used
    to crash the daemon when the issuer was itself a non-offloaded TLS
    session, back when shedding ran first).
    """
    hub = ircd_tls_network["hub"]
    bystander = IRCClient()
    plain_oper = IRCClient()
    tls_oper = IRCClient()
    await bystander.connect(hub["host"], hub["port"])
    await plain_oper.connect(hub["host"], hub["port"])
    moved = False
    try:
        await bystander.register("rlt6bystander", "b", "Preflight TLS Bystander")
        await plain_oper.register("rlt6plainop", "po", "Preflight TLS Plain Oper")
        assert (await oper_up(plain_oper)).command == "381"

        pid_before = get_hub_pid()

        await set_tls_ktls(plain_oper, False)
        await tls_oper.connect_tls(hub["host"], hub["tls_port"])
        await tls_oper.register("rlt6tlsop", "to", "Preflight TLS Oper")
        assert (await oper_up(tls_oper)).command == "381"

        await move_conf_away()
        moved = True

        await tls_oper.send("RELOAD")

        deadline = asyncio.get_running_loop().time() + 20.0
        aborted = None
        while asyncio.get_running_loop().time() < deadline:
            msg = await tls_oper.recv(timeout=5.0)
            if msg.command == "NOTICE" and (
                "Reload aborted: pre-flight check failed" in msg.params[-1]
            ):
                aborted = msg
                break
            if msg.command == "ERROR":
                raise AssertionError(
                    f"TLS oper was shed on a failed pre-flight (should not "
                    f"be, under the hardened contract): {msg.raw}"
                )
        assert aborted is not None, "no pre-flight-abort NOTICE observed on the TLS oper"

        await restore_conf()
        moved = False

        assert hub_running()
        pid_after = get_hub_pid()
        assert pid_after == pid_before, (pid_before, pid_after)

        # The TLS oper's own session must have survived the failed reload.
        await ping_pong(tls_oper, "rlt6-tlsop-still-alive")
        await ping_pong(bystander, "rlt6-bystander-alive")
        await ping_pong(plain_oper, "rlt6-plainop-alive")

        # Config is restored: a subsequent RELOAD's pre-flight passes, and
        # *now* the still-non-offloaded TLS oper is shed with the usual
        # ERROR, same as any other non-offloaded TLS session.
        await plain_oper.send("RELOAD")
        error = await _read_until_error_or_close(tls_oper, timeout=20.0)
        assert error is not None, "TLS oper closed without an ERROR line"
        assert "TLS session cannot be carried over" in error.raw, error

        await wait_for_reload(
            hub["host"],
            hub["port"],
            [(bystander, "rlt6-bystander-recovered"), (plain_oper, "rlt6-plainop-recovered")],
        )
    finally:
        if moved:
            await restore_conf()
        await set_tls_ktls(plain_oper, True)
        await _disconnect_all(bystander, plain_oper)
        try:
            await tls_oper.disconnect()
        except Exception:
            pass
