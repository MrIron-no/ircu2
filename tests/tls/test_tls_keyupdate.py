"""Post-handshake TLS 1.3 KeyUpdate: the one real-TLS exercise of the ircd's
cross-direction data path.

A peer-initiated KeyUpdate is the only standard way (client renegotiation is
off by default on modern OpenSSL) to make a completed TLS session do more
handshake-shaped work mid-stream, which is what the con_tls_want_rd/wr
machinery in ircd_tls_recv()/sendv() + update_write() exists to handle.  These
tests drive a real KeyUpdate through libssl (see keyupdate_peer.py, since
Python's ssl module cannot) and assert the server keeps working with no CPU
spin.

Note: the *deterministic* cross-direction stall/spin (an empty sendq with a
full socket, or a partial KeyUpdate arriving mid-write) sits on a razor's edge
of socket-buffer timing that is not reliably reproducible from a peer; those
remain covered by fault injection.  What is reliable, and what these tests
lock in, is that a mid-session KeyUpdate never crashes, hangs, spins, or drops
the rekeyed application stream.

OpenSSL-specific (KeyUpdate handling differs per backend); skipped otherwise.

Kernel TLS (kTLS, feature TLS_KTLS, default TRUE) changes what a
post-handshake KeyUpdate even exercises: once a session is offloaded to the
kernel, the con_tls_want_rd/wr machinery these tests target is no longer in
the data path at all, and on this host's kernel/OpenSSL combination (6.12,
3.5) the kernel cannot rekey -- OpenSSL fails with "no suitable record
layer" and sends a fatal alert, so a KeyUpdate under kTLS just gets the
connection closed rather than exercising the rekey path.  Each test here
therefore turns kTLS off (`SET TLS_KTLS FALSE`) before its peer connects
and restores it (`SET TLS_KTLS TRUE`) in a `finally:`, so the userspace
rekey path this module exists to test is what actually runs.  The kTLS-ON
behaviour -- a KeyUpdate is fatal and the server must close the connection
cleanly rather than hang, spin, or crash -- is covered separately by
tests/hotreload/test_reload_tls.py::test_tls_keyupdate_after_reload_closes_cleanly,
since it only matters once a session has survived a hot reload (the
scenario that motivated defaulting TLS_KTLS to TRUE at all).
"""

from __future__ import annotations

import asyncio
import os
import re

import pytest

from irc_client import IRCClient
from tls.bogus_peer import sample_cpu
from tls.helpers import oper_up
from tls.keyupdate_peer import KeyUpdatePeer

pytestmark = [
    pytest.mark.tls,
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.environ.get("TLS_BACKEND", "openssl") != "openssl",
        reason="KeyUpdate handling is backend-specific; test targets OpenSSL",
    ),
]

HUB_CONTAINER = "ircu-tls-hub"
CPU_SPIN_THRESHOLD = 50.0


def _register(peer: KeyUpdatePeer, nick: str, timeout: float = 15.0) -> bytes:
    """NICK/USER to 001 over the ctypes peer, answering the nospoof PING."""
    peer.write_app(f"NICK {nick}\r\nUSER {nick} 0 * :keyupdate\r\n".encode())
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


def _command_reply(peer: KeyUpdatePeer, command: bytes, needle: bytes,
                   timeout: float = 5.0) -> bool:
    """Send a command and read until `needle` (a token echoed back) appears."""
    peer.write_app(command)
    got = b""
    for _ in range(30):
        chunk = peer.read_app(timeout=timeout)
        if not chunk:
            break
        got += chunk
        for m in re.finditer(rb"PING :(\S+)", got):
            peer.write_app(b"PONG :" + m.group(1) + b"\r\n")
        if needle in got:
            return True
    return False


async def _set_tls_ktls(oper: IRCClient, enabled: bool) -> None:
    """SET TLS_KTLS TRUE|FALSE, verify it actually took effect, and give the
    daemon a moment to settle before the caller proceeds.

    Requires PRIV_SET, granted to testoper by `set = yes;` in
    tests/docker/ircd-tls-hub.conf. kTLS is enabled per-session at
    handshake time, so this must run BEFORE the affected peer connects.

    feature_set() falls through to feature_get() on success, which replies
    RPL_FEATURE (284) ":Boolean value of TLS_KTLS: TRUE|FALSE"; a missing
    PRIV_SET instead gets ERR_NOPRIVILEGES (481). Reading and checking this
    reply (rather than firing SET and blindly sleeping) is what catches a
    silently-refused toggle instead of proceeding as if kTLS were off when
    it never actually was.
    """
    expected = "TRUE" if enabled else "FALSE"
    await oper.send(f"SET TLS_KTLS {expected}")
    # Skip past anything unrelated (e.g. a still-unread "is now operator"
    # SNO_OLDSNO notice from a recent OPER) rather than trusting the very
    # next message on the stream to be the SET reply.
    deadline = asyncio.get_running_loop().time() + 10.0
    reply = None
    while asyncio.get_running_loop().time() < deadline:
        msg = await oper.recv(timeout=10.0)
        if msg.command in ("284", "481"):
            reply = msg
            break
    if reply is None:
        raise AssertionError(f"SET TLS_KTLS {expected}: no 284/481 reply seen")
    if reply.command == "481":  # ERR_NOPRIVILEGES
        raise AssertionError(
            f"SET TLS_KTLS {expected} refused with ERR_NOPRIVILEGES -- "
            f"oper lacks PRIV_SET: {reply}"
        )
    assert reply.params[-1] == f"Boolean value of TLS_KTLS: {expected}", (
        f"SET TLS_KTLS {expected} did not take effect as expected: {reply}"
    )
    await asyncio.sleep(1.0)


async def _oper_client(hub: dict, nick: str) -> IRCClient:
    c = IRCClient()
    await c.connect(hub["host"], hub["port"])
    await c.register(nick, "op", "KeyUpdate kTLS control")
    assert (await oper_up(c)).command == "381"
    return c


async def _healthy_pong(hub: dict, token: str) -> bool:
    c = IRCClient()
    await c.connect(hub["host"], hub["port"])
    await c.register("kuphealthy", "probe", "liveness")
    try:
        await c.send(f"PING :{token}")
        for _ in range(20):
            msg = await c.recv(timeout=2.0)
            if msg.command == "PONG" and token in msg.params[-1]:
                return True
        return False
    finally:
        try:
            await c.disconnect()
        except Exception:
            pass


async def test_keyupdate_midsession_survives_without_spin(ircd_tls_network):
    """A registered TLS client sends a KeyUpdate and then keeps talking: the
    server must process the rekey, answer post-KeyUpdate commands (rekeyed data
    both directions), and not spin."""
    hub = ircd_tls_network["hub"]
    oper = await _oper_client(hub, "kupdctl1")
    peer = KeyUpdatePeer(hub["host"], hub["tls_port"])

    try:
        await _set_tls_ktls(oper, False)

        def setup():
            peer.connect()
            peer.handshake()
            _register(peer, "kupdate1")
            rec = peer.key_update_record(requested=True)
            assert rec and rec[0] == 0x17, f"expected an encrypted record, got {rec[:8]!r}"
            peer.send_raw(rec)                    # KeyUpdate onto the wire, whole

        await asyncio.to_thread(setup)

        samples = await sample_cpu(HUB_CONTAINER, 3.0)
        assert await _healthy_pong(hub, "kupd-mid"), "healthy client lost service"

        # The session is rekeyed: a command sent under the new key must still be
        # processed and its reply delivered.
        ok = await asyncio.to_thread(
            _command_reply, peer, b"PING :kupdalive\r\n", b"kupdalive"
        )
        assert ok, "server stopped responding after KeyUpdate"

        assert max(samples or [0]) < CPU_SPIN_THRESHOLD, f"hub spun: {samples}"
        await asyncio.to_thread(peer.close)
    finally:
        await _set_tls_ktls(oper, True)
        try:
            await oper.disconnect()
        except Exception:
            pass


async def test_partial_keyupdate_then_complete_survives(ircd_tls_network):
    """A KeyUpdate record delivered in two socket writes (a partial post-
    handshake record parked in the server, then the remainder) must not wedge
    or spin the server, and the session must continue once completed."""
    hub = ircd_tls_network["hub"]
    oper = await _oper_client(hub, "kupdctl2")
    peer = KeyUpdatePeer(hub["host"], hub["tls_port"])
    held = {}

    try:
        await _set_tls_ktls(oper, False)

        def setup_partial():
            peer.connect()
            peer.handshake()
            _register(peer, "kupdate2")
            rec = peer.key_update_record(requested=True)
            held["rec"] = rec
            peer.send_raw(rec[:-4])               # withhold the last 4 bytes

        await asyncio.to_thread(setup_partial)

        samples = await sample_cpu(HUB_CONTAINER, 3.0)   # partial record pending
        assert await _healthy_pong(hub, "kupd-part"), "healthy client lost service"
        assert max(samples or [0]) < CPU_SPIN_THRESHOLD, f"hub spun on partial KeyUpdate: {samples}"

        def complete():
            peer.send_raw(held["rec"][-4:])       # deliver the remainder

        await asyncio.to_thread(complete)
        ok = await asyncio.to_thread(
            _command_reply, peer, b"PING :kupdpart\r\n", b"kupdpart"
        )
        assert ok, "server stopped responding after completing the KeyUpdate"
        await asyncio.to_thread(peer.close)
    finally:
        await _set_tls_ktls(oper, True)
        try:
            await oper.disconnect()
        except Exception:
            pass
