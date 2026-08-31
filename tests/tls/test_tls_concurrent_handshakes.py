"""Concurrency stress: many TLS handshakes fired at once must all complete.

Hypothesis under test: when many TLS handshakes are in flight simultaneously
(e.g. a burst of clients reconnecting at the same instant a server link
handshakes), they interfere and one loses its follow-up read events, stalling
to the 5 s handshake deadline -- the "one ET_READ then silence" seen on the
FreeBSD hub.

This runs on the docker hub (epoll).  If it reproduces here, the bug is
engine-independent and fixable/testable in CI; if everything completes, the
fault is likely kqueue-specific.
"""

from __future__ import annotations

import asyncio
import ssl
import time

import pytest

from irc_client import IRCClient

pytestmark = [pytest.mark.tls, pytest.mark.asyncio]

# A completed handshake + registration is fast; anything near the 5 s handshake
# deadline means it stalled.
PER_CONN_TIMEOUT = 12.0


def _noverify_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _handshake_and_register(hub: dict, nick: str, ctx: ssl.SSLContext) -> tuple[bool, str]:
    c = IRCClient()
    start = time.monotonic()
    try:
        await asyncio.wait_for(c.connect_tls(hub["host"], hub["tls_port"], ctx),
                               timeout=PER_CONN_TIMEOUT)
        msgs = await asyncio.wait_for(c.register(nick, "conc", "concurrent"),
                                      timeout=PER_CONN_TIMEOUT)
        ok = any(m.command in ("001", "376", "422") for m in msgs)
        return ok, "ok" if ok else f"no 001 in {[m.command for m in msgs][:6]}"
    except asyncio.TimeoutError:
        return False, f"TIMEOUT/stall after {time.monotonic() - start:.1f}s"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            await c.disconnect()
        except Exception:
            pass


async def _wave(hub: dict, n: int, base: int) -> list[tuple[bool, str]]:
    ctx = _noverify_ctx()
    # gather() schedules them together, so the handshakes start as near
    # simultaneously as the event loop allows.
    return await asyncio.gather(
        *[_handshake_and_register(hub, f"c{base + i}", ctx) for i in range(n)]
    )


async def test_many_concurrent_tls_handshakes(ircd_tls_network):
    """Fire a burst of simultaneous TLS handshakes; none may stall."""
    hub = ircd_tls_network["hub"]
    n = 60
    results = await _wave(hub, n, 0)
    failures = [r for r in results if not r[0]]
    assert not failures, (
        f"{len(failures)}/{n} concurrent handshakes did not complete: "
        f"{[f[1] for f in failures][:8]}"
    )


async def test_repeated_waves_of_concurrent_handshakes(ircd_tls_network):
    """Several back-to-back bursts, to hit more timing windows."""
    hub = ircd_tls_network["hub"]
    n, waves = 40, 4
    all_failures: list[str] = []
    for w in range(waves):
        results = await _wave(hub, n, w * n)
        all_failures += [f[1] for f in results if not f[0]]
    assert not all_failures, (
        f"{len(all_failures)}/{n * waves} handshakes across {waves} waves "
        f"stalled/failed: {all_failures[:8]}"
    )
