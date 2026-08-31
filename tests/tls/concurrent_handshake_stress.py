#!/usr/bin/env python3
"""Hammer an ircd TLS port with many simultaneous handshakes; report stalls.

Standalone, stdlib only -- runs anywhere python3 is (including the FreeBSD hub);
does NOT need the test venv or docker.

    python3 concurrent_handshake_stress.py <host> <port> [count] [waves]

Each worker opens a TLS connection, registers (answering the nospoof PING), and
must reach 001/376/422 quickly.  Anything that instead runs to ~the 5 s
handshake deadline is a stall -- the "one ET_READ then silence" bug.  To match
the real trigger, fire this at the hub's client TLS port at the same moment the
restarted leaf autoconnects.

Exit status: 0 if everything completed, 1 if anything stalled/failed.
"""

from __future__ import annotations

import asyncio
import ssl
import sys
import time

TIMEOUT = 12.0  # well past the 5 s handshake deadline


async def _one(host: str, port: int, ctx: ssl.SSLContext, nick: str):
    start = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout=TIMEOUT)
        writer.write(f"NICK {nick}\r\nUSER c 0 * :c\r\n".encode())
        await writer.drain()
        buf = b""
        done = (b" 001 ", b" 376 ", b" 422 ")
        while not any(d in buf for d in done):
            data = await asyncio.wait_for(reader.read(4096), timeout=TIMEOUT)
            if not data:
                break
            buf += data
            for line in buf.split(b"\r\n"):
                if line.startswith(b"PING"):
                    tok = line.split(b":", 1)[-1] if b":" in line else line.split()[-1]
                    writer.write(b"PONG :" + tok + b"\r\n")
                    await writer.drain()
        ok = any(d in buf for d in done)
        return ("ok" if ok else "no-registration", time.monotonic() - start)
    except asyncio.TimeoutError:
        return ("STALL", time.monotonic() - start)
    except Exception as exc:  # noqa: BLE001
        return (f"{type(exc).__name__}:{exc}", time.monotonic() - start)
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    waves = int(sys.argv[4]) if len(sys.argv) > 4 else 1

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    total_bad = 0
    for w in range(waves):
        results = await asyncio.gather(
            *[_one(host, port, ctx, f"cc{w}_{i}") for i in range(count)])
        bad = [r for r in results if r[0] != "ok"]
        slow = max((r[1] for r in results), default=0.0)
        total_bad += len(bad)
        print(f"wave {w}: {count - len(bad)}/{count} ok  (slowest {slow:.1f}s)",
              flush=True)
        for status, dt in bad[:8]:
            print(f"    {status}  ({dt:.1f}s)", flush=True)
    print(f"TOTAL stalled/failed: {total_bad}", flush=True)
    return 1 if total_bad else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
