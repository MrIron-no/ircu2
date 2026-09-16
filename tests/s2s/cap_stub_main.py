"""Entry point for running the P10/P11 stub in the accepting role inside a
sidecar container (see cap_sidecar.py).

The ircd under test is told to CONNECT to this container.  Every line on
the wire and every state change is printed as one JSON object per line on
stdout so the test on the host can follow it through ``docker logs``:

  {"event": "listening", "port": N}
  {"event": "accepted", "n": k}                 k-th inbound connection
  {"event": "line", "dir": "in"|"out", "text": "..."}
  {"event": "closed"}
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys

from p11_server import P11Server


def emit(**kw) -> None:
    sys.stdout.write(json.dumps(kw) + "\n")
    sys.stdout.flush()


class ReportingStub(P11Server):
    """P11Server that reports every line it sends or receives."""

    async def _send(self, line: str):
        emit(event="line", dir="out", text=line)
        await super()._send(line)

    async def _recv_raw(self, timeout: float = 10.0) -> str:
        line = await super()._recv_raw(timeout=timeout)
        emit(event="line", dir="in", text=line)
        return line

    async def _on_accept(self, reader, writer):
        emit(event="accepted", n=self.accepted_count + 1)
        await super()._on_accept(reader, writer)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4501)
    ap.add_argument("--name", default="capstub.test.net")
    ap.add_argument("--numeric", type=int, default=6)
    ap.add_argument("--protocol", type=int, default=11)
    ap.add_argument("--caps", default="")
    ap.add_argument("--no-cap", action="store_true")
    ap.add_argument("--first-line", default=None)
    ap.add_argument("--cap-delay", type=float, default=0.0)
    ap.add_argument("--password", default="testpass")
    args = ap.parse_args()

    # Each scenario replaces the container at the same address; announce the
    # new MAC so the ircd's neighbour cache does not point at the old one.
    try:
        ip = subprocess.run(["hostname", "-i"], capture_output=True, text=True,
                            timeout=5).stdout.split()[0]
        subprocess.run(["arping", "-c", "2", "-U", "-I", "eth0", ip],
                       capture_output=True, timeout=10)
    except Exception:
        pass

    srv = ReportingStub(
        name=args.name, numeric=args.numeric, password=args.password,
        server_flags="", protocol=args.protocol, caps=args.caps,
        send_cap=not args.no_cap, first_line=args.first_line,
        cap_delay=args.cap_delay,
    )
    await srv.serve("0.0.0.0", args.port)
    emit(event="listening", port=args.port)

    await srv.connection_closed.wait()
    emit(event="closed")
    # Give a follow-up connection a moment to arrive, then exit.
    seen = srv.accepted_count
    await asyncio.sleep(5.0)
    if srv.accepted_count != seen:
        await asyncio.sleep(5.0)
    emit(event="done", accepted=srv.accepted_count)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
