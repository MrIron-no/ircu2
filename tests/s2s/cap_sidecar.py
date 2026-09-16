"""Run the P10/P11 stub in the accepting role in a container on the test
network, so the ircd under test can CONNECT to it.

Copied from the tls/bogus_peer.py sidecar pattern: the host firewall may
drop container->host traffic, so the listener runs where the hub can reach
it, and events are read back from the container's stdout as JSON lines
(see cap_stub_main.py).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess

SIDECAR_IMAGE = "python:3-alpine"
SIDECAR_NAME = "ircu-cap-stub"
SIDECAR_IP = "10.55.0.41"          # Connect { name = "capstub.test.net" } in ircd-hub.conf
SIDECAR_PORT = 4501
SIDECAR_SERVER_NAME = "capstub.test.net"
TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _test_network() -> str:
    out = subprocess.run(
        ["docker", "network", "ls", "--filter", "name=ircu-test-net", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=30,
    ).stdout.split()
    if not out:
        raise RuntimeError("test network ircu-test-net not found; is the hub topology up?")
    return out[0]


class SidecarCapStub:
    """cap_stub_main.py running in a container the hub can connect to."""

    def __init__(self, *, protocol: int = 11, caps: str = "", send_cap: bool = True,
                 first_line: str | None = None, cap_delay: float = 0.0):
        self.protocol = protocol
        self.caps = caps
        self.send_cap = send_cap
        self.first_line = first_line
        self.cap_delay = cap_delay
        self.port = SIDECAR_PORT
        self.ip = SIDECAR_IP
        self.name = SIDECAR_SERVER_NAME
        self.events: list[dict] = []
        self._started = False

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._start_blocking)
        self._started = True
        await self.wait_event("listening", 30.0)
        return self.port

    def _start_blocking(self) -> None:
        subprocess.run(["docker", "rm", "-f", SIDECAR_NAME], capture_output=True, timeout=30)
        cmd = [
            "docker", "run", "-d", "--name", SIDECAR_NAME,
            "--network", _test_network(), "--ip", self.ip,
            "-v", f"{TESTS_DIR}:/tests:ro", "-e", "PYTHONPATH=/tests", "-w", "/tests",
            SIDECAR_IMAGE, "python", "-u", "s2s/cap_stub_main.py",
            "--port", str(self.port), "--name", self.name,
            "--protocol", str(self.protocol), "--caps", self.caps,
            "--cap-delay", str(self.cap_delay),
        ]
        if not self.send_cap:
            cmd.append("--no-cap")
        if self.first_line is not None:
            cmd += ["--first-line", self.first_line]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            raise RuntimeError(f"sidecar start failed: {r.stderr.strip()}")

    def _poll_events(self) -> list[dict]:
        r = subprocess.run(["docker", "logs", SIDECAR_NAME], capture_output=True, text=True, timeout=30)
        events = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
        return events

    async def refresh(self) -> list[dict]:
        loop = asyncio.get_running_loop()
        self.events = await loop.run_in_executor(None, self._poll_events)
        return self.events

    async def wait_event(self, name: str, timeout: float, **match) -> dict:
        """Wait for an event named ``name`` whose fields include ``match``."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            await self.refresh()
            for ev in self.events:
                if ev.get("event") == name and all(ev.get(k) == v for k, v in match.items()):
                    return ev
            if loop.time() > deadline:
                raise asyncio.TimeoutError(f"sidecar: no {name!r} event; got {self.events[-8:]}")
            await asyncio.sleep(0.3)

    async def wait_line(self, direction: str, prefix: str, timeout: float) -> dict:
        """Wait for a wire line in ``direction`` ("in" from the ircd, "out" to it)
        starting with ``prefix``."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            await self.refresh()
            for ev in self.events:
                if (ev.get("event") == "line" and ev.get("dir") == direction
                        and ev.get("text", "").startswith(prefix)):
                    return ev
            if loop.time() > deadline:
                raise asyncio.TimeoutError(
                    f"sidecar: no {direction!r} line starting {prefix!r}; got {self.lines}")
            await asyncio.sleep(0.3)

    async def wait_line_containing(self, direction: str, needle: str, timeout: float) -> dict:
        """Wait for a wire line in ``direction`` that contains ``needle``."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            await self.refresh()
            for ev in self.events:
                if (ev.get("event") == "line" and ev.get("dir") == direction
                        and needle in ev.get("text", "")):
                    return ev
            if loop.time() > deadline:
                raise asyncio.TimeoutError(
                    f"sidecar: no {direction!r} line containing {needle!r}; got {self.lines}")
            await asyncio.sleep(0.3)

    @property
    def lines(self) -> list[tuple[str, str]]:
        """Every wire line as (dir, text), in the order it happened."""
        return [(ev["dir"], ev["text"]) for ev in self.events if ev.get("event") == "line"]

    @property
    def lines_in(self) -> list[str]:
        return [t for d, t in self.lines if d == "in"]

    @property
    def lines_out(self) -> list[str]:
        return [t for d, t in self.lines if d == "out"]

    @property
    def accepted(self) -> int:
        return sum(1 for ev in self.events if ev.get("event") == "accepted")

    async def stop(self) -> None:
        if not self._started:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(["docker", "rm", "-f", SIDECAR_NAME], capture_output=True, timeout=30),
        )
        self._started = False
