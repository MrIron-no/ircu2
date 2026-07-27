"""Tests for iauth forced nickname assignment (f command).

These tests run the locally built ircd with an iauth stub that rewrites
nicknames during registration.  Rebuild with `make` if sources change.
"""

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from irc_client import IRCClient


REPO_ROOT = Path(__file__).resolve().parents[2]
IRCD_BIN = REPO_ROOT / "ircd" / "ircd"
STUB = Path(__file__).resolve().parent / "iauth_stub.py"


def _ircd_bin_is_stale() -> bool:
    if not IRCD_BIN.exists():
        return False
    built = IRCD_BIN.stat().st_mtime
    for pattern in ("ircd/*.c", "ircd/*.y", "include/*.h"):
        for src in REPO_ROOT.glob(pattern):
            if src.stat().st_mtime > built:
                return True
    return False


pytestmark = [
    pytest.mark.skipif(
        not IRCD_BIN.exists(), reason="local ircd binary not built"
    ),
    pytest.mark.skipif(
        _ircd_bin_is_stale(),
        reason="local ircd binary is older than the sources; rebuild with make",
    ),
]


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spath():
    for line in (REPO_ROOT / "config.h").read_text().splitlines():
        if line.startswith("#define SPATH "):
            return Path(line.split('"')[1])
    return None


@pytest.fixture
def ensure_spath():
    spath = _spath()
    created = False
    if spath and not spath.exists() and spath.parent.is_dir():
        spath.symlink_to(IRCD_BIN)
        created = True
    yield
    if created:
        spath.unlink(missing_ok=True)


CONF_TEMPLATE = """\
General {{
        name = "iauthnick.example.net";
        vhost = "127.0.0.1";
        description = "iauth nick test server";
        numeric = 98;
}};
Admin {{
        Location = "test";
        Location = "test";
        Contact = "test@example.net";
}};
Class {{
        name = "Local";
        pingfreq = 90 seconds;
        sendq = 160000;
        maxlinks = 100;
}};
Client {{ ip = "127.*"; class = "Local"; }};
Port {{ port = {port}; }};
IAuth {{ program = "{python}" "{stub}" "{log}"; }};
"""


@pytest.fixture
def local_ircd(tmp_path, ensure_spath):
    port = _free_port()
    log = tmp_path / "iauth.log"
    log.touch()
    conf = tmp_path / "ircd.conf"
    conf.write_text(
        CONF_TEMPLATE.format(
            port=port,
            python=sys.executable,
            stub=STUB,
            log=log,
        )
    )
    proc = subprocess.Popen(
        [str(IRCD_BIN), "-n", "-f", str(conf), "-d", str(tmp_path)],
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("ircd exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("ircd did not start listening")

        last_exc = None
        for _ in range(3):
            try:
                asyncio.run(_register(port, "probeok", "testuser"))
                break
            except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
                last_exc = exc
        else:
            raise RuntimeError(f"iauth stub never became ready: {last_exc!r}")

        yield {"port": port, "log": log}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _register(port, nick, username="testuser", timeout=15.0):
    client = IRCClient()
    await client.connect("127.0.0.1", port)
    try:
        await client.send(f"NICK {nick}")
        await client.send(f"USER {username} 0 * :Test User")
        msg = await client.wait_for("001", timeout=timeout)
        return msg
    finally:
        try:
            await client.send("QUIT :done")
        except Exception:
            pass
        await client.disconnect()


def _iauth_errors(log_path):
    errors = []
    for line in log_path.read_text().splitlines():
        parts = line.split(" ")
        if len(parts) >= 3 and parts[1] == "E":
            errors.append(parts[2])
    return errors


async def test_iauth_forced_nick_on_registration(local_ircd):
    """IAuth may replace the client's requested nick before registration."""
    msg = await _register(local_ircd["port"], "tmpuser")
    assert msg.params[0] == "finaluser"


async def test_iauth_forced_nick_explicit_prefix(local_ircd):
    """set_<nick> requests a specific assigned nickname."""
    msg = await _register(local_ircd["port"], "set_custnick")
    assert msg.params[0] == "custnick"


async def test_iauth_invalid_forced_nick_is_rejected(local_ircd):
    """An invalid forced nick must be rejected without killing the ircd."""
    msg = await _register(local_ircd["port"], "bad_-invalid")
    # Stub still sends D; client keeps its original nick.
    assert msg.params[0] == "bad_-invalid"
    await asyncio.sleep(0.3)
    assert "Invalid" in _iauth_errors(local_ircd["log"])


async def test_iauth_forced_nick_collision(local_ircd):
    """A forced nick already in use must be rejected by iauth."""
    holder = IRCClient()
    await holder.connect("127.0.0.1", local_ircd["port"])
    try:
        await holder.send("NICK set_taken")
        await holder.send("USER holder 0 * :Holder")
        msg = await holder.wait_for("001", timeout=15.0)
        assert msg.params[0] == "taken"

        msg2 = await _register(local_ircd["port"], "collide")
        assert msg2.params[0] == "collide"
        await asyncio.sleep(0.3)
        assert "InUse" in _iauth_errors(local_ircd["log"])
    finally:
        try:
            await holder.send("QUIT :done")
        except Exception:
            pass
        await holder.disconnect()
