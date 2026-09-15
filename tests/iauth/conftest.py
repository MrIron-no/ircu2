"""Fixtures for the hub-side IAuth STATS tests.

The shared hub must NOT carry a permanent IAuth block (a cloudflare websocket
test asserts this, and trust_username tests rely on it), so these tests give
the hub an IAuth stub only for their duration, then restore it -- the same
docker-cp + SIGHUP pattern the cloudflare test uses.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time

import pytest

_HUB_CONTAINER = "ircu-hub"
_HUB_CONF = "/opt/ircu/lib/ircd.conf"
_IAUTH_BLOCK = '\nIAuth { program = "/opt/ircu/bin/iauth-tilded.pl"; };\n'


def _read_hub_conf() -> str:
    return subprocess.run(
        ["docker", "exec", _HUB_CONTAINER, "cat", _HUB_CONF],
        check=True, capture_output=True, text=True).stdout


def _write_hub_conf(text: str) -> None:
    tmp = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
    try:
        tmp.write(text)
        tmp.close()
        os.chmod(tmp.name, 0o644)
        subprocess.run(
            ["docker", "cp", tmp.name, f"{_HUB_CONTAINER}:{_HUB_CONF}"],
            check=True, capture_output=True)
    finally:
        os.unlink(tmp.name)


def _sighup_hub() -> None:
    subprocess.run(
        ["docker", "exec", _HUB_CONTAINER, "sh", "-c",
         "pid=$(pidof /opt/ircu/bin/ircd 2>/dev/null || "
         "pgrep -n -f /opt/ircu/bin/ircd || true); "
         '[ -n "$pid" ] && kill -HUP "$pid"'],
        check=False, capture_output=True, text=True)
    time.sleep(0.6)


@pytest.fixture
def hub_iauth(ircd_network):
    """Temporarily attach iauth-tilded.pl to the hub (no version line, no S
    policy flag), then restore the baseline config so the hub is left clean."""
    baseline = _read_hub_conf()
    try:
        if "IAuth {" not in baseline:
            _write_hub_conf(baseline + _IAUTH_BLOCK)
            _sighup_hub()
        yield
    finally:
        _write_hub_conf(baseline)
        _sighup_hub()
