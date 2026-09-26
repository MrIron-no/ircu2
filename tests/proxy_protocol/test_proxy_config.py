"""Config-parser rules for PROXY protocol ``Port`` blocks.

Runs the real ircd binary in config-check mode (``-k -f <file>``) inside the
already-running hub container against the working-tree hub config plus one
extra Port block, and inspects the exit code / parse-error message. No IRC
traffic is involved, but the container must be up (hence ``ircd_hub``).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.single_server

REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_CONF_HOST = REPO_ROOT / "tests" / "docker" / "ircd-hub.conf"
CONTAINER = "ircu-hub"
CONTAINER_TMP_CONF = "/tmp/proxy_protocol_check.conf"


def _check_config(text: str) -> tuple[int, str]:
    """Push ``text`` into the hub container and run ``ircd -k -f`` on it.

    Returns (exit code, combined stdout+stderr).
    """
    tmp = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
    try:
        tmp.write(text)
        tmp.close()
        os.chmod(tmp.name, 0o644)
        subprocess.run(
            ["docker", "cp", tmp.name, f"{CONTAINER}:{CONTAINER_TMP_CONF}"],
            check=True,
            capture_output=True,
        )
    finally:
        os.unlink(tmp.name)

    result = subprocess.run(
        [
            "docker", "exec", "-u", "ircu", CONTAINER,
            "timeout", "-s", "KILL", "20",
            "/opt/ircu/bin/ircd", "-k", "-f", CONTAINER_TMP_CONF,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode, (result.stdout + result.stderr)


def _base_conf() -> str:
    text = HUB_CONF_HOST.read_text()
    assert "General {" in text, "hub conf missing General block (sanity check)"
    return text


def test_cloudflare_mode_requires_websocket(ircd_hub):
    conf = _base_conf() + "\nPort { proxy = cloudflare; port = 7910; };\n"
    rc, output = _check_config(conf)
    assert rc != 0, f"expected parse failure, got rc=0: {output}"
    assert "proxy = cloudflare but is not a websocket port" in output, output


def test_proxy_rejected_on_server_port(ircd_hub):
    conf = _base_conf() + "\nPort { server = yes; proxy = yes; port = 7911; };\n"
    rc, output = _check_config(conf)
    assert rc != 0, f"expected parse failure, got rc=0: {output}"
    assert "cannot combine proxy with server = yes" in output, output


def test_proxy_rejected_on_webirc_port(ircd_hub):
    conf = _base_conf() + "\nPort { webirc = yes; proxy = yes; port = 7912; };\n"
    rc, output = _check_config(conf)
    assert rc != 0, f"expected parse failure, got rc=0: {output}"
    assert "cannot combine proxy with webirc = yes" in output, output


def test_old_cloudflare_keyword_rejected(ircd_hub):
    """The pre-refactor ``cloudflare = yes;`` port item is gone; now a syntax error."""
    conf = _base_conf() + "\nPort { cloudflare = yes; port = 7913; };\n"
    rc, output = _check_config(conf)
    assert rc != 0, f"expected parse failure, got rc=0: {output}"
    assert "syntax error" in output, output


def test_valid_combinations_accepted(ircd_hub):
    conf = (
        _base_conf()
        + "\nPort { proxy = yes; port = 7905; };"
        + "\nPort { websocket = yes; proxy = yes; port = 7906; };"
        + "\nPort { websocket = yes; proxy = cloudflare; port = 7907; };"
        + "\nPort { proxy = no; port = 7908; };\n"
    )
    rc, output = _check_config(conf)
    assert rc == 0, f"expected clean config check, got rc={rc}: {output}"
    assert "checked okay" in output, output
