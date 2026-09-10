"""Shared helpers for the hot-reload docker integration suite (tests/hotreload/).

RELOAD replaces the running ircd binary in place: same PID, listeners and
surviving client sockets inherited across execv().  These helpers wait for
that handoff, drive the oper commands the spec requires, and read back the
state the daemon writes to disk (pid file, SYSTEM log, RELOAD DUMP files).

Every helper that reads a multi-line numeric reply (WHOIS, NAMES, MODE b,
SILENCE, CAP LIST, MODE <chan>) drains the reply fully, through its
terminating numeric.  ``IRCClient.wait_for()`` stashes any message that
doesn't match into a buffer that persists across calls -- a helper that
reads only *part* of a reply (e.g. consuming 324 but not the 329 that
always follows a channel MODE query) would leave the other half sitting in
the buffer to be silently handed back to some unrelated later ``wait_for``
in the same test.  So every helper here always reads through to the known
terminator, even when the caller only wants one piece of it.
"""

from __future__ import annotations

import asyncio
import re
import subprocess

from conftest import wait_for_port
from debug_support import docker_exec
from irc_client import IRCClient

HUB = "ircu-tls-hub"
HUB_PID_PATH = "/opt/ircu/lib/ircd-tls-hub.pid"
HUB_CONF_PATH = "/opt/ircu/lib/ircd.conf"
SYSTEM_LOG_NAME = "ircd-system.log"


# ---------------------------------------------------------------------------
# Container / process introspection
# ---------------------------------------------------------------------------


def get_hub_pid() -> str:
    """Return the ircd PID inside the hub container, from its pid file."""
    result = docker_exec(HUB, "cat", HUB_PID_PATH)
    return result.stdout.strip()


def hub_cmdline() -> str:
    """Return /proc/<pid>/cmdline for the hub's ircd, NUL-joined args kept."""
    pid = get_hub_pid()
    result = docker_exec(HUB, "cat", f"/proc/{pid}/cmdline")
    return result.stdout


def hub_running() -> bool:
    """True if `docker inspect` reports the hub container as Running."""
    result = subprocess.run(
        ["docker", "inspect", HUB, "--format", "{{.State.Running}}"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def read_system_log() -> str:
    """Return the hub's SYSTEM log.

    Read via `docker exec ... cat` rather than the host bind-mount path
    (tests/debug-output/ircd-system.log): the file is created by the
    container's ircu user and is not reliably host-readable (mode 0600 in
    practice). Empty string if the file does not exist yet -- e.g. before
    the LOG Features lines take effect, or before the first message that
    meets the configured LEVEL.
    """
    path = f"/opt/ircu/debug/{SYSTEM_LOG_NAME}"
    result = docker_exec(HUB, "cat", path, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout


async def move_conf_away() -> None:
    """Rename the hub's config so the next pre-flight fork fails to parse it.

    Always pair with restore_conf() in a finally:.
    """
    await asyncio.to_thread(
        docker_exec, HUB, "mv", HUB_CONF_PATH, HUB_CONF_PATH + ".bak"
    )


async def restore_conf() -> None:
    """Undo move_conf_away(); harmless (a no-op) if already restored."""
    await asyncio.to_thread(
        docker_exec,
        HUB,
        "sh",
        "-c",
        f"test -f {HUB_CONF_PATH}.bak && mv {HUB_CONF_PATH}.bak {HUB_CONF_PATH} || true",
    )


# ---------------------------------------------------------------------------
# Reload orchestration from the client side
# ---------------------------------------------------------------------------


async def ping_pong(client: IRCClient, token: str, timeout: float = 20.0) -> None:
    """Send a tagged PING and require the matching PONG back."""
    await client.send(f"PING :{token}")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise AssertionError(f"no PONG for {token!r} within {timeout}s")
        msg = await client.recv(timeout=remaining)
        if msg.command == "PONG" and token in msg.params[-1]:
            return
        if msg.command == "ERROR":
            raise AssertionError(f"ERROR while waiting for PONG {token!r}: {msg.raw}")


async def wait_for_reload(
    host: str,
    port: int,
    clients: list[tuple[IRCClient, str]],
    port_timeout: float = 30.0,
    pong_timeout: float = 20.0,
) -> None:
    """Wait for a RELOAD to complete: the port answers again, then every
    surviving client's tagged PING gets its PONG.

    `clients` is a list of (client, token) pairs so each probe uses its own
    cookie and a stale PONG from one client can't be mistaken for another's.
    """
    await asyncio.to_thread(wait_for_port, host, port, port_timeout)
    for client, token in clients:
        await ping_pong(client, token, timeout=pong_timeout)


async def set_tls_ktls(oper: IRCClient, enabled: bool, settle: float = 1.0) -> None:
    """SET TLS_KTLS TRUE|FALSE, and verify it actually took effect.

    Requires PRIV_SET (granted to testoper by `set = yes;` in
    tests/docker/ircd-tls-hub.conf -- global opers do not have PRIV_SET by
    default). On success feature_set() falls through to feature_get(),
    which replies RPL_FEATURE (284) ":Boolean value of TLS_KTLS: TRUE|FALSE"
    -- so this reads that reply and raises loudly instead of silently
    proceeding if PRIV_SET is somehow missing (ERR_NOPRIVILEGES, 481) or
    the value didn't end up what was asked for. A caller that only checks
    "did SET blow up" and never reads the reply cannot tell a real toggle
    from a silently-refused one, which was a real -- if fortunately
    inert -- bug in an earlier revision of this helper.

    kTLS is enabled per-session at handshake time, so callers must do this
    BEFORE the affected TLS client connects, and restore the original value
    afterwards (in a finally:) so later tests see the default (TRUE).
    """
    expected = "TRUE" if enabled else "FALSE"
    await oper.send(f"SET TLS_KTLS {expected}")
    # Skip past anything unrelated (e.g. a still-unread "is now operator"
    # SNO_OLDSNO notice from a recent OPER, which oper_up() only reads
    # through the 381/491 numeric and does not drain) rather than trusting
    # the very next message on the stream to be the SET reply.
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
            f"oper lacks PRIV_SET (check `set = yes;` on its Operator "
            f"block in tests/docker/ircd-tls-hub.conf): {reply}"
        )
    assert reply.params[-1] == f"Boolean value of TLS_KTLS: {expected}", (
        f"SET TLS_KTLS {expected} did not take effect as expected: {reply}"
    )
    await asyncio.sleep(settle)


# ---------------------------------------------------------------------------
# Draining helpers for multi-line replies (see module docstring)
# ---------------------------------------------------------------------------


async def chan_state(client: IRCClient, channel: str, timeout: float = 10.0) -> tuple[str, int]:
    """MODE <channel> (no args); return (modestring, creationtime).

    The server always answers a channel MODE query with 324 then 329
    (m_mode.c), so both are read every time this is called.
    """
    await client.send(f"MODE {channel}")
    m324 = await client.wait_for("324", timeout=timeout)
    m329 = await client.wait_for("329", timeout=timeout)
    modestring = next((p for p in m324.params if p.startswith("+")), "")
    return modestring, int(m329.params[-1])


async def umode_string(client: IRCClient, nick: str | None = None, timeout: float = 10.0) -> str:
    """MODE <nick> (no args); return the RPL_UMODEIS (221) modestring."""
    nick = nick or client.nick
    await client.send(f"MODE {nick}")
    msg = await client.wait_for("221", timeout=timeout)
    return msg.params[-1]


async def names_prefixes(client: IRCClient, channel: str, timeout: float = 10.0) -> dict[str, str]:
    """NAMES <channel>; return {nick: prefix} ('' when no prefix), draining
    every 353 through the terminating 366."""
    await client.send(f"NAMES {channel}")
    prefixes: dict[str, str] = {}
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"NAMES {channel} never reached 366")
        msg = await client.recv(timeout=remaining)
        if msg.command == "353":
            for tok in msg.params[-1].split():
                nick = tok.lstrip("@+%&~")
                prefixes[nick] = tok[: len(tok) - len(nick)]
        elif msg.command == "366":
            return prefixes


async def ban_list(client: IRCClient, channel: str, timeout: float = 10.0) -> list[str]:
    """MODE <channel> b; return the ban masks, draining 367 through 368."""
    await client.send(f"MODE {channel} b")
    masks: list[str] = []
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"MODE {channel} b never reached 368")
        msg = await client.recv(timeout=remaining)
        if msg.command == "367":
            masks.append(msg.params[1])
        elif msg.command == "368":
            return masks


async def silence_lines(client: IRCClient, timeout: float = 10.0) -> list[str]:
    """SILENCE with no args; return the raw text of every 271 line, draining
    through the terminating 272."""
    await client.send("SILENCE")
    out: list[str] = []
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError("SILENCE never reached 272")
        msg = await client.recv(timeout=remaining)
        if msg.command == "271":
            out.append(msg.raw)
        elif msg.command == "272":
            return out


async def cap_list(client: IRCClient, timeout: float = 10.0) -> list[str]:
    """CAP LIST; return the currently-set capability names."""
    await client.send("CAP LIST")
    deadline = asyncio.get_running_loop().time() + timeout
    caps: list[str] = []
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError("no CAP ... LIST reply")
        msg = await client.recv(timeout=remaining)
        if msg.command == "CAP" and len(msg.params) >= 3 and msg.params[1] == "LIST":
            caps.extend(msg.params[-1].split())
            if msg.params[2] != "*":
                return caps


async def whois_numerics(
    client: IRCClient, nick: str, wanted: set[str], timeout: float = 10.0
) -> dict[str, str]:
    """WHOIS <nick>; collect the trailing text of every numeric in `wanted`,
    draining fully through RPL_ENDOFWHOIS (318)."""
    await client.send(f"WHOIS {nick}")
    found: dict[str, str] = {}
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"WHOIS {nick} never reached 318")
        msg = await client.recv(timeout=remaining)
        if msg.command in wanted:
            found[msg.command] = msg.params[-1]
        if msg.command == "318":
            return found


# ---------------------------------------------------------------------------
# RELOAD DUMP comparison
# ---------------------------------------------------------------------------

# Keys whose value is expected to change across a reload (or is simply not
# meaningful to compare): timestamps hotreload_apply() resets to
# CurrentTime, per-connection traffic counters, and fd numbers (preserved
# by exec in practice, but the spec explicitly says not to rely on that).
_VOLATILE_KEY_RE = re.compile(
    r"(?:^|(?<= ))(since|lasttime|sendM|receiveM|sendB|receiveB|keepalive|fd)=\S+ ?"
)

# Record types dropped wholesale: HOTRELOAD carries the dump's own pid/time
# header, STATS carries live counters, and SENDQ/RECVQ/LINEBUF are
# transient per-connection buffers.
_DROPPED_RECORD_TYPES = ("HOTRELOAD", "STATS", "SENDQ", "RECVQ", "LINEBUF")


def normalize_dump(text: str) -> list[str]:
    """Sorted dump lines with volatile fields and transient record types
    stripped, per the comparison rules in the hot-reload spec's dump test.
    """
    lines = []
    for raw in text.splitlines():
        if not raw:
            continue
        record_type = raw.split(" ", 1)[0]
        if record_type in _DROPPED_RECORD_TYPES:
            continue
        cleaned = _VOLATILE_KEY_RE.sub("", raw).rstrip()
        lines.append(cleaned)
    return sorted(lines)
