"""RELOAD DUMP and the state-dump wire format itself.

`RELOAD DUMP <name>` (ircd/m_reload.c::mo_reload) calls the exact same
hotreload_dump() used internally by a real RELOAD, just aimed at a named
file instead of the anonymous tmpfile() used for the handoff -- so a dump
taken immediately before a reload and one taken immediately after should
describe the same world, modulo the fields hotreload_apply() deliberately
resets (cli_since/cli_lasttime -> CurrentTime) and the purely transient
per-connection bits (traffic counters, buffered I/O, fd numbers). The
record table itself is documented at the top of ircd/hotreload_dump.c.

CONTRACT (security hardening, merged into feat/hot-reload as of commit
f12d268 -- "merge: hot-reload security hardening (RELOAD DUMP, pre-flight-
before-shed, fd hygiene)", commits 226be92 and 5255dc5): `RELOAD DUMP
<name>` takes a plain file name only -- no '/' anywhere, so no '.' or '..'
traversal either -- and writes it inside the directory named by feature
RELOAD_DUMP_DIR (configured here as /opt/ircu/debug, the bind-mounted
debug dir; see tests/docker/ircd-tls-hub.conf). The file is opened
O_EXCL|O_NOFOLLOW,
mode 0600: it must not already exist, and being 0600 and owned by the
container's ircu user, it is not reliably host-readable, so every dump is
read back with `docker exec ... cat` rather than from the host path. DUMP
now requires PRIV_RESTART *and* PRIV_DIE (testoper, a global oper, has
both by default) -- per ircd/m_reload.c's new doc comment, a state dump
holds every local user's nick, host, address, account, oper privileges,
silence list and queued output, so the right to request one is the right
to read the whole server's state off disk.

Every DUMP attempt, success or failure, is noticed to opers up front
(`sendto_opmask_butone`, SNO_OLDSNO -- the same mask a global oper gets by
default on OPER) as `<nick> requested a state dump to <name>` and logged
to SYSTEM as `State dump to <name> requested by ...`, *before* the
attempt is even made. The outcome notice, direct to the requester, is
exactly one message: success is `NOTICE ... :State dumped to <name>`; a
name that fails the plain-file-name check ('/' anywhere, empty, '.', or
'..') gets the specific `NOTICE ... :Dump failed: file name must be a
plain file name (no '/')` -- the oper's own mistake, and one that reveals
nothing about the disk, so it is spelled out; every other failure (the
target already existing, a symlink in the way, an unwritable directory)
gets only the bare `NOTICE ... :Dump failed`, no reason at all, since
echoing one back would let a caller probe the filesystem. (An earlier
revision of this contract, seen briefly during development, sent the bare
notice before the specific one on a name-check failure; the version
tested here is the corrected one: exactly one notice, matched to the
failure.) `RELOAD_DUMP_DIR` is `FEAT_READ` -- config-only, no `SET`.

"""

from __future__ import annotations

import asyncio
import difflib
import uuid

import pytest

from debug_support import docker_exec
from hotreload.helpers import HUB, normalize_dump, wait_for_reload
from irc_client import IRCClient
from tls.helpers import oper_up

pytestmark = [pytest.mark.tls, pytest.mark.asyncio, pytest.mark.hotreload]

DUMP_DIR = "/opt/ircu/debug"


async def _disconnect_all(*clients: IRCClient) -> None:
    for c in clients:
        try:
            await c.disconnect()
        except Exception:
            pass


def _rm(name: str) -> None:
    """Remove a stale dump file (owned by the container's ircu user) so the
    next RELOAD DUMP's O_EXCL open does not fail EEXIST by accident."""
    docker_exec(HUB, "rm", "-f", f"{DUMP_DIR}/{name}", check=False)


def _cat(name: str) -> str:
    """Read a dump back as the ircu user: 0600 mode may not be host-readable."""
    return docker_exec(HUB, "cat", f"{DUMP_DIR}/{name}").stdout


def _touch(name: str) -> None:
    docker_exec(HUB, "sh", "-c", f"touch {DUMP_DIR}/{name} && chmod 600 {DUMP_DIR}/{name}")


async def _wait_for_notice_containing(
    client: IRCClient, needle: str, timeout: float = 15.0
):
    """Wait for a NOTICE whose text *contains* `needle`.

    Unlike wait_for_message_with_text() (exact match on the trailing
    param), this is for the sendto_opmask_butone() family: those notices
    arrive wrapped as "*** Notice -- <text>", so an exact match against
    the bare text would never hit.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"no NOTICE containing {needle!r}")
        msg = await client.wait_for("NOTICE", timeout=remaining)
        if needle in msg.params[-1]:
            return msg


async def _dump_to(oper: IRCClient, name: str, timeout: float = 15.0) -> None:
    """Issue RELOAD DUMP <name> and require both the up-front "requested a
    state dump" notice and the eventual success notice."""
    await oper.send(f"RELOAD DUMP {name}")
    await _wait_for_notice_containing(
        oper, f"{oper.nick} requested a state dump to {name}", timeout=timeout
    )
    msg = await oper.wait_for_message_with_text(
        "NOTICE", f"State dumped to {name}", timeout=timeout
    )
    assert msg.command == "NOTICE", msg


async def test_dump_roundtrip_is_identical(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]
    uniq = uuid.uuid4().hex[:8]
    before_name = f"before-{uniq}.txt"
    after_name = f"after-{uniq}.txt"

    oper = IRCClient()
    a = IRCClient()
    b = IRCClient()
    await oper.connect(host, port)
    await a.connect(host, port)
    await b.connect(host, port)
    try:
        await oper.register("rld1op", "op", "Dump Oper")
        assert (await oper_up(oper)).command == "381"
        await a.register("rld1a", "a", "Dump A")
        await b.register("rld1b", "b", "Dump B")

        # Channel with op/voice/ban/topic.
        await oper.send("JOIN #dumpreload")
        await oper.collect_until("366")
        await a.send("JOIN #dumpreload")
        await a.collect_until("366")
        await b.send("JOIN #dumpreload")
        await b.collect_until("366")

        # wait_for(), not a bare recv(): a and b are fellow channel members,
        # so their own broadcasts can land on oper's stream ahead of the
        # reply to oper's own command.
        await oper.send(f"MODE #dumpreload +v {a.nick}")
        await oper.wait_for("MODE", timeout=5.0)
        await oper.send("MODE #dumpreload +b *!*@dumpban.example")
        await oper.wait_for("MODE", timeout=5.0)
        await oper.send("TOPIC #dumpreload :dump topic")
        await oper.wait_for("TOPIC", timeout=5.0)

        # An invite on a second, invite-only channel.
        await b.send("JOIN #dumpinvite")
        await b.collect_until("366")
        await b.send("MODE #dumpinvite +i")
        await b.wait_for("MODE", timeout=5.0)
        await b.send(f"INVITE {a.nick} #dumpinvite")
        await b.wait_for("341", timeout=5.0)

        # Silence and away.
        silence_reply = await a.silence("*!*@dumpsilence.example")
        assert silence_reply.command == "SILENCE", silence_reply
        await a.send("AWAY :dump away")
        await a.wait_for("306", timeout=5.0)

        # A G-line.
        await oper.send("GLINE +*@9.9.9.9 3600 :dump gline test")
        await asyncio.sleep(0.5)

        _rm(before_name)
        await _dump_to(oper, before_name)

        await oper.send("RELOAD")
        await wait_for_reload(
            host, port, [(oper, "rld1-op"), (a, "rld1-a"), (b, "rld1-b")]
        )

        _rm(after_name)
        await _dump_to(oper, after_name)

        before_text = _cat(before_name)
        after_text = _cat(after_name)

        before_lines = normalize_dump(before_text)
        after_lines = normalize_dump(after_text)

        if before_lines != after_lines:
            diff = "\n".join(
                difflib.unified_diff(
                    before_lines,
                    after_lines,
                    fromfile="before (normalized, sorted)",
                    tofile="after (normalized, sorted)",
                    lineterm="",
                )
            )
            raise AssertionError(f"dump mismatch across reload:\n{diff}")
    finally:
        try:
            await oper.send("GLINE -*@9.9.9.9")
            await asyncio.sleep(0.2)
        except Exception:
            pass
        _rm(before_name)
        _rm(after_name)
        await _disconnect_all(oper, a, b)


async def test_dump_contains_every_record_type(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]
    name = f"dump-{uuid.uuid4().hex[:8]}.txt"

    oper = IRCClient()
    a = IRCClient()
    await oper.connect(host, port)
    await a.connect(host, port)
    try:
        await oper.register("rld2op", "op", "Dump Types Oper")
        assert (await oper_up(oper)).command == "381"
        await a.register("rld2a", "a", "Dump Types A")

        await oper.send("JOIN #dumptypes")
        await oper.collect_until("366")
        await oper.send("MODE #dumptypes +b *!*@dumptypesban.example")
        await oper.wait_for("MODE", timeout=5.0)

        await oper.send("JOIN #dumpinv")
        await oper.collect_until("366")
        await oper.send("MODE #dumpinv +i")
        await oper.wait_for("MODE", timeout=5.0)
        await oper.send(f"INVITE {a.nick} #dumpinv")
        await oper.wait_for("341", timeout=5.0)

        silence_reply = await a.silence("*!*@dumptypessilence.example")
        assert silence_reply.command == "SILENCE", silence_reply

        await oper.send("GLINE +*@8.8.8.8 3600 :dump record types test")
        await asyncio.sleep(0.5)

        _rm(name)
        await _dump_to(oper, name)

        text = _cat(name)
        lines = text.splitlines()

        def has(record_type: str) -> bool:
            return any(
                line == record_type or line.startswith(record_type + " ")
                for line in lines
            )

        for record_type in (
            "LISTENER",
            "CLIENT",
            "CHANNEL",
            "MEMBER",
            "BAN",
            "INVITE",
            "SILENCE",
            "GLINE",
            "STATS",
            "END",
        ):
            assert has(record_type), (
                f"no {record_type} record in dump; last 2000 chars:\n{text[-2000:]}"
            )
    finally:
        try:
            await oper.send("GLINE -*@8.8.8.8")
            await asyncio.sleep(0.2)
        except Exception:
            pass
        _rm(name)
        await _disconnect_all(oper, a)


async def _expect_exactly_one_dump_notice(
    oper: IRCClient, expected_text: str, other_text: str, timeout: float = 10.0
) -> None:
    """Require `expected_text` verbatim as the single outcome NOTICE, and
    confirm `other_text` never also arrives (the two failure shapes must
    not blend)."""
    msg = await oper.wait_for_message_with_text("NOTICE", expected_text, timeout=timeout)
    assert msg.command == "NOTICE", msg
    try:
        extra = await oper.wait_for_message_with_text(
            "NOTICE", other_text, timeout=3.0
        )
    except asyncio.TimeoutError:
        extra = None
    assert extra is None, f"unexpected second outcome notice: {extra}"


async def test_dump_rejects_bad_and_existing_names(ircd_tls_network):
    """Two rejection paths the hardened DUMP command must distinguish, each
    with exactly one outcome notice.

    A name that isn't a plain file name gets only the specific `Dump
    failed: file name must be a plain file name (no '/')` -- the oper's
    own mistake, and one that reveals nothing about the filesystem, so it
    is spelled out. A name that already exists gets only the bare `Dump
    failed`: the whole point of O_EXCL is that a caller cannot use the
    DUMP reply to probe what is on disk, so no reason is given and the
    specific wording must not appear either.
    """
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]
    name = f"exists-{uuid.uuid4().hex[:8]}.txt"
    bare_text = "Dump failed"
    specific_text = "Dump failed: file name must be a plain file name (no '/')"

    oper = IRCClient()
    await oper.connect(host, port)
    try:
        await oper.register("rld3op", "op", "Dump Reject Oper")
        assert (await oper_up(oper)).command == "381"

        # Bad name: the up-front "requested" notice still fires (the
        # request is logged/noticed regardless of outcome), then exactly
        # the specific failure notice -- never the bare one too.
        await oper.send("RELOAD DUMP ../x.txt")
        await _wait_for_notice_containing(
            oper, f"{oper.nick} requested a state dump to ../x.txt", timeout=10.0
        )
        await _expect_exactly_one_dump_notice(oper, specific_text, bare_text)

        # Existing file: up-front notice fires again, then exactly the
        # bare failure notice -- never the specific one.
        _rm(name)
        _touch(name)
        await oper.send(f"RELOAD DUMP {name}")
        await _wait_for_notice_containing(
            oper, f"{oper.nick} requested a state dump to {name}", timeout=10.0
        )
        await _expect_exactly_one_dump_notice(oper, bare_text, specific_text)
    finally:
        _rm(name)
        await _disconnect_all(oper)
