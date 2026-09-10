"""RELOAD: plaintext connection survival, server relinking, and everything a
reload is supposed to preserve or shed.

RELOAD execv()s the ircd binary in place: same PID, the listening and
client sockets inherited by fd number, state rebuilt from a text dump.  The
spec's contract (specs/2026-09-10-hot-reload.md, "Objective") is that every
registered plaintext client keeps its nick, modes, channels, ops/voices,
bans, topics, caps, invites, silence list and oper status; server links
relink and re-burst with the channel timestamps preserved so no net-ride
happens; server links, unregistered connections and in-progress LIST
cursors do not survive; and a failed pre-flight leaves the old process
serving with no visible disruption at all.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from conftest import wait_for_port
from hotreload.helpers import (
    HUB,
    HUB_PID_PATH,
    ban_list,
    cap_list,
    chan_state,
    get_hub_pid,
    hub_cmdline,
    hub_running,
    move_conf_away,
    names_prefixes,
    ping_pong,
    read_system_log,
    restore_conf,
    set_tls_ktls,
    silence_lines,
    umode_string,
    wait_for_reload,
    whois_numerics,
)
from irc_client import IRCClient
from tls.helpers import connect_link, links_contains, oper_up, wait_for_server_link
from debug_support import docker_exec

pytestmark = [pytest.mark.tls, pytest.mark.asyncio, pytest.mark.hotreload]

LEAF_NAME = "tls-leaf.test.net"
LEAF_SERVER_PORT = 4401


async def _disconnect_all(*clients: IRCClient) -> None:
    for c in clients:
        try:
            await c.disconnect()
        except Exception:
            pass


async def test_plaintext_clients_survive(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    voiced = IRCClient()
    plain = IRCClient()
    await oper.connect(host, port)
    await voiced.connect(host, port)
    await plain.connect(host, port)
    try:
        await oper.register("rl1op", "op", "Reload Oper")
        await voiced.register("rl1voice", "v", "Reload Voice")
        await plain.register("rl1plain", "p", "Reload Plain")
        assert (await oper_up(oper)).command == "381"

        # oper is the first joiner -> auto-opped.
        await oper.send("JOIN #reload")
        await oper.collect_until("366")
        await voiced.send("JOIN #reload")
        await voiced.collect_until("366")
        await plain.send("JOIN #reload")
        await plain.collect_until("366")

        # wait_for(), not a bare recv(): voiced and plain are fellow channel
        # members, so their own JOIN (and later, other) broadcasts can land
        # on oper's stream ahead of the reply to oper's own command.
        await oper.send(f"MODE #reload +v {voiced.nick}")
        await oper.wait_for("MODE", timeout=5.0)

        await oper.send("MODE #reload +b *!*@banned.example")
        await oper.wait_for("MODE", timeout=5.0)

        await oper.send("TOPIC #reload :reload topic")
        await oper.wait_for("TOPIC", timeout=5.0)

        pre_umodes = {c.nick: await umode_string(c) for c in (oper, voiced, plain)}
        pre_names = await names_prefixes(oper, "#reload")
        pre_modestring, _ = await chan_state(oper, "#reload")
        assert pre_names.get(oper.nick) == "@", pre_names
        assert pre_names.get(voiced.nick) == "+", pre_names

        await oper.send("RELOAD")
        await wait_for_reload(
            host,
            port,
            [(oper, "rl1-op"), (voiced, "rl1-voice"), (plain, "rl1-plain")],
        )

        post_names = await names_prefixes(plain, "#reload")
        assert post_names.get(oper.nick) == pre_names.get(oper.nick), (
            pre_names,
            post_names,
        )
        assert post_names.get(voiced.nick) == pre_names.get(voiced.nick), (
            pre_names,
            post_names,
        )

        bans = await ban_list(plain, "#reload")
        assert "*!*@banned.example" in bans, bans

        await plain.send("TOPIC #reload")
        topic_msg = await plain.wait_for("332", timeout=10.0)
        assert topic_msg.params[-1] == "reload topic", topic_msg

        whois = await whois_numerics(plain, oper.nick, {"313"})
        assert "313" in whois, whois

        for c in (oper, voiced, plain):
            post_umode = await umode_string(c)
            assert post_umode == pre_umodes[c.nick], (
                c.nick,
                pre_umodes[c.nick],
                post_umode,
            )

        post_modestring, _ = await chan_state(plain, "#reload")
        assert post_modestring == pre_modestring, (pre_modestring, post_modestring)
    finally:
        await _disconnect_all(oper, voiced, plain)


async def test_message_during_handoff_delivered(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    a = IRCClient()
    b = IRCClient()
    await oper.connect(host, port)
    await a.connect(host, port)
    await b.connect(host, port)
    try:
        await oper.register("rl2op", "op", "Reload Oper")
        assert (await oper_up(oper)).command == "381"
        await a.register("rl2a", "a", "Handoff A")
        await b.register("rl2b", "b", "Handoff B")

        # Fire RELOAD and, without waiting for anything, immediately race a
        # PRIVMSG onto the wire: the bytes must sit in the kernel socket
        # buffer across the exec and be processed once the new image reads
        # them, per the spec's "bytes that arrive during the handoff wait
        # in the kernel socket buffers" guarantee.
        await oper.send("RELOAD")
        await a.send(f"PRIVMSG {b.nick} :during-handoff")

        await wait_for_reload(host, port, [(oper, "rl2-op")])

        msg = await b.wait_for_user_msg("PRIVMSG", timeout=20.0)
        assert msg.params[-1] == "during-handoff", msg
    finally:
        await _disconnect_all(oper, a, b)


async def test_issuer_throttled_pipelined_command_survives(ircd_tls_network):
    """A command pipelined directly behind RELOAD in the same recvQ buffer
    must still be delivered once the new image comes up, even when the
    issuer was over its read throttle at the moment RELOAD was dispatched.

    read_packet()'s drain loop (ircd/s_bsd.c) pops one line at a time from
    recvQ with dbuf_getmsg() and dispatches it; RELOAD's dispatch calls
    server_reload(), which execs and never returns to that loop, so
    whatever is still sitting behind it in the same recvQ buffer is left
    exactly as the dump captures it -- a RECVQ record (see the table atop
    ircd/hotreload_dump.c). Flooding the issuer past the read throttle
    first (`cli_since(cptr) - CurrentTime < 10`, FEAT_CLIENT_FLOOD) makes
    this deterministic instead of a TCP-segment-boundary race: once
    throttled, read_packet() defers *all* further draining to its own
    per-connection timer (cli_proc) regardless of how the bytes arrive, so
    RELOAD and the pipelined PING are guaranteed to still be sitting
    together, undrained, when RELOAD is finally dispatched. The new image
    must re-arm that timer on adoption (schedule_recvq_process(), called
    from hotreload_load.c for every adopted client with a non-empty
    recvQ) or the pipelined PING is never reprocessed: a level-triggered
    engine has nothing to notify it about on a socket with no new bytes.
    """
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    await oper.connect(host, port)
    try:
        await oper.register("rl12op", "op", "Throttled Reload Issuer")
        assert (await oper_up(oper)).command == "381"

        # Push cli_since just past the 10s throttle guard -- read_packet()
        # adds ~2s of penalty per short command processed, so 10 lines are
        # comfortably enough to trip it (5 process before the guard stops
        # the drain) with only a small backlog left to work off afterward,
        # keeping the test fast: draining leftover flood + RELOAD + the
        # pipelined PING happens at roughly one command per ~2 real
        # seconds once throttled, so a much larger burst would just make
        # this test slow without testing anything more. Comfortably under
        # the 1024-byte default FEAT_CLIENT_FLOOD recvQ-flood disconnect
        # limit too (~110 bytes total). Written and drained as one blob,
        # not via IRCClient.send()'s one-write-per-call, so nothing is
        # awaited between lines.
        flood = "".join(f"PING :flood{i}\r\n" for i in range(10)).encode()
        oper._writer.write(flood)
        await oper._writer.drain()

        unique = f"carried-{uuid.uuid4().hex[:8]}"
        # RELOAD and the PING behind it MUST be in the same write, sent
        # back-to-back with nothing awaited in between: that is what
        # guarantees they are still sitting together, undrained, in the
        # issuer's recvQ at the moment RELOAD's dispatch execs the new
        # image, exercising the exact carried-recvQ path the fix covers.
        oper._writer.write(f"RELOAD\r\nPING :{unique}\r\n".encode())
        await oper._writer.drain()

        await asyncio.to_thread(wait_for_port, host, port, 30.0)

        found = None
        deadline = asyncio.get_running_loop().time() + 45.0
        while asyncio.get_running_loop().time() < deadline:
            remaining = deadline - asyncio.get_running_loop().time()
            msg = await oper.recv(timeout=max(0.1, remaining))
            if msg.command == "PONG" and unique in msg.params[-1]:
                found = msg
                break
        assert found is not None, (
            f"pipelined PING {unique!r} (sent behind a throttled RELOAD in "
            f"the same write) never got a PONG after the reload -- the "
            f"issuer's carried recvQ was not reprocessed"
        )
    finally:
        await _disconnect_all(oper)


async def test_server_link_relinks_with_timestamps(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    leaf = ircd_tls_network["leaf"]

    hub_op = IRCClient()
    leaf_client = IRCClient()
    hub_client = IRCClient()
    await hub_op.connect(hub["host"], hub["port"])
    await leaf_client.connect(leaf["host"], leaf["port"])
    await hub_client.connect(hub["host"], hub["port"])
    try:
        await hub_op.register("rl3hubop", "op", "Relink Oper")
        assert (await oper_up(hub_op)).command == "381"
        await leaf_client.register("rl3leaf", "l", "Relink Leaf")
        # The relink is verified below by querying the leaf's LINKS. LINKS is
        # hidden from non-opers by default (FEAT_HIS_LINKS, ircd/m_links.c),
        # so a plain client sees only RPL_ENDOFLINKS with no server lines and
        # could never observe the hub -- oper up here so the leaf side is
        # checked with the same privilege the hub side uses (hub_op).
        assert (await oper_up(leaf_client)).command == "381"
        await hub_client.register("rl3hub", "h", "Relink Hub")

        await connect_link(hub_op, LEAF_NAME, LEAF_SERVER_PORT)

        await hub_client.send("JOIN #reload")
        await hub_client.collect_until("366")

        # Let the join burst reach the leaf, then record the creation
        # timestamp from the leaf's own view of the channel.
        await asyncio.sleep(1.0)
        _, pre_ts = await chan_state(leaf_client, "#reload")
        pre_names = await names_prefixes(hub_client, "#reload")
        assert pre_names.get(hub_client.nick) == "@", pre_names

        await hub_op.send("RELOAD")
        await wait_for_reload(hub["host"], hub["port"], [(hub_op, "rl3-op")])

        # autoconnect is off both ways in the test configs (see
        # tests/docker/ircd-tls-hub.conf), so the squit from RELOAD's shedding
        # walk must be relinked explicitly.
        await connect_link(hub_op, LEAF_NAME, LEAF_SERVER_PORT)
        await wait_for_server_link(leaf_client, "tls-hub.test.net")

        leaf_joiner = IRCClient()
        await leaf_joiner.connect(leaf["host"], leaf["port"])
        try:
            await leaf_joiner.register("rl3leafjoin", "lj", "Relink Leaf Joiner")
            await leaf_joiner.send("JOIN #reload")
            await leaf_joiner.collect_until("366")

            _, post_ts = await chan_state(leaf_client, "#reload")
            assert post_ts == pre_ts, (pre_ts, post_ts)

            post_names = await names_prefixes(leaf_joiner, "#reload")
            assert post_names.get(hub_client.nick) == "@", post_names
        finally:
            await leaf_joiner.disconnect()
    finally:
        await _disconnect_all(hub_op, leaf_client, hub_client)


async def test_unregistered_connection_gets_error(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    await oper.connect(host, port)

    reader, writer = await asyncio.open_connection(host, port)
    try:
        await oper.register("rl4op", "op", "Unregistered Oper")
        assert (await oper_up(oper)).command == "381"

        writer.write(b"NICK pending\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)  # let the NICK reach the server first

        await oper.send("RELOAD")

        # An unregistered connection is still subject to the ordinary ping
        # timer, so a keepalive PING can legitimately arrive before the
        # ERROR the reload's shedding walk sends; skip over it (and answer
        # it, in case the server is waiting on it for anything) rather than
        # asserting on the very next line.
        deadline = asyncio.get_running_loop().time() + 20.0
        text = ""
        while asyncio.get_running_loop().time() < deadline:
            remaining = deadline - asyncio.get_running_loop().time()
            line = await asyncio.wait_for(reader.readline(), timeout=max(0.1, remaining))
            text = line.decode("utf-8", errors="replace").strip()
            if text.startswith("PING"):
                cookie = text.split(":", 1)[-1] if ":" in text else text.split(" ", 1)[-1]
                writer.write(f"PONG :{cookie}\r\n".encode())
                await writer.drain()
                continue
            break
        assert text.startswith("ERROR :Closing Link"), text
        assert "Server reloading" in text, text

        # And then EOF: the connection was closed, not left half-open.
        tail = await asyncio.wait_for(reader.readline(), timeout=10.0)
        assert tail == b"", tail

        await wait_for_reload(host, port, [(oper, "rl4-op")])
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await _disconnect_all(oper)


async def test_caps_and_away_survive(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    victim = IRCClient()
    await oper.connect(host, port)
    await victim.connect(host, port)
    try:
        await oper.register("rl5op", "op", "Caps Away Oper")
        assert (await oper_up(oper)).command == "381"

        acked = await victim.negotiate_cap(["multi-prefix"])
        if "multi-prefix" not in acked:
            pytest.skip("multi-prefix not supported on this build")
        await victim.register("rl5victim", "v", "Caps Away Victim")
        await victim.send("AWAY :brb")
        await victim.wait_for("306", timeout=5.0)  # RPL_NOWAWAY

        await oper.send("RELOAD")
        await wait_for_reload(host, port, [(oper, "rl5-op"), (victim, "rl5-victim")])

        caps = await cap_list(victim)
        assert "multi-prefix" in caps, caps

        whois = await whois_numerics(oper, victim.nick, {"301"})
        assert whois.get("301") == "brb", whois
    finally:
        await _disconnect_all(oper, victim)


async def test_silence_and_invite_survive(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    a = IRCClient()
    b = IRCClient()
    oper = IRCClient()
    await a.connect(host, port)
    await b.connect(host, port)
    await oper.connect(host, port)
    try:
        await oper.register("rl6op", "op", "Silence Invite Oper")
        assert (await oper_up(oper)).command == "381"
        await a.register("rl6a", "a", "Silence Invite A")
        await b.register("rl6b", "b", "Silence Invite B")

        silence_reply = await a.silence("*!*@silenced.example")
        assert silence_reply.command == "SILENCE", silence_reply

        await b.send("JOIN #inv")
        await b.collect_until("366")
        await b.send("MODE #inv +i")
        await b.wait_for("MODE", timeout=5.0)

        await b.send(f"INVITE {a.nick} #inv")
        await b.wait_for("341", timeout=5.0)  # RPL_INVITING

        await oper.send("RELOAD")
        await wait_for_reload(
            host, port, [(oper, "rl6-op"), (a, "rl6-a"), (b, "rl6-b")]
        )

        lines = await silence_lines(a)
        assert any("silenced.example" in line for line in lines), lines

        await a.send("JOIN #inv")
        deadline = asyncio.get_running_loop().time() + 10.0
        outcome = None
        while asyncio.get_running_loop().time() < deadline:
            msg = await a.recv(timeout=5.0)
            if msg.command in ("366", "473"):
                outcome = msg.command
                break
        assert outcome == "366", f"JOIN #inv after reload got {outcome!r}"
    finally:
        await _disconnect_all(a, b, oper)


async def test_sigusr2_triggers_reload(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    survivor = IRCClient()
    await survivor.connect(host, port)
    try:
        await survivor.register("rl7usr2", "u", "SIGUSR2 survivor")
        pid_before = get_hub_pid()

        await asyncio.to_thread(
            docker_exec, HUB, "sh", "-c", f"kill -USR2 $(cat {HUB_PID_PATH})"
        )

        await wait_for_reload(host, port, [(survivor, "rl7-usr2")])

        pid_after = get_hub_pid()
        assert pid_after == pid_before, (pid_before, pid_after)
        assert hub_running()

        log = read_system_log()
        assert "caught signal: SIGUSR2" in log, log[-4000:]
    finally:
        await _disconnect_all(survivor)


async def test_reload_twice(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    survivor = IRCClient()
    await oper.connect(host, port)
    await survivor.connect(host, port)
    try:
        await oper.register("rl8op", "op", "Reload Twice Oper")
        assert (await oper_up(oper)).command == "381"
        await survivor.register("rl8surv", "s", "Reload Twice Survivor")

        for i in range(2):
            await oper.send("RELOAD")
            await wait_for_reload(
                host, port, [(oper, f"rl8-op-{i}"), (survivor, f"rl8-surv-{i}")]
            )

        args = hub_cmdline().split("\x00")
        assert args.count("-R") == 1, args
        assert "-K" not in args, args
    finally:
        await _disconnect_all(oper, survivor)


async def test_gline_survives(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    await oper.connect(host, port)
    try:
        await oper.register("rl9op", "op", "Gline Oper")
        assert (await oper_up(oper)).command == "381"

        # Local G-line: no <target>, mask prefixed with '+', expiration and
        # reason required (doc/readme.gline, "Local G-lines"); testoper has
        # PRIV_LOCAL_GLINE via the global-oper defaults in client_set_privs().
        await oper.send("GLINE +*@1.2.3.4 3600 :hotreload gline test")
        await asyncio.sleep(0.5)

        await oper.send("RELOAD")
        await wait_for_reload(host, port, [(oper, "rl9-op")])

        await oper.send("STATS G")
        found = False
        deadline = asyncio.get_running_loop().time() + 10.0
        while asyncio.get_running_loop().time() < deadline:
            msg = await oper.recv(timeout=5.0)
            if msg.command == "247" and "1.2.3.4" in msg.raw:
                found = True
            if msg.command == "219":
                break
        assert found, "G-line for 1.2.3.4 missing from STATS G after reload"
    finally:
        try:
            await oper.send("GLINE -*@1.2.3.4")
            await asyncio.sleep(0.2)
        except Exception:
            pass
        await _disconnect_all(oper)


async def test_preflight_failure_keeps_old_process(ircd_tls_network):
    hub = ircd_tls_network["hub"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    survivor = IRCClient()
    await oper.connect(host, port)
    await survivor.connect(host, port)
    moved = False
    try:
        await oper.register("rl10op", "op", "Preflight Oper")
        assert (await oper_up(oper)).command == "381"
        await survivor.register("rl10surv", "s", "Preflight Survivor")

        pid_before = get_hub_pid()

        await move_conf_away()
        moved = True

        await oper.send("RELOAD")

        found = None
        deadline = asyncio.get_running_loop().time() + 20.0
        while asyncio.get_running_loop().time() < deadline:
            msg = await oper.recv(timeout=5.0)
            if msg.command == "NOTICE" and (
                "Reload aborted: pre-flight check failed" in msg.params[-1]
            ):
                found = msg
                break
        assert found is not None, "no pre-flight-abort NOTICE observed"

        await restore_conf()
        moved = False

        pid_after = get_hub_pid()
        assert pid_after == pid_before, (pid_before, pid_after)
        assert hub_running()

        await ping_pong(oper, "rl10-op-still-alive")
        await ping_pong(survivor, "rl10-surv-still-alive")

        # The re-entrancy guard must have cleared: a subsequent RELOAD
        # (config restored) must succeed.
        await oper.send("RELOAD")
        await wait_for_reload(
            host, port, [(oper, "rl10-op-recovered"), (survivor, "rl10-surv-recovered")]
        )
    finally:
        if moved:
            await restore_conf()
        await _disconnect_all(oper, survivor)


async def test_preflight_failure_disconnects_nothing(ircd_tls_network):
    """A failed pre-flight must be invisible to everything but the oper who
    asked for it: no server link squit, no TLS session shed for not being
    kTLS-offloaded. Complements test_preflight_failure_keeps_old_process
    (which only checks plaintext clients, both before and after this
    hardening) with the two kinds of connection a pre-flight failure used
    to take down anyway under the old (shed-first) ordering.
    """
    hub = ircd_tls_network["hub"]
    leaf = ircd_tls_network["leaf"]
    host, port = hub["host"], hub["port"]

    oper = IRCClient()
    tls_client = IRCClient()
    await oper.connect(host, port)
    moved = False
    try:
        await oper.register("rl11op", "op", "Preflight Nothing Oper")
        assert (await oper_up(oper)).command == "381"

        await connect_link(oper, LEAF_NAME, LEAF_SERVER_PORT)

        await set_tls_ktls(oper, False)
        await tls_client.connect_tls(host, hub["tls_port"])
        await tls_client.register("rl11tls", "t", "Preflight Nothing TLS")

        pid_before = get_hub_pid()

        await move_conf_away()
        moved = True

        await oper.send("RELOAD")

        found = None
        deadline = asyncio.get_running_loop().time() + 20.0
        while asyncio.get_running_loop().time() < deadline:
            msg = await oper.recv(timeout=5.0)
            if msg.command == "NOTICE" and (
                "Reload aborted: pre-flight check failed" in msg.params[-1]
            ):
                found = msg
                break
        assert found is not None, "no pre-flight-abort NOTICE observed"

        await restore_conf()
        moved = False

        assert hub_running()
        assert get_hub_pid() == pid_before

        # Neither connection was touched by the failed reload.
        assert await links_contains(oper, LEAF_NAME), "leaf link dropped by a failed pre-flight"
        await ping_pong(tls_client, "rl11-tls-still-alive")
        await ping_pong(oper, "rl11-op-still-alive")
    finally:
        if moved:
            await restore_conf()
        await set_tls_ktls(oper, True)
        await _disconnect_all(oper)
        try:
            await tls_client.disconnect()
        except Exception:
            pass
