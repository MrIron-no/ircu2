"""Labeled-response for queries about *remote* users, one and two hops away.

Two genuinely different code paths answer "a query about someone not on
this server", and they behave very differently under labeled-response:

1. Plain `WHOIS nick` is answered entirely from this server's own,
   already-synced network state (ircd/m_whois.c: do_whois() only
   special-cases MyConnect(acptr) to decide whether to include
   RPL_WHOISIDLE/RPL_WHOISWEBIRC -- everything else is the same code path
   whether the target is local or N hops away). No S2S round trip
   happens at all. So a labeled plain WHOIS for a remote user is captured
   and batched exactly like a local one; test_remote_whois_one_hop_is_
   fully_batched and test_remote_whois_two_hops_is_fully_batched confirm
   that empirically (the latter via a server introduced *behind* the
   first hop, so the target is genuinely two hops from the querying
   client's server).

2. `WHOIS nick nick` (the classic "whois trick": a second parameter
   forces hunt_server_cmd() to route the query to the *target's own*
   home server) and `STATS <letter> <server>` are different: when the
   named target isn't this server, hunt_server_cmd() forwards the
   command on and returns immediately with *zero* local output. The real
   reply is generated later, asynchronously, by the remote server itself,
   and arrives back over the S2S link with no knowledge of -- and no way
   to carry -- the original request's label= tag (labels are an IRCv3
   client-facing concept parse.c consumes locally; hunt_server_cmd()'s
   S2S forwarding format has no tag slot for it at all). parse.c's
   labeled-response wrapper has no way to know the command it just ran
   is still "in flight" elsewhere (that's the "once S2S support lands"
   future work called out in include/client.h's LabelCapture comment),
   so it finishes the capture immediately -- with zero lines captured,
   that means a bare ACK, sent *before* the real reply exists.

   test_remote_queries_s2s_roundtrip.py (multi_server: real hub + leaf)
   documents this empirically for both commands, using a real linked
   leaf so the reply is a genuine, unscripted S2S round trip rather than
   a fake server that has to be told what to say back. It is a known
   gap, not a regression this change introduces or claims to fix.
"""

from __future__ import annotations

import pytest

from cap_helpers import make_cap_client
from irc_client import IRCClient

from .helpers import LABELED_CAPS, tag_value

pytestmark = pytest.mark.single_server


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def test_remote_whois_one_hop_is_fully_batched(ircd_hub, ulined_server):
    """WHOIS for a user homed directly on a linked (fake) server: one hop
    away from the querying client's server. Must batch correctly, same
    shape as a local multiline reply.
    """
    numnick = await ulined_server.introduce_user("RemoteOne", host="one-hop.test")

    client = await make_cap_client(ircd_hub["host"], ircd_hub["port"], "lblrwho1", caps=LABELED_CAPS)
    try:
        await client.send("@label=rwho1 WHOIS RemoteOne")

        opening = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening.tags, "label") == "rwho1", opening.raw
        assert opening.params[1] == "labeled-response", opening.raw
        ref = opening.params[0][1:]

        lines = await client.collect_until("BATCH", timeout=5.0)
        closing = lines[-1]
        assert closing.params[0] == f"-{ref}", closing.raw

        body = [m for m in lines[:-1] if tag_value(m.tags, "batch") == ref]
        assert any(m.command == "311" for m in body), [m.command for m in body]
        assert any(m.command == "318" for m in body), [m.command for m in body]
        whoisuser = next(m for m in body if m.command == "311")
        assert whoisuser.params[1] == "RemoteOne", whoisuser.raw
    finally:
        await _cleanup(client)
        assert numnick  # the fake user was actually introduced


async def test_remote_whois_two_hops_is_fully_batched(ircd_hub, ulined_server):
    """WHOIS for a user homed on a server introduced *behind* the fake
    link: two hops from the querying client's server (hub -> fake server
    -> fake downstream server -> user). Same do_whois() code path as one
    hop (it only distinguishes MyConnect() vs. not), so this should be
    just as fully batched.
    """
    down_num = await ulined_server.send_downstream_server("down.two-hop.test", 90)
    await ulined_server.send_downstream_nick(
        down_num, "RemoteTwo", server_numeric=90, client_num=1,
        host="two-hop.test",
    )

    client = await make_cap_client(ircd_hub["host"], ircd_hub["port"], "lblrwho2", caps=LABELED_CAPS)
    try:
        await client.send("@label=rwho2 WHOIS RemoteTwo")

        opening = await client.wait_for("BATCH", timeout=5.0)
        assert tag_value(opening.tags, "label") == "rwho2", opening.raw
        ref = opening.params[0][1:]

        lines = await client.collect_until("BATCH", timeout=5.0)
        closing = lines[-1]
        assert closing.params[0] == f"-{ref}", closing.raw

        body = [m for m in lines[:-1] if tag_value(m.tags, "batch") == ref]
        assert any(m.command == "311" for m in body), [m.command for m in body]
        assert any(m.command == "318" for m in body), [m.command for m in body]
        whoisuser = next(m for m in body if m.command == "311")
        assert whoisuser.params[1] == "RemoteTwo", whoisuser.raw
        # RPL_WHOISSERVER's server name is deliberately masked to the HIS
        # placeholder for a non-oper querying a two-hop-away user
        # (FEAT_HIS_WHOIS_SERVERNAME, m_whois.c) -- that's unrelated to
        # labeled-response; just confirm the line is present and batched.
        assert any(m.command == "312" for m in body), [m.command for m in body]
    finally:
        await _cleanup(client)
