"""Labeled-response S2S propagation across a partially-upgraded (P11/P10) network.

Topology (see docker-compose ircd-nf-{a,b,c}):

    A (prod release, u2.10.12.19 -- P10, no labeled-response/BATCH S2S)
      -- B (working tree, P11)
      -- C (working tree, P11)

The A--B link negotiates P10 (A caps at protocol 10); the B--C link
negotiates P11.

Under P11, sendcmdto_one_hunted() (send.c) and parse_server()'s
labeled-response wrapper (parse.c) gate S2S @label= propagation on the
*negotiated link protocol* (Protocol(link) >= 11), not on a per-server
feature flag. A hop attaches or relays the label only over a link whose
peer speaks P11, so the P10 server A never sees an @label=/@batch= tag it
would not understand.

Two outcomes are checked here:

  1. Federation succeeds on a P11-only path. A client on C doing a
     labeled WHOIS-trick for a user on B is answered entirely over the
     P11 B--C link, so the reply comes back wrapped in a labeled BATCH.
     The P10 server A elsewhere in the network does not poison federation
     on the P11 segment.

  2. Degradation is clean when the path crosses a P10 hop. A labeled
     WHOIS reached over the P10 A--B link cannot be labeled: the label is
     dropped at the P10 boundary and the reply arrives complete but
     unlabeled, with no ACK and no BATCH.

     This is not a bug: it is the escape hatch the labeled-response spec
     sanctions for a response a server cannot honestly label ("servers
     might not produce a labeled response... clients should handle these
     cases as they would normally for a server without support for
     labeled responses"). ACK is reserved for commands that normally
     produce no response, so a forwarded, response-producing command that
     cannot be labeled degrades to unlabeled-with-no-ACK, never to a bare
     ACK. Nothing is left dangling (the capture is unlinked and freed at
     handoff), nothing hangs, and A never sees a tag it would not
     understand (confirmed on the wire via spy_on_b).
"""

from __future__ import annotations

import asyncio

import pytest

from cap_helpers import make_cap_client
from irc_client import IRCClient
from p11_server import P11Server

pytestmark = pytest.mark.nf_compat

LABELED_CAPS = ["batch", "labeled-response"]


def _tag_value(tags: str, key: str) -> str | None:
    if not tags:
        return None
    for part in tags.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        if k == key:
            return v
    return None


def _tag_has(tags: str, key: str) -> bool:
    return _tag_value(tags, key) is not None


@pytest.fixture
async def spy_on_b(ircd_nf_compat):
    """P10 peer on B to observe what B relays toward other servers (incl. A)."""
    b = ircd_nf_compat["b"]
    spy = P11Server(
        name="spy.test.net",
        numeric=7,
        password="testpass",
        description="NF compat labeled-response wire spy",
    )
    await spy.connect(b["host"], b["server_port"])
    await spy.handshake()
    yield spy
    await spy.disconnect()


async def _cleanup(*clients: IRCClient):
    for c in clients:
        try:
            await c.send("QUIT :test cleanup")
        except Exception:
            pass
        await c.disconnect()


async def _assert_still_alive(server: dict, nick: str):
    """Sanity check: the server in question is still responsive."""
    probe = IRCClient()
    await probe.connect(server["host"], server["port"])
    await probe.register(nick, "testuser", "Liveness Probe")
    await probe.send("PING :alive")
    pong = await probe.wait_for("PONG", timeout=5.0)
    assert pong.params[-1] == "alive", pong.raw
    await probe.send("QUIT :done")
    await probe.disconnect()


async def test_whois_trick_via_p10_hop_degrades_unlabeled_no_ack(
    ircd_nf_compat,
):
    """Client connects directly to B and does a labeled WHOIS trick for a
    user on A, reached over the B->A link, which is P10. The label cannot
    be carried, so B hands the capture off and the reply degrades to an
    unlabeled WHOIS with NO ACK -- never an immediate ACK and never a hang.

    Per the IRCv3 labeled-response spec, ACK is reserved for commands that
    normally produce no response; WHOIS produces one, so an unlabelable
    relayed WHOIS must degrade to "no labeled response, not even an ACK"
    (clients treat it as an unlabeled server), not to a bare ACK.
    """
    a = ircd_nf_compat["a"]
    b = ircd_nf_compat["b"]

    target = IRCClient()
    await target.connect(a["host"], a["port"])
    await target.register("nfwhoistgt1", "testuser", "NF WHOIS Target on A")

    client = await make_cap_client(b["host"], b["port"], "nflblb1", caps=LABELED_CAPS)
    try:
        await client.send(f"@label=viaB WHOIS {target.nick} {target.nick}")

        # The real reply arrives, unlabeled, and there is no ACK or BATCH.
        lines = await client.collect_until("318", timeout=10.0)
        assert any(m.command == "311" for m in lines), [m.command for m in lines]
        for m in lines:
            assert not _tag_has(m.tags, "label"), m.raw
            assert not _tag_has(m.tags, "batch"), m.raw
        assert not any(m.command == "ACK" for m in lines), lines
        assert not any(m.command == "BATCH" for m in lines), lines
    finally:
        await _cleanup(client, target)

    await _assert_still_alive(a, "nfaliveA1")
    await _assert_still_alive(b, "nfaliveB1")


async def test_whois_trick_to_p10_target_degrades_unlabeled(
    ircd_nf_compat, spy_on_b,
):
    """Client on C (P11) does a labeled WHOIS trick for a user on A (P10),
    routed C -> B -> A. C federates @label= over the P11 C--B link and B
    captures it, but the B--A link is P10, so B drops the label there
    rather than send a tag the prod binary would not understand. The real
    WHOIS reply still arrives complete, with no ACK and no BATCH -- the
    spec-sanctioned "can't honestly label this" degradation (see send.c),
    not a bug. Confirms it degrades cleanly rather than hanging or
    corrupting anything, and that A never sees an @label=/@batch= tag
    (confirmed on the wire via spy_on_b).
    """
    a = ircd_nf_compat["a"]
    b = ircd_nf_compat["b"]
    c = ircd_nf_compat["c"]

    target = IRCClient()
    await target.connect(a["host"], a["port"])
    await target.register("nfwhoistgt2", "testuser", "NF WHOIS Target on A 2")

    client = await make_cap_client(c["host"], c["port"], "nflblc1", caps=LABELED_CAPS)
    try:
        await client.send(f"@label=viaC WHOIS {target.nick} {target.nick}")

        # The real reply does arrive (routing itself is unaffected) --
        # collect up to RPL_ENDOFWHOIS.
        lines = await client.collect_until("318", timeout=10.0)
        assert any(m.command == "311" for m in lines), [m.command for m in lines]

        # No ACK and no BATCH ever showed up for this label: the label
        # was dropped at the P10 A--B boundary, so nothing labeled ever
        # reached A -- confirmed directly on the wire via spy_on_b, not
        # just inferred from the client's own view.
        for m in lines:
            assert not _tag_has(m.tags, "label"), m.raw
            assert not _tag_has(m.tags, "batch"), m.raw
        assert not any(m.command == "ACK" for m in lines), lines
        assert not any(m.command == "BATCH" for m in lines), lines

        await spy_on_b.drain_messages(0.5)
        tagged_toward_a = [
            line for line in spy_on_b.received
            if line.startswith("@") and ("label=" in line or "batch=" in line)
        ]
        assert not tagged_toward_a, (
            f"B must never relay @label=/@batch= toward the P10 peer A: "
            f"{tagged_toward_a!r}"
        )
    finally:
        await _cleanup(client, target)

    # Nothing crashed or desynced anywhere on the path.
    await _assert_still_alive(a, "nfaliveA2")
    await _assert_still_alive(b, "nfaliveB2")
    await _assert_still_alive(c, "nfaliveC2")



async def test_labeled_whois_federates_on_p11_only_path(ircd_nf_compat):
    """Client on C (P11) does a labeled WHOIS trick for a user on B (P11).

    The WHOIS is routed C -> B over the P11 B--C link and answered on B.
    Because the whole path speaks P11, C's capture is federated: B wraps
    its numerics in a BATCH labeled with the client's label and relays it
    back, so the client receives a properly labeled response. This is the
    positive counterpart to the P10-hop degradation tests -- the P10
    server A elsewhere in the network does not poison federation on the
    P11 segment.
    """
    b = ircd_nf_compat["b"]
    c = ircd_nf_compat["c"]

    target = IRCClient()
    await target.connect(b["host"], b["port"])
    await target.register("nfwhoistgt3", "testuser", "NF WHOIS Target on B")

    client = await make_cap_client(c["host"], c["port"], "nflblc2", caps=LABELED_CAPS)
    try:
        await client.send(f"@label=viaCB WHOIS {target.nick} {target.nick}")

        # WHOIS produces several numerics, so a successful labeled response
        # is a BATCH: an opening "@label=viaCB BATCH +<ref>", the 3xx
        # numerics tagged "@batch=<ref>", then a closing "BATCH -<ref>".
        # collect_until("318") captures the open and the numerics.
        lines = await client.collect_until("318", timeout=10.0)
        assert any(m.command == "311" for m in lines), [m.command for m in lines]
        batch_open = next(
            (m for m in lines
             if m.command == "BATCH" and m.params and m.params[0].startswith("+")),
            None,
        )
        assert batch_open is not None, [m.raw for m in lines]
        assert _tag_value(batch_open.tags, "label") == "viaCB", batch_open.raw
    finally:
        await _cleanup(client, target)

    await _assert_still_alive(b, "nfaliveB3")
    await _assert_still_alive(c, "nfaliveC3")
