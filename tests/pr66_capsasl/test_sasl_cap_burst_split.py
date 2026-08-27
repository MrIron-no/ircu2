"""SASL capability advertisement across a bursting link and a netsplit.

Reproduces a production incident: the SASL server (``channels.*``) lived
behind a hub (``shub``) that linked half-way -- it introduced its downlinks
but never completed its burst -- and then pinged out. Clients with
cap-notify saw::

    CAP hubby NEW sasl=plain,scram-sha-256,external
    CAP hubby DEL :sasl

on the *split*. Two defects combined to produce that:

* SASL availability was only re-evaluated on END_OF_BURST_ACK, so a
  half-linked SASL server was (correctly) never advertised, but the
  capability flag stayed stale relative to ``find_match_server()``.
* ``exit_one_client()`` re-evaluated availability for every server torn
  down in the split. A sibling of the SASL server exited first, the check
  still found the SASL server linked, and emitted a spurious CAP NEW one
  message before the real CAP DEL.

Topology in these tests (fake ``services.test.net`` plays ``shub``)::

    hub.test.net --- services.test.net --+-- channels.test.net  (sasl.server)
                     (fake, P10Server)   +-- other.test.net

``other`` is introduced *after* ``channels`` so it sits at the head of the
uplink's downlink list and is torn down first on a split -- the ordering
that triggered the spurious NEW.
"""

import asyncio

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.single_server

SASL_SERVER = "channels.test.net"
MECHANISMS = "PLAIN"


async def _capnotify_client(ircd_hub, nick: str) -> IRCClient:
    """Registered client with cap-notify active (implicit via CAP LS 302)."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.send("CAP LS 302")
    await client.wait_for("CAP", timeout=5.0)
    await client.send("CAP END")
    await client.register(nick, "testuser", "Test User")
    return client


async def _collect_cap(client: IRCClient, timeout: float) -> list[tuple[str, str]]:
    """Return every (subcommand, argument) CAP message seen within timeout."""
    seen = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return seen
        try:
            msg = await client.wait_for("CAP", timeout=remaining)
        except asyncio.TimeoutError:
            return seen
        seen.append((msg.params[1], msg.params[-1]))


async def _half_link_with_sasl_server(ircd_hub) -> P10Server:
    """Link a fake hub that introduces the SASL server but never finishes its burst."""
    srv = P10Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.begin_handshake()
    # Mid-burst from the hub's point of view: it has sent us EB, we have
    # not sent ours. Point SASL at a server *behind* us, then introduce it.
    await srv.send_config("sasl.server", SASL_SERVER)
    await srv.send_config("sasl.mechanisms", MECHANISMS)
    # Like a real uplink re-introducing downlinks that finished their own
    # burst long ago: P10, not J10.
    await srv.send_downstream_server(SASL_SERVER, 5, flags="s", bursting=False)
    await srv.send_downstream_server("other.test.net", 6, bursting=False)
    return srv


async def test_no_cap_new_when_half_linked_sasl_server_splits(ircd_hub):
    """A link that dies mid-burst must not produce CAP NEW (nor DEL) for sasl.

    The SASL server was never advertised, so there is nothing to withdraw
    and certainly nothing to announce.
    """
    client = await _capnotify_client(ircd_hub, "capsplit1")
    try:
        srv = await _half_link_with_sasl_server(ircd_hub)

        # Still bursting: nothing may be advertised yet.
        assert await _collect_cap(client, 1.5) == []

        # Link collapses without ever sending EB (ping timeout in production).
        await srv.disconnect()

        assert await _collect_cap(client, 2.0) == [], (
            "sasl must not be announced/withdrawn for a server that never "
            "finished bursting"
        )
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_new_on_end_of_burst_and_single_del_on_split(ircd_hub):
    """sasl is announced when the link finishes bursting, withdrawn once on split."""
    client = await _capnotify_client(ircd_hub, "capsplit2")
    try:
        srv = await _half_link_with_sasl_server(ircd_hub)
        assert await _collect_cap(client, 1.5) == []

        # Our EB completes the path to the SASL server. Advertise now --
        # without waiting for the EA exchange, which a services package
        # may never send.
        await srv.send_end_of_burst()
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NEW", f"expected CAP NEW, got {msg.params}"
        assert msg.params[-1] == f"sasl={MECHANISMS}", msg.params

        await srv.complete_handshake()
        # The EA exchange must not re-announce anything.
        assert await _collect_cap(client, 1.0) == []

        # Now the whole subtree goes away. Exactly one DEL, no NEW.
        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()


async def test_cap_new_waits_for_sasl_server_own_end_of_burst(ircd_hub):
    """A SASL server introduced with J10 is not advertised until *its* EB.

    Every hop on the path to the SASL server must be out of burst, not just
    the direct link.
    """
    client = await _capnotify_client(ircd_hub, "capsplit3")
    try:
        srv = P10Server(name="services.test.net", numeric=4, password="testpass")
        await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
        await srv.begin_handshake()
        await srv.send_config("sasl.server", SASL_SERVER)
        await srv.send_config("sasl.mechanisms", MECHANISMS)
        sasl_num = await srv.send_downstream_server(
            SASL_SERVER, 5, flags="s", bursting=True
        )

        # Our link finishes bursting, but channels.* is still in burst.
        await srv.send_end_of_burst()
        await srv.complete_handshake()
        assert await _collect_cap(client, 1.5) == [], (
            "sasl advertised while the SASL server itself is still bursting"
        )

        await srv.send_end_of_burst_for(sasl_num)
        msg = await client.wait_for("CAP", timeout=5.0)
        assert msg.params[1] == "NEW", f"expected CAP NEW, got {msg.params}"
        assert msg.params[-1] == f"sasl={MECHANISMS}", msg.params

        await srv.disconnect()
        caps = await _collect_cap(client, 2.0)
        assert caps == [("DEL", "sasl")], caps
    finally:
        await client.send("QUIT :done")
        await client.disconnect()
