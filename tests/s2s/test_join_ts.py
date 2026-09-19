"""P11 channel JOIN timestamp handling.

On a P11 link the channel timestamp of an S2S JOIN (``J``) is a mandatory,
all-digit parameter; only ``J 0`` (part all channels) goes without one.  No
ircu since u2.10.11 omits it, so a P11 JOIN without a valid timestamp is a
protocol violation and is dropped (neither applied nor relayed).  A P10 link
keeps the legacy optional form, so a P10 peer -- e.g. a services package --
that omits it is never dropped.

The *value* 0 stays legal on both: it means "creation time unknown" and is
what a server relays for a channel that a P10 peer created without a
timestamp.  No other value is consistent with the P10 server that holds the
channel at 0 (it bounces every MODE stamped with a real time, and its BURST
wins with 0), so the relay must carry it unchanged.

Every test watches the relay from a second linked server, not only the local
effect.
"""

from __future__ import annotations

import asyncio

import pytest

from p11_server import P11Server, strip_msg_tags

pytestmark = pytest.mark.single_server


async def _sender(hub, protocol=None) -> P11Server:
    kwargs = dict(name="notulined.test.net", numeric=5,
                  password="testpass", server_flags="")
    if protocol is not None:
        kwargs["protocol"] = protocol
    srv = P11Server(**kwargs)
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    return srv


async def _observer(hub) -> P11Server:
    srv = P11Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(hub["host"], hub["server_port"])
    await srv.handshake()
    return srv


async def _next_join_from(obs: P11Server, numnick: str, timeout: float = 5.0) -> list[str]:
    """Parameters of the next ``J`` line relayed to ``obs`` with source ``numnick``."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError(f"no J from {numnick}")
        line = await obs.wait_for_token("J", timeout=remaining)
        parts = strip_msg_tags(line).split()
        if parts[0] == numnick:
            return parts[2:]


async def _creationtime(client, chan) -> int:
    await client.send(f"MODE {chan}")
    ct = await client.wait_for("329", timeout=5.0)
    return int(ct.params[-1])


async def _sync(client) -> None:
    """Flush everything already queued (e.g. the join-time NAMES reply) so
    the next query reads its own answer."""
    await client.send("PING :joints-sync")
    while True:
        msg = await client.wait_for("PONG", timeout=10.0)
        if msg.params and msg.params[-1] == "joints-sync":
            break
    client._buffer.clear()


async def _names(client, chan) -> list[str]:
    await _sync(client)
    await client.send(f"NAMES {chan}")
    msgs = await client.collect_until("366", timeout=5.0)
    names: list[str] = []
    for msg in msgs:
        if msg.command == "353":
            names.extend(n.lstrip("@+") for n in msg.params[-1].split())
    return names


@pytest.mark.parametrize("bad_ts", ["", " abc", " 12x4"], ids=["missing", "alpha", "mixed"])
async def test_join_p11_without_valid_ts_is_dropped(ircd_hub, make_client, bad_ts):
    """A P11 JOIN with no / a non-numeric timestamp is neither applied nor relayed."""
    obs = await _observer(ircd_hub)
    srv = await _sender(ircd_hub)
    try:
        client = await make_client("joints1")
        chan = "#joints-drop"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")
        created = await _creationtime(client, chan)

        user = await srv.introduce_user("jtsfake1")
        await srv._send(f"{user} J {chan}{bad_ts}")
        await asyncio.sleep(0.7)
        assert "jtsfake1" not in await _names(client, chan)

        # Positive control: the well-formed JOIN is applied, and it is the
        # *first* J the observer sees from this user -- the bad one was never
        # relayed.
        await srv._send(f"{user} J {chan} {created}")
        assert await _next_join_from(obs, user) == [chan, str(created)]
        msg = await client.wait_for("JOIN", timeout=5.0)
        assert msg.prefix.startswith("jtsfake1!"), msg
    finally:
        await srv.disconnect()
        await obs.disconnect()


async def test_join_0_without_ts_still_honoured_on_p11(ircd_hub, make_client):
    """``J 0`` carries no timestamp by design and must keep working."""
    obs = await _observer(ircd_hub)
    srv = await _sender(ircd_hub)
    try:
        client = await make_client("joints2")
        chan = "#joints-zero"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")
        created = await _creationtime(client, chan)

        user = await srv.introduce_user("jtsfake2")
        await srv._send(f"{user} J {chan} {created}")
        assert await _next_join_from(obs, user) == [chan, str(created)]
        await client.wait_for("JOIN", timeout=5.0)

        await srv._send(f"{user} J 0")
        assert await _next_join_from(obs, user) == ["0"]
        msg = await client.wait_for("PART", timeout=5.0)
        assert msg.prefix.startswith("jtsfake2!"), msg
    finally:
        await srv.disconnect()
        await obs.disconnect()


async def test_join_p10_missing_ts_is_applied_and_relayed_with_our_ts(ircd_hub, make_client):
    """A P10 peer may omit the timestamp; for an existing channel the relay
    carries *our* creation time, never the (absent) received one."""
    obs = await _observer(ircd_hub)
    srv = await _sender(ircd_hub, protocol=10)
    try:
        client = await make_client("joints3")
        chan = "#joints-p10"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")
        created = await _creationtime(client, chan)

        user = await srv.introduce_user("jtsfake3")
        await srv._send(f"{user} J {chan}")
        assert await _next_join_from(obs, user) == [chan, str(created)]
        msg = await client.wait_for("JOIN", timeout=5.0)
        assert msg.prefix.startswith("jtsfake3!"), msg
    finally:
        await srv.disconnect()
        await obs.disconnect()


async def test_join_p10_missing_ts_new_channel_relays_unknown_as_zero(ircd_hub):
    """A channel a P10 peer creates without a timestamp is relayed with 0
    ("creation time unknown"), unchanged, even to a P11 link."""
    obs = await _observer(ircd_hub)
    srv = await _sender(ircd_hub, protocol=10)
    try:
        chan = "#joints-unknown"
        user = await srv.introduce_user("jtsfake4")
        await srv._send(f"{user} J {chan}")
        assert await _next_join_from(obs, user) == [chan, "0"]
    finally:
        await srv.disconnect()
        await obs.disconnect()


async def test_join_p11_explicit_zero_ts_is_accepted(ircd_hub):
    """An explicit 0 is a valid timestamp on a P11 link: a P11 server cannot
    tell whether it originated behind a P10 hop, so rejecting it would desync
    membership."""
    obs = await _observer(ircd_hub)
    srv = await _sender(ircd_hub)
    try:
        chan = "#joints-zero-ts"
        user = await srv.introduce_user("jtsfake5")
        await srv._send(f"{user} J {chan} 0")
        assert await _next_join_from(obs, user) == [chan, "0"]
    finally:
        await srv.disconnect()
        await obs.disconnect()
