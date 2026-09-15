"""Reproduction: a P11 MODE that is dropped for a missing/invalid channel TS
must not leave the channel's ban list corrupted.

mode_parse() applies parametric modes (+b, +l, +k, +U, +A) inline as it walks
the mode string, *before* it decides -- at the end -- that a P11 link sent no
valid trailing timestamp and the whole mode must be dropped.  For a ban this is
memory-unsafe: mode_parse_ban()/apply_ban() links a stack-allocated struct Ban
into chptr->banlist during the loop, and mode_process_bans() (which replaces
those stack entries with heap copies) is skipped by the drop's early return.
The channel is left pointing at freed stack memory, and the mode also took
partial local effect despite the spec saying it is "neither applied nor
propagated".
"""

from __future__ import annotations

import asyncio

import pytest

from p10_server import P10Server

pytestmark = pytest.mark.single_server


async def _link(hub, numeric=5, protocol=None) -> P10Server:
    kwargs = dict(name="notulined.test.net", numeric=numeric,
                  password="testpass", server_flags="")
    if protocol is not None:
        kwargs["protocol"] = protocol
    srv = P10Server(**kwargs)
    await srv.connect(hub["host"], hub["server_port"])
    return srv


async def _ban_list(client, chan):
    """Return the list of ban masks (367) for a channel."""
    await client.send(f"MODE {chan} b")
    masks = []
    while True:
        m = await client.recv(timeout=5.0)
        if m.command == "367":
            masks.append(m.params[2] if len(m.params) > 2 else "")
        elif m.command == "368":
            break
    return masks


async def test_p11_mode_drop_does_not_corrupt_banlist(ircd_hub, make_client):
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("bandrop1")
        chan = "#bandrop"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")

        # P11 MODE adding a ban but carrying NO trailing channel timestamp.
        # Per the P11 spec this is dropped: the ban must not be applied.
        await srv._send(f"{srv.server_numnick} M {chan} +b *!*@evil.example")
        await asyncio.sleep(0.5)

        # The ban must be absent (drop == "neither applied nor propagated").
        masks = await _ban_list(client, chan)
        assert masks == [], f"dropped ban was applied locally: {masks}"

        # And the server must still be alive and serving this channel: if the
        # ban list is dangling, walking it above (or this follow-up JOIN that
        # checks bans) trips ASan / crashes the hub.
        joiner = await make_client("bandrop2")
        await joiner.send(f"JOIN {chan}")
        await joiner.wait_for("JOIN", timeout=5.0)
    finally:
        await srv.disconnect()


async def _channel_modes(client, chan):
    """Return the mode string (324) for a channel, e.g. '+lm 50'."""
    await client.send(f"MODE {chan}")
    m = await client.wait_for("324", timeout=5.0)
    return " ".join(m.params[2:]) if len(m.params) > 2 else ""


async def test_p11_mode_drop_does_not_apply_limit(ircd_hub, make_client):
    """A dropped P11 MODE must not leave a parametric mode applied locally.

    +l writes chptr->mode inline during the parse loop, before the missing-TS
    drop decision; without the undo it stays set on this server only -- a
    network-wide mode desync, the very thing the P11 TS rule prevents.
    """
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("limitdrop1")
        chan = "#limitdrop"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")

        # P11 MODE setting a limit but carrying NO trailing channel timestamp.
        await srv._send(f"{srv.server_numnick} M {chan} +l 50")
        await asyncio.sleep(0.5)

        modes = await _channel_modes(client, chan)
        assert "l" not in modes.split(" ")[0], f"dropped +l was applied: {modes}"
        assert "50" not in modes, f"dropped +l was applied: {modes}"
    finally:
        await srv.disconnect()


async def _creationtime(client, chan):
    await client.send(f"MODE {chan}")
    ct = await client.wait_for("329", timeout=5.0)
    return int(ct.params[-1])


async def test_p11_mode_with_valid_ts_applies_ban(ircd_hub, make_client):
    """Positive control: a P11 MODE carrying a valid TS commits its ban
    through the deferred apply_ban() path."""
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("banok1")
        chan = "#banok"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")
        orig = await _creationtime(client, chan)

        await srv._send(f"{srv.server_numnick} M {chan} +b *!*@ok.example {orig}")
        await asyncio.sleep(0.5)

        masks = await _ban_list(client, chan)
        assert "*!*@ok.example" in masks, f"ban not applied: {masks}"
    finally:
        await srv.disconnect()


async def test_p11_less_specific_ban_replaces_more_specific(ircd_hub, make_client):
    """The deferred apply_ban() must still replace more-specific bans with a
    less-specific one.  Two narrow bans are set, then a broader ban that is a
    superset of both; the broad ban must remain and the two narrow ones must
    be removed (apply_ban marks them BAN_OVERLAPPED|BAN_DEL, mode_process_bans
    unlinks them).  Guards the relocation of the apply_ban() call into the
    commit phase."""
    srv = await _link(ircd_hub)
    try:
        await srv.handshake()
        client = await make_client("banoverlap1")
        chan = "#banoverlap"
        await client.send(f"JOIN {chan}")
        await client.wait_for("JOIN")
        orig = await _creationtime(client, chan)

        # Two specific bans.
        await srv._send(
            f"{srv.server_numnick} M {chan} +bb "
            f"a!b@host1.example.com a!b@host2.example.com {orig}")
        await asyncio.sleep(0.5)
        masks = await _ban_list(client, chan)
        assert "a!b@host1.example.com" in masks, masks
        assert "a!b@host2.example.com" in masks, masks

        # A broader ban that is a superset of both.
        await srv._send(f"{srv.server_numnick} M {chan} +b a!b@*.example.com {orig}")
        await asyncio.sleep(0.5)

        masks = await _ban_list(client, chan)
        assert masks == ["a!b@*.example.com"], (
            f"less-specific ban did not replace the specific ones: {masks}")
    finally:
        await srv.disconnect()
