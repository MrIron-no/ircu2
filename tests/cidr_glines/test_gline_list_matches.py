"""Tests for gline_list() enumerating every matching G-line, and for the
non-oper restriction on wildcard/text-covering searches.

Historically `GLINE <mask>` (both the oper form and the plain-user form)
only ever returned the first matching G-line. Reported bug: after adding
G-lines on `*@1.2.3.4`, `*@1.2.3.0/24`, and `*hidden@1.2.3.4`, querying
`1.2.3.4` only showed the first one -- never the CIDR parent, never the
second G-line sharing the same exact tree node.

The fix makes gline_list() enumerate every match: for a concrete ip/cidr,
it walks the CIDR tree from the deepest covering node up through every
ancestor (mirroring gline_lookup()'s real per-connection containment
walk), plus checks family-ambiguous ip-mask G-lines that live outside the
tree via a numeric ipmask_check(). Non-opers get the same numeric
treatment for a concrete ip/cidr (no privilege gap there), but are
restricted to exact string matches for anything that doesn't parse as an
ip/cidr -- wildcards are only honored on the user@ part -- so they cannot
enumerate/discover wildcarded G-lines or BadChans by pattern fishing the
way an oper can.
"""

import asyncio
import time

import pytest

from irc_client import IRCClient
from p11_server import P11Server


pytestmark = pytest.mark.single_server

RPL_GLIST = "280"
RPL_ENDOFGLIST = "281"
ERR_NOSUCHGLINE = "512"
RPL_YOUREOPER = "381"


async def oper_up(client):
    await client.send("OPER testoper operpass")
    await client.wait_for(RPL_YOUREOPER)


async def make_oper(ircd_hub, nick):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.register(nick, "testuser", "Test User")
    await oper_up(client)
    return client


@pytest.fixture
async def oper(ircd_hub):
    client = await make_oper(ircd_hub, "matchoper")
    yield client
    try:
        await client.disconnect()
    except Exception:
        pass


@pytest.fixture
async def plain(ircd_hub):
    """A plain registered client that never opers up."""
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.register("matchuser", "testuser", "Test User")
    yield client
    try:
        await client.disconnect()
    except Exception:
        pass


async def gline_query(client, mask):
    """Send `GLINE <mask>` and return every RPL_GLIST reply (as a list).

    Drains the full reply stream up to RPL_ENDOFGLIST/ERR_NOSUCHGLINE so
    leftover buffered replies don't corrupt whatever is read next on this
    connection. Returns [] on ERR_NOSUCHGLINE.
    """
    await client.send(f"GLINE {mask}")
    matches = []
    while True:
        msg = await client.recv(timeout=5.0)
        if msg.command == ERR_NOSUCHGLINE:
            return []
        if msg.command == RPL_GLIST:
            matches.append(msg)
        elif msg.command == RPL_ENDOFGLIST:
            return matches


def _texts(matches):
    return [p for msg in matches for p in msg.params]


async def gline_state(oper, mask):
    """Query `GLINE <mask>` and return the state of the entry matching mask."""
    matches = await gline_query(oper, mask)
    for msg in matches:
        if msg.params[1] == mask:
            return msg.params[-2]
    return None


async def deactivate_gline(ircd_hub, mask, nick):
    """Deactivate a G-line from a fresh oper connection and confirm it.

    Resent until it takes effect, since gline_modify() silently ignores a
    modification whose lastmod equals the G-line's current lastmod
    (same-second version dedup).
    """
    cleaner = await make_oper(ircd_hub, nick)
    try:
        deadline = time.time() + 15.0
        while time.time() < deadline:
            await cleaner.send(f"GLINE !-{mask} * 3600 :cleanup")
            if await gline_state(cleaner, mask) in ("-", None):
                return
            import asyncio

            await asyncio.sleep(1.0)
        raise AssertionError(f"could not deactivate G-line {mask}")
    finally:
        try:
            await cleaner.disconnect()
        except Exception:
            pass


async def test_multiple_matches_for_concrete_ip(ircd_hub, oper):
    """The reported bug: querying a concrete ip must list every covering
    G-line, not just the first -- the CIDR parent, and every G-line
    sharing the exact node.
    """
    await oper.send("GLINE !+*@1.2.3.4 * 3600 :exact host test")
    await oper.send("GLINE !+*@1.2.3.0/24 * 3600 :cidr parent test")
    await oper.send("GLINE !+*hidden@1.2.3.4 * 3600 :second gline same node")

    try:
        matches = await gline_query(oper, "1.2.3.4")
        texts = _texts(matches)
        assert any("*@1.2.3.4" in t for t in texts), (
            f"missing exact-node G-line, got {[(m.command, m.params) for m in matches]}"
        )
        assert any("1.2.3.0/24" in t for t in texts), (
            f"missing CIDR parent G-line, got {[(m.command, m.params) for m in matches]}"
        )
        assert any("*hidden@1.2.3.4" in t for t in texts), (
            f"missing second G-line sharing the exact node, got "
            f"{[(m.command, m.params) for m in matches]}"
        )
        assert len(matches) >= 3, (
            f"expected at least 3 matches, got {[(m.command, m.params) for m in matches]}"
        )
    finally:
        await deactivate_gline(ircd_hub, "*@1.2.3.4", nick="matchcln1")
        await deactivate_gline(ircd_hub, "*@1.2.3.0/24", nick="matchcln2")
        await deactivate_gline(ircd_hub, "*hidden@1.2.3.4", nick="matchcln3")


async def test_family_ambiguous_mask_surfaces_for_concrete_ip(ircd_hub, oper):
    """A family-ambiguous ip mask (e.g. *@::/0) never enters the per-family
    CIDR tree, but gline_lookup() still enforces it via a numeric
    ipmask_check() against GlobalGlineList -- gline_list() must surface it
    the same way for a concrete-ip query, or a self-check could report
    "no G-line" when one would actually hit the client.

    gline_checkmask() hard-rejects a bare "::/0" mask even with the "!"
    force prefix (its width is under the ipmask<16 floor), so inject it
    through a fake U-lined P10 services server instead, exactly as
    test_family_ambiguous_masks.py does for the equally-too-wide "*" mask.
    Reuses the same U-lined server name the docker config allows
    ("services.test.net"); these tests run sequentially, not
    concurrently, so there's no connection clash with other tests using it.
    """
    srv = P11Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.handshake()
    now = int(time.time())
    try:
        await srv._send(
            f"{srv._num} GL * +ambivictim@::/0 3600 {now} {now + 3600} :zero prefix test"
        )
        # Keep the services link open until the query is answered:
        # P11Server.disconnect() aborts the socket (RST), and an RST
        # arriving before the ircd reads the GL line discards it from
        # the receive buffer, so disconnecting right after _send()
        # loses the G-line on a timing race. The GL also lands
        # asynchronously relative to the oper connection, so poll.
        deadline = asyncio.get_running_loop().time() + 10.0
        matches = []
        while asyncio.get_running_loop().time() < deadline:
            matches = await gline_query(oper, "203.0.113.5")
            if any("ambivictim@::/0" in t for t in _texts(matches)):
                break
            await asyncio.sleep(0.3)
        assert any("ambivictim@::/0" in t for t in _texts(matches)), (
            "family-ambiguous *@::/0 must surface for a concrete ipv4 query, got "
            f"{[(m.command, m.params) for m in matches]}"
        )
    finally:
        await srv.disconnect()
        await deactivate_gline(ircd_hub, "ambivictim@::/0", nick="matchcln4")


async def test_non_oper_concrete_ip_query_matches_oper(ircd_hub, oper, plain):
    """A non-oper querying a concrete ip/cidr gets the same numeric
    containment result an oper would -- no privilege gap there.
    """
    await oper.send("GLINE !+*@198.51.100.7 * 3600 :non-oper parity test")
    try:
        # Confirm the add landed (round-trip on the oper connection) before
        # querying from the separate `plain` connection, to avoid a race
        # between the two independent TCP connections.
        oper_matches = await gline_query(oper, "198.51.100.7")
        assert oper_matches, "sanity: oper query should find the fresh G-line"

        matches = await gline_query(plain, "198.51.100.7")
        assert any("198.51.100.7" in t for t in _texts(matches)), (
            f"non-oper concrete-ip query should find the G-line, got "
            f"{[(m.command, m.params) for m in matches]}"
        )
    finally:
        await deactivate_gline(ircd_hub, "*@198.51.100.7", nick="matchcln5")


async def test_non_oper_wildcard_ip_query_rejected(ircd_hub, oper, plain):
    """A non-oper cannot use a wildcard host pattern to fish for G-lines,
    even though an oper's equivalent query finds it.
    """
    await oper.send("GLINE !+*@10.77.88.0/24 * 3600 :wildcard restriction test")
    try:
        oper_matches = await gline_query(oper, "*@10.77.*")
        assert any("10.77.88.0/24" in t for t in _texts(oper_matches)), (
            "sanity: oper wildcard query should still find the narrower G-line"
        )

        plain_matches = await gline_query(plain, "*@10.77.*")
        assert not any("10.77.88.0/24" in t for t in _texts(plain_matches)), (
            "non-oper must not be able to wildcard-search host masks, got "
            f"{[(m.command, m.params) for m in plain_matches]}"
        )
    finally:
        await deactivate_gline(ircd_hub, "*@10.77.88.0/24", nick="matchcln6")


async def test_non_oper_badchan_wildcard_query_rejected(ircd_hub, oper, plain):
    """Same restriction for BadChan masks: a non-oper cannot pattern-fish
    with a wildcard channel mask, though an oper still can.
    """
    await oper.send("GLINE !+#nonopwild* * 3600 :badchan wildcard test")
    try:
        oper_matches = await gline_query(oper, "#*")
        assert any("#nonopwild*" in t for t in _texts(oper_matches)), (
            "sanity: oper wildcard BadChan query should still find it"
        )

        plain_matches = await gline_query(plain, "#*")
        assert not any("#nonopwild*" in t for t in _texts(plain_matches)), (
            "non-oper must not be able to wildcard-search BadChan masks, got "
            f"{[(m.command, m.params) for m in plain_matches]}"
        )
    finally:
        await deactivate_gline(ircd_hub, "#nonopwild*", nick="matchcln7")


async def test_non_oper_exact_hostname_mask_query_works(ircd_hub, oper, plain):
    """A non-oper who already knows the exact (non-ip) mask text can still
    query it directly -- only wildcard *searching* is restricted, not
    exact lookups -- and wildcards on the user@ part are still honored.
    """
    await oper.send(
        "GLINE !+*@nonopexact.example.net * 3600 :exact hostname test"
    )
    try:
        oper_matches = await gline_query(oper, "*@nonopexact.example.net")
        assert oper_matches, "sanity: oper query should find the fresh G-line"

        exact_matches = await gline_query(plain, "*@nonopexact.example.net")
        assert any(
            "nonopexact.example.net" in t for t in _texts(exact_matches)
        ), (
            "non-oper exact hostname query should work, got "
            f"{[(m.command, m.params) for m in exact_matches]}"
        )

        wildcard_matches = await gline_query(plain, "*@nonopexact.*")
        assert not any(
            "nonopexact.example.net" in t for t in _texts(wildcard_matches)
        ), (
            "non-oper must not be able to wildcard-search hostname masks, got "
            f"{[(m.command, m.params) for m in wildcard_matches]}"
        )
    finally:
        await deactivate_gline(
            ircd_hub, "*@nonopexact.example.net", nick="matchcln8"
        )
