"""Lightweight P10 fake server for testing ircu2 S2S behavior.

Connects to an ircd as a server, completes the P10 handshake (PASS,
SERVER, burst, EB/EA), and exposes methods to send S2S protocol
messages like OPMODE and ACCOUNT.
"""

import asyncio
import ipaddress
import logging
import ssl
import time

logger = logging.getLogger("p10_server")

# Network config / S-line updates are resolved last-writer-wins by a
# whole-second time_t timestamp, and the ircd rejects any write that is not
# strictly newer than the stored one. Consecutive test writes can land in the
# same wall-clock second, so hand out a process-wide monotonically increasing
# timestamp (never below real time) to keep every write authoritative.
_last_ts = 0


def _next_timestamp() -> int:
    global _last_ts
    _last_ts = max(_last_ts + 1, int(time.time()))
    return _last_ts


# P10 base64 character set
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]"
_B64_VAL = {c: i for i, c in enumerate(_B64)}


def int_to_b64(value: int, width: int) -> str:
    """Encode an integer as a P10 base64 string of fixed width."""
    chars = []
    for _ in range(width):
        chars.append(_B64[value & 63])
        value >>= 6
    return "".join(reversed(chars))


def b64_to_int(s: str) -> int:
    """Decode a P10 base64 string to an integer."""
    result = 0
    for c in s:
        result = (result << 6) | _B64_VAL[c]
    return result


def server_numeric(num: int) -> str:
    """Encode a server numeric as 2-char P10 base64."""
    return int_to_b64(num, 2)


def client_numnick(server_num: int, client_num: int) -> str:
    """Encode a full SSCCC numnick (2-char server + 3-char client)."""
    return server_numeric(server_num) + int_to_b64(client_num, 3)


def ipv4_to_b64(ip: str = "127.0.0.1") -> str:
    """Encode an IPv4 address as a 6-character P10 base64 string."""
    parts = [int(x) for x in ip.split(".")]
    value = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    return int_to_b64(value, 6)


def parse_numnick(numnick: str) -> tuple[int, int]:
    """Parse a 5-char numnick into (server_numeric, client_numeric)."""
    return b64_to_int(numnick[:2]), b64_to_int(numnick[2:])


def strip_msg_tags(line: str) -> str:
    """Remove a leading IRCv3 @tag-section from an S2S line if present."""
    if not line.startswith("@"):
        return line
    sp = line.find(" ")
    return line[sp + 1 :] if sp != -1 else line


class P10Server:
    """A fake IRC server speaking the P10 wire protocol.

    Connects to an ircd on its server port, performs the full P10
    handshake, then allows sending arbitrary S2S messages.  By default it
    announces protocol 11 (J11) so the ircd sends it the P11 extensions;
    construct with ``protocol=10`` to act as a legacy P10 peer.
    """

    def __init__(
        self,
        name: str = "services.test.net",
        numeric: int = 4,
        password: str = "testpass",
        max_clients: int = 64,
        description: str = "Test Services",
        server_flags: str = "s",
        protocol: int = 11,
        caps: str = "",
        send_cap: bool = True,
        first_line: str | None = None,
        numnick_mask: str | None = None,
        cap_delay: float = 0.0,
        announce_ipv6: bool = True,
    ):
        self.name = name
        self.numeric = numeric
        self.password = password
        self.max_clients = max_clients
        self.description = description
        # Protocol number announced in our SERVER line.  ircd gates the
        # P11 extensions (message tags, TAGMSG, TLS fingerprints, remote
        # OPMODE +x, already-authed ACCOUNT updates) per link on this, so
        # pass protocol=10 to observe what a legacy P10 peer receives.
        self.protocol = protocol
        # A direct P10 peer must announce the IPv6 server flag ('6') or the
        # ircd refuses the link (doc/P11.md, "Server flags"); a P11 peer
        # implies it and never sends it.  ``announce_ipv6=False`` withholds
        # the flag to provoke that refusal.
        if protocol < 11 and announce_ipv6 and "6" not in server_flags:
            server_flags += "6"
        self.server_flags = server_flags
        # P11 link capabilities (doc/P11.md, "Link capabilities").  On a P11
        # link each side sends one unprefixed ``CAP :<list>`` line right
        # after SERVER and before its burst.  ``caps`` is our announced
        # list (space separated, empty by default -> the literal ``CAP :``).
        # ``send_cap=False`` withholds the line (silent peer); ``first_line``
        # replaces it verbatim with something else (to provoke the strict
        # gate).  Neither has any effect when either side is P10.
        self.caps = caps
        self.send_cap = send_cap
        self.first_line = first_line
        # Accepting role only: seconds to wait before sending our CAP line,
        # to hold the connector in its CAP wait.
        self.cap_delay = cap_delay
        # Accepting role bookkeeping (see serve()).
        self.accepted_count = 0
        self.peer_password: str | None = None
        self._server: asyncio.AbstractServer | None = None
        self.connection_closed = asyncio.Event()
        # Peer-side observations, filled in during the handshake.
        self.peer_protocol: int | None = None
        self.peer_cap_line: str | None = None
        self.peer_caps: str = ""
        # Order in which the peer's SERVER, CAP and first burst line arrived.
        self.handshake_order: list[str] = []

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.connected = False
        self.burst_complete = False

        # Our server's base64 numeric prefix (2 chars). Exposed via the
        # `server_numick` property below for tests that need to send a message
        # with the server itself (not one of its users) as the source.
        self._num = server_numeric(numeric)
        # Numnick mask: server numeric (2) + max clients (3).  A verbatim
        # override lets tests send a malformed or legacy (3-char YXX) mask.
        if numnick_mask is None:
            self._numnick_mask = self._num + int_to_b64(max_clients, 3)
        else:
            self._numnick_mask = numnick_mask
            # Our prefix must match what we announced: YYXXX has a 2-char
            # server part, the legacy YXX form a 1-char one.  A malformed
            # mask keeps the default numeric (the ircd refuses it anyway).
            if len(numnick_mask) == 5:
                self._num = numnick_mask[:2]
            elif len(numnick_mask) == 3:
                self._num = numnick_mask[:1]

        # Users we've seen, keyed by nick (lowercase)
        self.users: dict[str, dict] = {}
        # All raw messages received
        self.received: list[str] = []
        # Next client numeric for users we introduce ourselves
        self._next_client_num = 0

    @property
    def server_numnick(self) -> str:
        """This server's own base64 P10 numeric prefix, for server-sourced messages.
        """
        return self._num

    async def connect(self, host: str, port: int):
        """Open a TCP connection to the ircd's server port."""
        self._reader, self._writer = await asyncio.open_connection(host, port)
        self.connected = True
        logger.debug("Connected to %s:%d", host, port)

    async def connect_tls(
        self,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None = None,
    ):
        """Open a TLS connection to the ircd's server port."""
        if ssl_context is None:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        self._reader, self._writer = await asyncio.open_connection(
            host, port, ssl=ssl_context
        )
        self.connected = True
        await asyncio.sleep(0.3)
        logger.debug("Connected with TLS to %s:%d", host, port)

    async def read_raw_line(self, timeout: float = 5.0) -> str:
        """Read one raw line without PING handling."""
        return await self._recv_raw(timeout=timeout)

    async def disconnect(self):
        """Send SQUIT and close the connection."""
        if self._writer:
            try:
                if self.burst_complete:
                    await self._send(f"{self._num} SQ {self.name} 0 :Test done")
            except Exception:
                pass
            try:
                transport = self._writer.transport
                self._writer.close()
                if transport is not None:
                    transport.abort()
                else:
                    await self._writer.wait_closed()
            except (ssl.SSLError, OSError, ConnectionError):
                pass
        self.connected = False
        self._reader = None
        self._writer = None

    async def _send(self, line: str):
        """Send a raw line to the ircd."""
        if not self._writer:
            raise ConnectionError("Not connected")
        logger.debug(">> %s", line)
        self._writer.write((line + "\r\n").encode("utf-8"))
        await self._writer.drain()

    async def _recv_raw(self, timeout: float = 10.0) -> str:
        """Read one raw line from the ircd."""
        if not self._reader:
            raise ConnectionError("Not connected")
        raw = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
        if not raw:
            raise ConnectionError("Connection closed by server")
        line = raw.decode("utf-8", errors="replace").strip()
        logger.debug("<< %s", line)
        self.received.append(line)
        return line

    async def _recv(self, timeout: float = 10.0) -> str:
        """Read one line, auto-handling PINGs and parsing NICKs.

        Returns the line. PINGs are answered automatically and skipped
        (the next line is returned instead).
        """
        while True:
            line = await self._recv_raw(timeout=timeout)
            payload = strip_msg_tags(line)
            tokens = payload.split()

            # Handle PING in both forms:
            #   PING :<origin>                    (unprefixed, pre-handshake)
            #   <prefix> G !<cookie> <target> ... (token form, post-handshake)
            if tokens and tokens[0] == "PING":
                origin = tokens[1].lstrip(":")
                await self._send(f"{self._num} Z {self._num} :{origin}")
                continue
            if len(tokens) >= 2 and tokens[1] == "G":
                # PONG format: <our_num> Z <our_num> :<cookie>
                # The cookie is the second token (after G), strip the !
                cookie = tokens[2].lstrip("!") if len(tokens) > 2 else tokens[-1]
                await self._send(f"{self._num} Z {self._num} :{cookie}")
                continue

            # Parse NICK (N) messages to track users
            if len(tokens) >= 2 and tokens[1] == "N":
                self._parse_nick(payload)

            return line

    def _get_token(self, line: str) -> str | None:
        """Extract the P10 token (second space-delimited word) from a line."""
        parts = strip_msg_tags(line).split(" ", 2)
        return parts[1] if len(parts) >= 2 else None

    async def handshake(self, timeout: float = 15.0):
        """Perform the full P10 server handshake.

        Sends PASS + SERVER, reads the hub's PASS + SERVER + burst,
        sends our EB, waits for EA, sends EA.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        await self.begin_handshake(timeout=timeout)
        await self.send_end_of_burst()
        remaining = deadline - asyncio.get_event_loop().time()
        await self.complete_handshake(timeout=remaining)

    async def begin_handshake(self, timeout: float = 15.0):
        """Send PASS + SERVER and read the hub's burst up to its EB.

        Leaves the link in the "still bursting" state from the hub's point
        of view: we have not sent our own EB yet. Tests that need a
        half-linked server (e.g. to simulate a link that dies mid-burst)
        stop here; otherwise follow with send_end_of_burst() and
        complete_handshake().
        """
        now = int(time.time())

        # Send our credentials
        await self._send(f"PASS :{self.password}")
        flags = self.server_flags
        flag_field = f"+{flags}" if flags else "+"
        await self._send(
            f"SERVER {self.name} 1 {now} {now} J{self.protocol} {self._numnick_mask} "
            f"{flag_field} :{self.description}"
        )

        # Read hub's PASS/SERVER (+ CAP on a P11 link) and burst until EB.
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for end of burst")
            line = await self._recv(timeout=remaining)
            await self._observe_handshake_line(line)
            tok = self._get_token(line)
            if tok == "EB" or line == "EB":
                break

    @staticmethod
    def _parse_server_protocol(tokens: list[str]) -> int | None:
        """Return the protocol number from a SERVER line's ``[JP]NN`` field."""
        for tok in tokens[1:]:
            if len(tok) >= 2 and tok[0] in "JP" and tok[1:].isdigit():
                return int(tok[1:])
        return None

    async def _observe_handshake_line(self, line: str):
        """Track the peer's SERVER / CAP / first burst line and answer CAP.

        Called for every line read during the handshake (both roles).  When
        the peer's SERVER shows protocol >= 11 and we are P11 ourselves, our
        own CAP line (or ``first_line``) goes out immediately, before any
        further line is read -- this is the slot P11 reserves for it.
        """
        payload = strip_msg_tags(line)
        tokens = payload.split()
        if not tokens:
            return
        if tokens[0] == "PASS" and self.peer_protocol is None:
            return
        if tokens[0] == "SERVER" and self.peer_protocol is None:
            self.peer_protocol = self._parse_server_protocol(tokens)
            self.handshake_order.append("SERVER")
            if (self.peer_protocol or 0) >= 11 and self.protocol >= 11:
                await self._send_cap_slot()
            return
        if tokens[0] == "CAP" and self.peer_cap_line is None:
            self.peer_cap_line = payload
            self.peer_caps = payload.split(":", 1)[1] if ":" in payload else ""
            self.handshake_order.append("CAP")
            return
        if "SERVER" in self.handshake_order and "BURST" not in self.handshake_order:
            self.handshake_order.append("BURST")

    async def _send_cap_slot(self):
        """Send whatever we put in the post-SERVER slot on a P11 link."""
        if self.first_line is not None:
            await self._send(self.first_line)
        elif self.send_cap:
            await self._send(f"CAP :{self.caps}")

    async def send_end_of_burst(self):
        """Send our EB, marking the end of our (possibly empty) burst."""
        await self._send(f"{self._num} EB")

    async def complete_handshake(self, timeout: float = 15.0):
        """Wait for the hub's EA and answer with our own EA."""
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for EA")
            line = await self._recv(timeout=remaining)
            tok = self._get_token(line)
            if tok == "EA" or line == "EA":
                break

        # Send our EA
        await self._send(f"{self._num} EA")
        self.burst_complete = True
        logger.info("P10 handshake complete, connected as %s (%s)", self.name, self._num)

    # ------------------------------------------------------------------
    # Accepting role: the ircd connects to us (CONNECT / autoconnect)
    # ------------------------------------------------------------------

    async def serve(self, host: str, port: int) -> asyncio.AbstractServer:
        """Listen for one inbound server link and run accept_handshake() on it.

        A second connection while one is active is counted in
        ``accepted_count`` and closed immediately.  ``connection_closed`` is
        set once the active link has gone away.
        """
        self._server = await asyncio.start_server(self._on_accept, host, port)
        return self._server

    async def _on_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.accepted_count += 1
        if self._reader is not None:
            logger.info("Refusing a second inbound connection (#%d)", self.accepted_count)
            writer.close()
            return
        self._reader, self._writer = reader, writer
        self.connected = True
        try:
            await self.accept_handshake()
            while True:                     # stay linked until the peer goes
                await self._recv(timeout=3600.0)
        except (ConnectionError, asyncio.TimeoutError, TimeoutError) as exc:
            logger.info("Inbound link ended: %s", exc)
        finally:
            try:
                writer.close()
            except Exception:
                pass
            self.connected = False
            self.connection_closed.set()

    async def accept_handshake(self, timeout: float = 15.0):
        """Accepting-role handshake: read PASS + SERVER, answer, then burst.

        Mirrors what an ircd acceptor does: our SERVER goes out after the
        connector's; on a P11 link our CAP (or ``first_line``) follows it,
        after ``cap_delay``; then the connector's CAP and burst are read
        through EB, and EB/EA are exchanged.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout

        while self.peer_protocol is None:
            line = await self._recv(timeout=max(0.1, deadline - loop.time()))
            tokens = strip_msg_tags(line).split()
            if tokens and tokens[0] == "PASS":
                self.peer_password = tokens[-1].lstrip(":")
            elif tokens and tokens[0] == "SERVER":
                self.peer_protocol = self._parse_server_protocol(tokens)
                self.handshake_order.append("SERVER")

        now = int(time.time())
        flag_field = f"+{self.server_flags}" if self.server_flags else "+"
        await self._send(f"PASS :{self.password}")
        await self._send(
            f"SERVER {self.name} 1 {now} {now} J{self.protocol} {self._numnick_mask} "
            f"{flag_field} :{self.description}"
        )
        if (self.peer_protocol or 0) >= 11 and self.protocol >= 11:
            if self.cap_delay:
                await asyncio.sleep(self.cap_delay)
            await self._send_cap_slot()

        while True:
            line = await self._recv(timeout=max(0.1, deadline - loop.time()))
            await self._observe_handshake_line(line)
            tok = self._get_token(line)
            if tok == "EB" or line == "EB":
                break
        await self.send_end_of_burst()
        await self.complete_handshake(timeout=max(1.0, deadline - loop.time()))

    def _parse_nick(self, line: str):
        """Parse a P10 N (NICK) message and store user info.

        Format: <server> N <nick> <hop> <ts> <user> <host> [+modes] [<b64ip>] <numnick> :<realname>
        """
        if " :" in line:
            head, realname = line.rsplit(" :", 1)
        else:
            head = line
            realname = ""

        parts = head.split()
        if len(parts) < 6:
            return

        nick = parts[2]
        username = parts[5] if len(parts) > 5 else "unknown"
        host = parts[6] if len(parts) > 6 else "unknown"

        # The numnick is the last token in head (before the :realname)
        numnick = parts[-1]

        # Detect modes - look for a token starting with +
        modes = ""
        for p in parts[7:-1]:
            if p.startswith("+"):
                modes = p
                break

        self.users[nick.lower()] = {
            "nick": nick,
            "numnick": numnick,
            "username": username,
            "host": host,
            "modes": modes,
            "realname": realname,
        }

    def get_user_numnick(self, nick: str) -> str | None:
        """Look up a user's 5-char numnick by their nick."""
        info = self.users.get(nick.lower())
        return info["numnick"] if info else None

    async def send_downstream_server(
        self,
        name: str,
        numeric: int,
        *,
        hop: int = 2,
        flags: str = "",
        description: str = "Downstream test server",
        timestamp: int | None = None,
        protocol: int | None = None,
        bursting: bool = True,
    ) -> str:
        """Introduce a remote server behind this link.

        ``bursting`` selects the protocol field: ``J10`` (default) tells the
        hub the server is still bursting -- it stays flagged as such until
        an EB arrives from *that* server's numeric (see send_end_of_burst_for).
        ``P10`` introduces a server whose burst already completed, which is
        how an uplink re-introduces its existing downlinks during its own
        burst.

        Returns the 2-character P10 server numeric for the new server.
        """
        ts = timestamp or _next_timestamp()
        version = self.protocol if protocol is None else protocol
        down_num = server_numeric(numeric)
        down_mask = down_num + int_to_b64(self.max_clients, 3)
        flag_field = f"+{flags}" if flags else "+"
        prefix = "J" if bursting else "P"
        await self._send(
            f"{self._num} SERVER {name} {hop} 0 {ts} {prefix}{version} {down_mask} "
            f"{flag_field} :{description}"
        )
        return down_num

    async def send_end_of_burst_for(self, server_numeric_prefix: str):
        """Send EB on behalf of a downstream server introduced with J10."""
        await self._send(f"{server_numeric_prefix} EB")

    async def send_downstream_nick(
        self,
        server_numeric_prefix: str,
        nick: str,
        *,
        server_numeric: int,
        client_num: int = 1,
        username: str | None = None,
        host: str = "downstream.test",
        realname: str = "Downstream User",
        timestamp: int | None = None,
        modes: str = "",
    ) -> str:
        """Introduce a user homed on a downstream server.

        modes: optional usermode letters (without '+'), e.g. "iz" for an
        invisible TLS user.
        """
        ts = timestamp or int(time.time())
        user = username or nick.lower()
        numnick = client_numnick(server_numeric, client_num)
        ip_b64 = ipv4_to_b64()
        mode_field = f"+{modes} " if modes else ""
        await self._send(
            f"{server_numeric_prefix} N {nick} 1 {ts} {user} {host} "
            f"{mode_field}{ip_b64} {numnick} :{realname}"
        )
        self.users[nick.lower()] = {
            "nick": nick,
            "numnick": numnick,
            "username": user,
            "host": host,
            "modes": modes,
            "realname": realname,
        }
        return numnick

    async def send_downstream_join(
        self,
        nick: str,
        channel: str,
        *,
        creation: int | None = None,
    ):
        """Make a downstream user join a channel (P10 JOIN / J)."""
        info = self.users.get(nick.lower())
        if not info:
            raise KeyError(f"unknown downstream user {nick!r}")
        ts = creation if creation is not None else _next_timestamp()
        await self._send(f"{info['numnick']} J {channel} {ts}")

    async def send_downstream_part(
        self,
        nick: str,
        channel: str,
        comment: str = "leaving",
    ):
        """Make a downstream user part a channel (P10 PART / L)."""
        info = self.users.get(nick.lower())
        if not info:
            raise KeyError(f"unknown downstream user {nick!r}")
        await self._send(f"{info['numnick']} L {channel} :{comment}")

    async def send_opmode(self, target_numnick: str, mode: str):
        """Send an OPMODE for a user mode change.

        Format: <our_numeric> OM <target_numnick> <mode>
        """
        await self._send(f"{self._num} OM {target_numnick} {mode}")

    async def send_account(self, target_numnick: str, account: str,
                           acc_id: int | None = None, acc_flags: int | None = None):
        """Send an ACCOUNT message to set a user's account.

        Format: <our_numeric> AC <target_numnick> <account> [<acc_id> [<acc_flags>]]
        """
        parts = f"{self._num} AC {target_numnick} {account}"
        if acc_id is not None:
            parts += f" {acc_id}"
            if acc_flags is not None:
                parts += f" {acc_flags}"
        await self._send(parts)

    async def introduce_user(
        self,
        nick: str,
        username: str = "fakeuser",
        host: str = "fake.test.net",
        modes: str = "+i",
        realname: str = "Fake User",
        ip: str = "127.0.0.1",
    ) -> str:
        """Introduce a user originating from this server via a P10 N message.

        Format: <our_num> N <nick> <hops> <ts> <user> <host> <+modes> <b64ip> <numnick> :<realname>

        ``modes`` may include a following account token for +r, e.g. ``+ir AcctName``.
        ``ip`` is the user's IPv4 address as the hub should record it.

        Returns the new user's numnick.
        """
        client_num = self._next_client_num
        self._next_client_num += 1
        numnick = self._num + int_to_b64(client_num, 3)
        ts = int(time.time())
        ip64 = int_to_b64(int(ipaddress.IPv4Address(ip)), 6)
        await self._send(
            f"{self._num} N {nick} 1 {ts} {username} {host} {modes} "
            f"{ip64} {numnick} :{realname}"
        )
        self.users[nick.lower()] = {
            "nick": nick,
            "numnick": numnick,
            "username": username,
            "host": host,
            "modes": modes,
            "realname": realname,
        }
        return numnick

    async def send_join(self, numnick: str, channel: str, creation: int | None = None):
        """JOIN a channel from a P10 client numnick."""
        ts = creation if creation is not None else int(time.time())
        await self._send(f"{numnick} J {channel} {ts}")

    async def send_privmsg(self, from_numnick: str, target: str, text: str):
        """Send a PRIVMSG (P) from one of our users to a target numnick."""
        await self._send(f"{from_numnick} P {target} :{text}")

    async def send_notice(self, from_numnick: str, target: str, text: str):
        """Send a NOTICE (O) from one of our users to a target numnick."""
        await self._send(f"{from_numnick} O {target} :{text}")

    async def send_invite(self, from_numnick: str, target_nick: str, channel: str):
        """Send an INVITE (I) from one of our users to a target nick/channel.

        On a P11 link ms_invite() resolves the invitee by numnick (findNUser);
        on a P10 link by nickname.  When this link is P11 and we know the
        target's numnick (call wait_for_user first), address it by numnick.
        """
        target = target_nick
        if self.protocol >= 11:
            target = self.get_user_numnick(target_nick) or target_nick
        await self._send(f"{from_numnick} I {target} {channel}")

    async def wait_for_user(self, nick: str, timeout: float = 5.0) -> str:
        """Wait until a user with the given nick appears, return their numnick.

        Reads incoming messages (handling PINGs and NICKs) until the
        user is found or timeout expires.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            numnick = self.get_user_numnick(nick)
            if numnick:
                return numnick
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(
                    f"User {nick!r} not seen. Known: {list(self.users.keys())}"
                )
            try:
                await self._recv(timeout=min(remaining, 1.0))
            except asyncio.TimeoutError:
                continue

    async def recv_until(self, token: str, timeout: float = 5.0) -> list[str]:
        """Read lines until we see one with the given P10 token."""
        collected = []
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for {token}")
            line = await self._recv(timeout=remaining)
            collected.append(line)
            tok = self._get_token(line)
            if tok == token or strip_msg_tags(line).split()[0] == token:
                return collected

    async def drain_messages(self, timeout: float = 0.5):
        """Read and process any pending messages (handles PINGs, tracks NICKs)."""
        while True:
            try:
                await self._recv(timeout=timeout)
            except (asyncio.TimeoutError, TimeoutError):
                break

    # --- S:line / netconf / extension-reply helpers ---

    async def send_sline(
        self,
        pattern: str,
        msg_type: str = "A",
        active: bool = True,
        expire: int = 0,
        lastmod: int | None = None,
    ):
        """Inject an S-line via the P10 SLINE (SL) command.

        Wire format (from ms_sline):
            <our_num> SL <state> <lastmod> <expire> <type> :<pattern>
        where state is '+' (active) or '-' (inactive), and type is a
        combination of A/P/C/L/Q.
        """
        if lastmod is None:
            lastmod = _next_timestamp()
        state = "+" if active else "-"
        await self._send(
            f"{self._num} SL {state} {lastmod} {expire} {msg_type} :{pattern}"
        )

    async def send_config(self, key: str, value: str, timestamp: int | None = None):
        """Set a network configuration value via the P10 CONFIG (CF) command.

        Wire format (from ms_config):
            <our_num> CF <timestamp> <key> :<value>
        """
        if timestamp is None:
            timestamp = _next_timestamp()
        await self._send(f"{self._num} CF {timestamp} {key} :{value}")

    async def send_xreply(self, target: str, routing: str, reply: str):
        """Send an extension reply via the P10 XREPLY (XR) command.

        Wire format (from ms_xreply):
            <our_num> XR <target> <routing> :<reply>
        <target> is the numeric of the server that issued the XQUERY
        (the hub's server numeric), <routing> is e.g. "spam:<token>".
        """
        await self._send(f"{self._num} XR {target} {routing} :{reply}")

    async def wait_for_token(self, token: str, timeout: float = 5.0) -> str:
        """Read lines until one whose P10 token matches, and return it.

        Handles PINGs and NICK tracking while waiting.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for token {token}")
            line = await self._recv(timeout=remaining)
            if self._get_token(line) == token:
                return line
