#!/usr/bin/env python3
"""IAuth stub for nickname assignment tests.

Logs every line from the ircd to the file given as argv[1].  Client
nicknames drive stub behaviour:

  tmpuser       -> force nick to "finaluser", then approve
  set_<nick>    -> force nick to <nick>, then approve
  bad_<nick>    -> try to force invalid nick <nick>, then approve with D only
  collide       -> force nick "taken", then approve (for collision tests)

All other clients are approved on "n" without changing their nick.
"""

import sys


def main():
    logf = open(sys.argv[1], "a", buffering=1)

    def out(line):
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    # R: iauth is required; U: enable Undernet extensions (U/u/n/H/T).
    out("O RU")

    clients = {}
    for line in sys.stdin:
        line = line.rstrip("\r\n")
        logf.write(line + "\n")
        parts = line.split(" ")
        if len(parts) < 2:
            continue
        cid, cmd = parts[0], parts[1]
        if cmd == "C" and len(parts) >= 4:
            clients[cid] = (parts[2], parts[3])
        elif cmd == "n" and cid in clients:
            ip, port = clients[cid]
            nick = parts[2] if len(parts) >= 3 else ""
            if nick == "tmpuser":
                out(f"f {cid} {ip} {port} finaluser")
            elif nick.startswith("set_"):
                out(f"f {cid} {ip} {port} {nick[4:]}")
            elif nick.startswith("bad_"):
                out(f"f {cid} {ip} {port} {nick[4:]}")
            elif nick == "collide":
                out(f"f {cid} {ip} {port} taken")
            out(f"D {cid} {ip} {port}")
            clients.pop(cid, None)
        elif cmd == "D":
            clients.pop(cid, None)


if __name__ == "__main__":
    main()
