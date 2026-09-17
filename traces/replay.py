#!/usr/bin/env python3
"""Replay a recorded TN3270 session against tn3270lib without a host.

Traces are JSONL, one record per line: {"dir": "<"|">", "hex": "..."} where
"<" is host-to-client. Outbound records are kept for reference but are not
checked during replay, so a trace stays usable when client behaviour changes.

    python3 traces/replay.py traces/netspi-logo-tso.jsonl
    python3 traces/replay.py traces/cics-mcmm.jsonl --all
    python3 traces/replay.py traces/cics-mcmm.jsonl --screens 4

Without --all or --screens only the first screen is printed. A multi-screen
trace is stepped by feeding the client the rest of the host records, which is
what next_screen() does.
"""

import json
import socket
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tn3270lib


class ReplaySocket:
    def __init__(self, inbound):
        self.inbound = list(inbound)
        self.sent = []

    def recv(self, _size):
        if not self.inbound:
            raise socket.timeout("replay exhausted")
        return self.inbound.pop(0)

    def sendall(self, data):
        self.sent.append(bytes(data))

    send = sendall

    def settimeout(self, _t):
        pass

    def close(self):
        pass


def load(path):
    inbound = []
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            if rec["dir"] == "<":
                inbound.append(bytes.fromhex(rec["hex"]))
    return inbound


def replay(path):
    tn = tn3270lib.TN3270()
    sock = ReplaySocket(load(path))
    tn.connect = lambda *a, **kw: (setattr(tn, "sock", sock), True)[1]
    tn.initiate("replay", 23)
    return tn, sock


def next_screen(tn):
    """Feed the client more host records until the next screen is painted.

    Returns True when another screen was painted, False once the trace is
    exhausted (ReplaySocket then raises a timeout, which get_data() treats as
    the end of the data).
    """
    tn.get_data()
    return bool(tn.first_screen)


def screens(tn, limit=None):
    """Yield each screen after the first one; limit None means until exhausted."""
    produced = 0
    while limit is None or produced < limit:
        if not next_screen(tn):
            return
        produced += 1
        yield tn.get_screen()


USAGE = "usage: replay.py [trace.jsonl] [--all | --screens N]"


def main(argv):
    path = None
    total = 1  # None means every screen in the trace
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--all":
            total = None
        elif arg == "--screens":
            i += 1
            if i >= len(argv):
                print(USAGE, file=sys.stderr)
                return 2
            total = int(argv[i])
        elif arg in ("-h", "--help"):
            print(USAGE)
            return 0
        elif arg.startswith("-"):
            print(USAGE, file=sys.stderr)
            return 2
        else:
            path = arg
        i += 1

    if path is None:
        path = os.path.join(os.path.dirname(__file__), "netspi-logo-tso.jsonl")

    tn, sock = replay(path)
    print("device type:", tn.connected_dtype, "| LU:", tn.get_lu())
    print("formatted:", tn.formatted, "| state:", tn3270lib.WORD_STATE[tn.state])
    print(tn.get_screen())

    n = 1
    for screen in screens(tn, None if total is None else max(total - 1, 0)):
        n += 1
        print("--- screen %d ---" % n)
        print(screen)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
