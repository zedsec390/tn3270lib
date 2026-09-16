#!/usr/bin/env python3
"""Replay a recorded TN3270 session against tn3270lib without a host.

Traces are JSONL, one record per line: {"dir": "<"|">", "hex": "..."} where
"<" is host-to-client. Outbound records are kept for reference but are not
checked during replay, so a trace stays usable when client behaviour changes.

    python3 traces/replay.py traces/netspi-logo-tso.jsonl
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


if __name__ == "__main__":
    tn, sock = replay(sys.argv[1] if len(sys.argv) > 1 else
                      os.path.join(os.path.dirname(__file__), "netspi-logo-tso.jsonl"))
    print("device type:", tn.connected_dtype, "| LU:", tn.get_lu())
    print("formatted:", tn.formatted, "| state:", tn3270lib.WORD_STATE[tn.state])
    print(tn.get_screen())
