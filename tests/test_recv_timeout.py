#!/usr/bin/env python3
"""Offline tests for the receive loops in get_data()/get_all_data().

Every timeout has to end the loop no matter how it is worded, and no socket
behaviour may make the loop spin: each test fails on a wall-clock budget
instead of hanging the run.

    python3 -m unittest discover -s tests -v
"""

import os
import socket
import ssl
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tn3270lib

BUDGET = 5.0  # seconds; a spinning loop blows through this


class FakeSocket:
    """A socket whose recv() always does the same thing."""

    def __init__(self, behaviour, timeout=10):
        self.behaviour = behaviour
        self.calls = 0
        self.timeouts = []
        self._timeout = timeout

    def recv(self, _size):
        self.calls += 1
        raise_or_return = self.behaviour
        if isinstance(raise_or_return, BaseException):
            raise raise_or_return
        return raise_or_return

    def gettimeout(self):
        return self._timeout

    def settimeout(self, t):
        self._timeout = t
        self.timeouts.append(t)

    def sendall(self, _data):
        pass

    send = sendall

    def close(self):
        pass


def client_with(behaviour):
    tn = tn3270lib.TN3270()
    tn.sock = FakeSocket(behaviour)
    return tn


class RecvLoopTerminates(unittest.TestCase):

    def _run(self, method, behaviour):
        tn = client_with(behaviour)
        start = time.monotonic()
        method(tn)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BUDGET,
                        "%s did not terminate promptly (%.1fs)" % (method, elapsed))
        return tn, elapsed

    def test_get_all_data_bare_timeout(self):
        tn, _ = self._run(lambda t: t.get_all_data(), socket.timeout())
        self.assertEqual(tn.sock.calls, 1)

    def test_get_all_data_ssl_wording(self):
        # What a TLS socket actually raises on a read timeout.
        tn, _ = self._run(lambda t: t.get_all_data(),
                          socket.timeout('The read operation timed out'))
        self.assertEqual(tn.sock.calls, 1)

    def test_get_all_data_want_read(self):
        tn, _ = self._run(lambda t: t.get_all_data(), ssl.SSLWantReadError())
        self.assertEqual(tn.sock.calls, 1)

    def test_get_all_data_closed_socket(self):
        tn, _ = self._run(lambda t: t.get_all_data(), b'')
        self.assertEqual(tn.sock.calls, 1)

    def test_get_all_data_other_socket_error(self):
        tn, _ = self._run(lambda t: t.get_all_data(), OSError(54, 'Connection reset by peer'))
        self.assertEqual(tn.sock.calls, 1)

    def test_get_all_data_restores_timeout(self):
        tn, _ = self._run(lambda t: t.get_all_data(), socket.timeout())
        self.assertEqual(tn.sock.timeouts, [2, 10])

    def test_get_all_data_restores_timeout_on_exception(self):
        def boom():
            raise RuntimeError('boom')

        tn = client_with(b'\x00')
        tn.process_packets = boom
        with self.assertRaises(RuntimeError):
            tn.get_all_data()
        self.assertEqual(tn.sock.timeouts, [2, 10])

    def test_get_all_data_is_bounded(self):
        # A socket that never times out and never closes must still stop.
        tn = client_with(b'\x00')
        tn.process_packets = lambda: None
        start = time.monotonic()
        tn.get_all_data()
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BUDGET)
        self.assertLessEqual(tn.sock.calls, 200)

    def test_get_data_bare_timeout(self):
        tn, _ = self._run(lambda t: t.get_data(), socket.timeout())
        self.assertEqual(tn.sock.calls, 1)

    def test_get_data_ssl_wording(self):
        tn, _ = self._run(lambda t: t.get_data(),
                          socket.timeout('The read operation timed out'))
        self.assertEqual(tn.sock.calls, 1)

    def test_get_data_closed_socket(self):
        tn, _ = self._run(lambda t: t.get_data(), b'')
        self.assertEqual(tn.sock.calls, 1)

    def test_get_data_errno_socket_error(self):
        # e.args[0] is an int here: the old 'timed out' in err raised TypeError.
        tn, _ = self._run(lambda t: t.get_data(), OSError(54, 'Connection reset by peer'))
        self.assertEqual(tn.sock.calls, 1)

    def test_get_data_is_bounded(self):
        tn = client_with(b'\x00')
        tn.process_packets = lambda: None
        start = time.monotonic()
        tn.get_data()
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BUDGET)
        self.assertLessEqual(tn.sock.calls, 200)


if __name__ == '__main__':
    unittest.main(verbosity=2)
