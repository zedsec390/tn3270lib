#!/usr/bin/env python3
"""Unit tests for remaining review findings (AID/RM, TLS, IAC, IND$FILE, packaging).

    python3 -m unittest tests.test_review_rest -v
"""

import os
import ssl
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tn3270lib
from tn3270.constants import (
    ENTER, SBA, IAC, TN_EOR, TELNET_NOP, SB, SE, SEND, DO,
    options, DEVICE_TYPE, FA_MDT, TN3270_DATA, ALWAYS_RESPONSE,
    DT_BIND_IMAGE, TN3270E_DATA, TN3270E_FN_RESPONSES, TN3270E_FN_BIND_IMAGE,
    TR_OPEN_REQ,
)
from tn3270.indfile import _valid_dataset
from tn3270.transport import _bytes


class CaptureSocket:
    def __init__(self):
        self.sent = bytearray()
        self.closed = False

    def sendall(self, data):
        self.sent.extend(data)

    send = sendall

    def recv(self, _size):
        return b''

    def gettimeout(self):
        return None

    def settimeout(self, _t):
        pass

    def close(self):
        self.closed = True


def client():
    tn = tn3270lib.TN3270()
    tn.sock = CaptureSocket()
    tn.state = TN3270_DATA
    return tn


class AidReadModified(unittest.TestCase):

    def _mdt_field(self, tn):
        tn.formatted = True
        tn.fa_buffer[0] = 0x40
        tn.fa_buffer[10] = 0xF0
        tn.cursor_addr = 1
        tn.buffer[1] = 0xC1
        tn.buffer[2] = 0xC2
        tn._set_mdt_at(1)

    def test_send_enter_includes_sba_and_field_data(self):
        tn = client()
        self._mdt_field(tn)
        tn.send_enter()
        wire = bytes(tn.sock.sent)
        self.assertEqual(wire[0], ENTER)
        self.assertIn(bytes([SBA]) + tn.ENCODE_BADDR(1), wire)
        self.assertIn(b'\xc1\xc2', wire)

    def test_send_pf_includes_sba_and_field_data(self):
        tn = client()
        self._mdt_field(tn)
        tn.send_pf(3)
        wire = bytes(tn.sock.sent)
        self.assertIn(bytes([SBA]) + tn.ENCODE_BADDR(1), wire)
        self.assertIn(b'\xc1\xc2', wire)

    def test_send_pf_zero_rejected(self):
        tn = client()
        self.assertFalse(tn.send_pf(0))
        self.assertFalse(tn.sock.sent)

    def test_send_location_writes_then_rm(self):
        tn = client()
        tn.formatted = True
        tn.fa_buffer[0] = 0x40
        tn.fa_buffer[10] = 0xF0
        tn.send_location(1, 'AB')
        self.assertEqual(tn.buffer[1], 0xC1)
        self.assertEqual(tn.fa_buffer[0] & FA_MDT, FA_MDT)
        wire = bytes(tn.sock.sent)
        self.assertEqual(wire[0], ENTER)
        self.assertIn(bytes([SBA]) + tn.ENCODE_BADDR(1), wire)


class TransportTlsAndProbe(unittest.TestCase):

    def test_require_tls_does_not_fall_back_to_plaintext(self):
        class DummyRaw:
            def settimeout(self, _t):
                pass

            def close(self):
                pass

        class BoomCtx:
            def wrap_socket(self, *a, **k):
                raise ssl.SSLError('handshake failed')

        calls = []

        def fake_conn(*a, **k):
            calls.append(a)
            return DummyRaw()

        tn = tn3270lib.TN3270()
        tn.require_tls = True
        with patch('tn3270.transport.socket.create_connection', fake_conn):
            with patch('tn3270.transport._make_ssl_context', lambda verify=False, **k: BoomCtx()):
                self.assertFalse(tn.connect('example.invalid', 23))
        self.assertEqual(len(calls), 1)
        self.assertIsNone(tn.sock)

    def test_default_does_not_fall_back_either(self):
        class DummyRaw:
            def settimeout(self, _t):
                pass

            def close(self):
                pass

        class BoomCtx:
            def wrap_socket(self, *a, **k):
                raise ssl.SSLError('handshake failed')

        calls = []

        def fake_conn(*a, **k):
            calls.append(a)
            return DummyRaw()

        tn = tn3270lib.TN3270()
        with patch('tn3270.transport.socket.create_connection', fake_conn):
            with patch('tn3270.transport._make_ssl_context', lambda verify=False, **k: BoomCtx()):
                self.assertFalse(tn.connect('example.invalid', 23))
        self.assertEqual(len(calls), 1)

    def test_check_tn3270_concatenated_options(self):
        payload = _bytes(IAC, DO, options['TN3270E'], IAC, DO, options['BINARY'])

        class ProbeSock:
            def __init__(self):
                self.closed = False

            def recv(self, _n):
                return payload

            def sendall(self, _d):
                pass

            def close(self):
                self.closed = True

        tn = tn3270lib.TN3270()
        sock = ProbeSock()
        tn._open_socket = lambda *a, **k: (sock, False)
        self.assertTrue(tn.check_tn3270('h', 23))
        self.assertTrue(sock.closed)


class TelnetIacAndTn3270e(unittest.TestCase):

    def test_iac_nop_returns_to_data_state(self):
        tn = client()
        tn.telnet_state = 0
        tn.ts_processor(IAC)
        self.assertEqual(tn.telnet_state, 1)
        tn.ts_processor(TELNET_NOP)
        self.assertEqual(tn.telnet_state, 0)
        tn.ts_processor(0x40)
        self.assertIn(0x40, tn.tn_buffer)
        self.assertEqual(tn.telnet_state, 0)

    def test_iac_iac_inside_sb(self):
        tn = client()
        tn.telnet_state = 0
        tn.ts_processor(IAC)
        tn.ts_processor(SB)
        tn.ts_processor(options['TTYPE'])
        tn.ts_processor(IAC)
        tn.ts_processor(IAC)
        self.assertEqual(tn.telnet_state, 6)  # TNS_SB
        self.assertEqual(tn.sb_options[-1], IAC)
        tn.ts_processor(SEND)
        tn.ts_processor(IAC)
        tn.ts_processor(SE)
        self.assertEqual(tn.telnet_state, 0)

    def test_bind_image_ignored_and_acked_when_responses_on(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.tn3270e_functions = {TN3270E_FN_RESPONSES}
        tn.tn_buffer = bytearray([DT_BIND_IMAGE, ALWAYS_RESPONSE, 0, 0, 0, 0x99])
        tn.process_data()
        wire = bytes(tn.sock.sent)
        self.assertTrue(wire)
        self.assertEqual(tn.buffer[0], 0)  # did not treat payload as 3270 data

    def test_functions_request_does_not_echo_bind_image(self):
        tn = client()
        tn.sb_options = bytearray([
            options['TN3270E'], 0x03, 0x07,  # FUNCTIONS REQUEST
            TN3270E_FN_BIND_IMAGE, TN3270E_FN_RESPONSES, SE,
        ])
        tn.negotiate_tn3270()
        wire = bytes(tn.sock.sent)
        self.assertIn(bytes([TN3270E_FN_RESPONSES]), wire)
        # IS payload must not include BIND_IMAGE.
        self.assertNotIn(bytes([0x03, 0x04, TN3270E_FN_BIND_IMAGE]), wire)

    def test_in3270_does_not_wipe_existing_screen(self):
        tn = client()
        tn.client_options[options['TTYPE']] = True
        tn.client_options[options['BINARY']] = True
        tn.server_options[options['BINARY']] = True
        tn.server_options[options['EOR']] = True
        tn.buffer[0] = 0xC1
        tn._in_3270 = True
        tn.state = TN3270_DATA
        tn.in3270()
        self.assertEqual(tn.buffer[0], 0xC1)


class IndfileAndClientApi(unittest.TestCase):

    def test_abort_does_not_typeerror(self):
        tn = client()
        tn.abort(TR_OPEN_REQ)
        self.assertTrue(tn.sock.sent)

    def test_rejected_dataset_name(self):
        self.assertFalse(_valid_dataset("FOO; LISTC"))
        self.assertFalse(_valid_dataset("A';LOGON"))
        self.assertFalse(_valid_dataset("name with spaces"))
        self.assertTrue(_valid_dataset("'PHIL.TN3270.TEXT'"))
        self.assertTrue(_valid_dataset("PHIL.TN3270.TEXT"))
        tn = client()
        self.assertFalse(tn.send_ascii_file("FOO;LISTC", "/tmp/x"))

    def test_disconnect_then_send_no_attributeerror(self):
        tn = client()
        tn.disconnect()
        self.assertIsNone(tn.sock)
        tn.send_data(b'x')  # must not raise

    def test_context_manager_closes(self):
        with tn3270lib.TN3270() as tn:
            tn.sock = CaptureSocket()
            sock = tn.sock
        self.assertIsNone(tn.sock)
        self.assertTrue(sock.closed)

    def test_init_host_failure_raises(self):
        with patch.object(tn3270lib.TN3270, 'initiate', return_value=False):
            with self.assertRaises(ConnectionError):
                tn3270lib.TN3270(host='nope.example')

    def test_lu_aliases(self):
        tn = client()
        tn.set_lu('TSO0001')
        self.assertEqual(tn.get_LU(), 'TSO0001')
        tn.set_LU('TSO0002')
        self.assertEqual(tn.get_lu(), 'TSO0002')

    def test_device_type_default(self):
        self.assertEqual(DEVICE_TYPE, 'IBM-3278-2-E')
        tn = tn3270lib.TN3270(device_type='IBM-3279-2-E')
        self.assertEqual(tn.device_type, 'IBM-3279-2-E')

    def test_package_all(self):
        import tn3270
        self.assertIn('TN3270', tn3270.__all__)
        self.assertIn('TN3270Timeout', tn3270.__all__)
        self.assertIn('TN3270KeyboardLocked', tn3270.__all__)
        self.assertIs(tn3270.TN3270, tn3270lib.TN3270)
        self.assertIs(tn3270.TN3270Timeout, tn3270lib.TN3270Timeout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
