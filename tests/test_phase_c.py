#!/usr/bin/env python3
"""Phase C: BIND parse, SYSREQ/SSCP-LU, NVT, seq, Set Reply Mode, reconnect.

    python3 -m unittest tests.test_phase_c -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tn3270lib
from tn3270.constants import (
    W, WSF, RM, SFE, SFE_FA, SFE_COLOR, COLOR_RED, SF_SET_REPLY_MODE,
    SF_SRM_FIELD, SF_SRM_XFIELD, ALWAYS_RESPONSE, DT_BIND_IMAGE, DT_UNBIND,
    DT_SSCP_LU_DATA, DT_NVT_DATA, DT_REQUEST, DT_3270_DATA, TN3270E_DATA,
    TN3270_DATA, TN3270E_FN_RESPONSES, TN3270E_FN_SYSREQ, TN3270E_FN_BIND_IMAGE,
    options, SYSREQ, IAC, TN_EOR, FA_MDT,
)


class CaptureSocket:
    def __init__(self):
        self.sent = bytearray()

    def sendall(self, data):
        self.sent.extend(data)

    send = sendall

    def recv(self, _size):
        return b''

    def settimeout(self, _t):
        pass

    def close(self):
        pass


def client():
    tn = tn3270lib.TN3270()
    tn.sock = CaptureSocket()
    return tn


def write_orders(tn, *parts):
    data = bytearray([W, 0x00])
    for part in parts:
        if isinstance(part, int):
            data.append(part)
        else:
            data.extend(part)
    return tn.process_3270(bytes(data))


class BindImage(unittest.TestCase):

    def test_short_bind_stored_and_acked(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.tn3270e_functions = {TN3270E_FN_RESPONSES}
        tn.tn_buffer = bytearray([DT_BIND_IMAGE, ALWAYS_RESPONSE, 0, 0, 0, 0x99])
        tn.process_data()
        self.assertEqual(tn.bind_image, b'\x99')
        self.assertEqual(tn.buffer[0], 0)
        self.assertTrue(tn.sock.sent)

    def test_unbind_clears_bind(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.tn3270e_functions = {TN3270E_FN_RESPONSES}
        tn.bind_image = b'\x31\x00'
        tn.bind = {'plu': 'TSO', 'raw': tn.bind_image}
        tn.tn_buffer = bytearray([DT_UNBIND, ALWAYS_RESPONSE, 0, 0, 0, 0x02])
        tn.process_data()
        self.assertEqual(tn.bind_image, b'')
        self.assertEqual(tn.bind.get('plu'), '')
        self.assertTrue(tn.sock.sent)

    def test_odd_bind_does_not_crash(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.tn_buffer = bytearray([DT_BIND_IMAGE, 0, 0, 0, 0])
        tn.process_data()
        self.assertEqual(tn.bind_image, b'')


class SysreqSscp(unittest.TestCase):

    def test_sysreq_function_sends_tn3270e_request(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.tn3270e_functions = {TN3270E_FN_RESPONSES, TN3270E_FN_SYSREQ}
        tn.sysreq()
        wire = bytes(tn.sock.sent)
        self.assertEqual(wire[0], DT_REQUEST)
        self.assertNotEqual(wire[0:1], bytes([SYSREQ]))
        self.assertTrue(tn.sscp_mode)
        self.assertTrue(wire.endswith(bytes([IAC, TN_EOR])))

    def test_inbound_sscp_populates_get_sscp(self):
        tn = client()
        tn.state = TN3270E_DATA
        hello = tn._str_to_ebcdic('HELLO')
        tn.tn_buffer = bytearray([DT_SSCP_LU_DATA, 0, 0, 0, 0]) + bytearray(hello)
        tn.process_data()
        self.assertIn('HELLO', tn.get_sscp())
        self.assertTrue(tn.sscp_mode)
        self.assertEqual(tn.buffer[0], 0)

    def test_send_aid_sysreq_without_function_is_3270_aid(self):
        tn = client()
        tn.state = TN3270_DATA
        tn.send_aid('SYSREQ')
        wire = bytes(tn.sock.sent)
        self.assertEqual(wire[0], SYSREQ)
        self.assertNotEqual(wire[0], DT_REQUEST)

    def test_functions_request_accepts_sysreq_not_bind_image(self):
        tn = client()
        tn.sb_options = bytearray([
            options['TN3270E'], 0x03, 0x07,
            TN3270E_FN_BIND_IMAGE, TN3270E_FN_RESPONSES, TN3270E_FN_SYSREQ, 0xf0,
        ])
        tn.negotiate_tn3270()
        wire = bytes(tn.sock.sent)
        self.assertIn(bytes([TN3270E_FN_RESPONSES]), wire)
        self.assertIn(bytes([TN3270E_FN_SYSREQ]), wire)
        self.assertNotIn(bytes([0x03, 0x04, TN3270E_FN_BIND_IMAGE]), wire)
        self.assertEqual(tn.tn3270e_functions,
                         {TN3270E_FN_RESPONSES, TN3270E_FN_SYSREQ})


class NvtBuffer(unittest.TestCase):

    def test_nvt_data_not_painted_on_3270_screen(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.tn_buffer = bytearray([DT_NVT_DATA, 0, 0, 0, 0]) + bytearray(b'NVT-HI')
        tn.process_data()
        self.assertIn('NVT-HI', tn.get_nvt())
        self.assertEqual(tn.buffer[0], 0)
        self.assertNotIn('NVT-HI', tn.get_screen())

    def test_pre3270_telnet_goes_to_nvt(self):
        tn = client()
        tn.state = 0
        for b in b'hi':
            tn.ts_processor(b)
        self.assertIn('hi', tn.get_nvt())
        self.assertEqual(tn.buffer[0], 0)


class SequenceNumbers(unittest.TestCase):

    def test_outbound_headers_increment_seq(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.send_tn3270(b'\x00')
        tn.send_tn3270(b'\x00')
        wire = bytes(tn.sock.sent)
        recs = wire.split(bytes([IAC, TN_EOR]))
        recs = [r for r in recs if r]
        self.assertGreaterEqual(len(recs), 2)
        self.assertEqual(recs[0][:5], bytes([DT_3270_DATA, 0, 0, 0, 0]))
        self.assertEqual(recs[1][:5], bytes([DT_3270_DATA, 0, 0, 0, 1]))


class SetReplyMode(unittest.TestCase):

    def test_extended_field_rm_includes_sfe_color(self):
        tn = client()
        write_orders(tn, SFE, 2, SFE_FA, 0x40, SFE_COLOR, COLOR_RED, 0xC1)
        tn.fa_buffer[0] = tn.fa_buffer[0] | FA_MDT
        tn.process_3270(bytes([
            WSF, 0x00, 0x05, SF_SET_REPLY_MODE, 0xff, SF_SRM_XFIELD,
        ]))
        self.assertEqual(tn.reply_mode, SF_SRM_XFIELD)
        tn.sock.sent = bytearray()
        tn.process_3270(bytes([RM]))
        wire = bytes(tn.sock.sent)
        self.assertIn(bytes([SFE]), wire)
        self.assertIn(bytes([SFE_COLOR, COLOR_RED]), wire)

        tn.reply_mode = SF_SRM_FIELD
        tn.sock.sent = bytearray()
        tn.process_3270(bytes([RM]))
        field_wire = bytes(tn.sock.sent)
        self.assertNotIn(bytes([SFE]), field_wire)


class Reconnect(unittest.TestCase):

    def test_reconnect_resets_in_3270(self):
        tn = tn3270lib.TN3270()
        tn.sock = CaptureSocket()
        tn.host = 'example.invalid'
        tn.port = 23
        tn._in_3270 = True
        tn.tn3270e_functions = {TN3270E_FN_RESPONSES, TN3270E_FN_SYSREQ}
        tn.bind_image = b'\x31'
        tn.sscp_mode = True
        called = []

        def fake_initiate(host, port=0, timeout=5):
            called.append((host, port))
            return True

        tn.initiate = fake_initiate
        self.assertTrue(tn.reconnect())
        self.assertFalse(tn._in_3270)
        self.assertEqual(tn.tn3270e_functions, set())
        self.assertEqual(tn.bind_image, b'')
        self.assertFalse(tn.sscp_mode)
        self.assertEqual(called, [('example.invalid', 23)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
