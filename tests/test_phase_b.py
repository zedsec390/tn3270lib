#!/usr/bin/env python3
"""Phase B: color/highlight, HTML dumps, lock-on-AID, TLS certs, numeric fields.

    python3 -m unittest tests.test_phase_b -v
"""

import os
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tn3270lib
from tn3270.client import TN3270Timeout, TN3270KeyboardLocked
from tn3270.constants import (
    W, SFE, SA, SFE_FA, SFE_COLOR, XA_FGCOLOR, COLOR_RED, COLOR_BLUE,
    WCC_RESTORE, FA_NUMERIC, FA_PROTECTED, QR_COLOR, QR_HIGHLIGHTING,
    ENTER,
)
from tn3270.query import parse_query_reply, build_query_reply


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


class ColorAndHighlight(unittest.TestCase):

    def test_sfe_color_applies_to_following_data(self):
        tn = client()
        write_orders(tn, SFE, 2, SFE_FA, 0x40, SFE_COLOR, COLOR_RED, 0xC1, 0xC2)
        self.assertEqual(tn.cell_fg(1), COLOR_RED)
        self.assertEqual(tn.cell_fg(2), COLOR_RED)
        self.assertEqual(tn.buffer[1], 0xC1)

    def test_sa_color_on_graphic_text(self):
        tn = client()
        write_orders(tn, SA, XA_FGCOLOR, COLOR_BLUE, 0xC1)
        self.assertEqual(tn.cell_fg(0), COLOR_BLUE)
        self.assertEqual(tn.cell_hl(0), 0)

    def test_query_reply_includes_color_and_highlighting(self):
        payload = build_query_reply(24, 80, 24, 80, 'cp037')
        fields = parse_query_reply(payload)
        qcodes = [q for q, _ in fields]
        self.assertIn(QR_COLOR, qcodes)
        self.assertIn(QR_HIGHLIGHTING, qcodes)
        self.assertEqual(set(qcodes), set(fields[0][1]))


class ScreenDumps(unittest.TestCase):

    def test_save_screen_txt_and_html(self):
        tn = client()
        write_orders(tn, SFE, 2, SFE_FA, 0x40, SFE_COLOR, COLOR_RED,
                     *tn._str_to_ebcdic('RED'))
        with tempfile.TemporaryDirectory() as d:
            txt = os.path.join(d, 's.txt')
            html_path = os.path.join(d, 's.html')
            tn.save_screen(txt)
            tn.save_screen_html(html_path)
            with open(txt, encoding='utf-8') as fh:
                body = fh.read()
            self.assertIn('RED', body)
            with open(html_path, encoding='utf-8') as fh:
                markup = fh.read()
            self.assertIn('color-red', markup)
            self.assertIn('unprotected', markup)
            self.assertIn('<pre', markup)


class WaitTimeoutDump(unittest.TestCase):

    def test_timeout_attaches_screen_cursor_lock(self):
        tn = client()
        tn.buffer[0:5] = tn._str_to_ebcdic('HELLO')
        tn.cursor_addr = 80
        tn.keyboard_locked = True
        tn.aid = ENTER
        with self.assertRaises(TN3270Timeout) as ctx:
            tn.wait_for_text('NOPE', timeout=0)
        exc = ctx.exception
        self.assertIn('HELLO', str(exc))
        self.assertIn('HELLO', exc.screen)
        self.assertEqual(exc.cursor, (2, 1, 80))
        self.assertTrue(exc.keyboard_locked)
        self.assertEqual(exc.aid, ENTER)
        self.assertIn('keyboard_locked=True', str(exc))


class KeyboardLockOnAid(unittest.TestCase):

    def test_send_enter_while_locked_raises(self):
        tn = client()
        tn.keyboard_locked = True
        with self.assertRaises(TN3270KeyboardLocked):
            tn.send_enter()
        self.assertFalse(tn.sock.sent)

    def test_wcc_restore_then_aid_locks_again(self):
        tn = client()
        tn.process_3270(bytes([W, WCC_RESTORE]))
        self.assertFalse(tn.keyboard_locked)
        tn.send_enter()
        self.assertTrue(tn.keyboard_locked)
        self.assertTrue(tn.sock.sent)
        with self.assertRaises(TN3270KeyboardLocked):
            tn.send_pf(3)


class NumericField(unittest.TestCase):

    def test_letters_rejected(self):
        tn = client()
        tn.fa_buffer[0] = 0x40 | FA_NUMERIC
        tn.fa_buffer[10] = FA_PROTECTED
        tn.formatted = True
        with self.assertRaises(ValueError) as ctx:
            tn._type_ascii_at(1, 'ABC')
        self.assertIn('numeric', str(ctx.exception).lower())
        tn._type_ascii_at(1, '12')
        self.assertEqual(tn.find('12'), (1, 2))


class TlsClientCert(unittest.TestCase):

    def test_certfile_and_ssl_context_constructor(self):
        tn = tn3270lib.TN3270(certfile='/no/such/client.pem',
                              keyfile='/no/such/client.key')
        self.assertEqual(tn.certfile, '/no/such/client.pem')
        self.assertEqual(tn.keyfile, '/no/such/client.key')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tn2 = tn3270lib.TN3270(ssl_context=ctx)
        self.assertIs(tn2.ssl_context, ctx)


if __name__ == '__main__':
    unittest.main(verbosity=2)
