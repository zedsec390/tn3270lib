#!/usr/bin/env python3
"""Phase A: wait API, instance geometry/EWA, Query Reply builder, SBCS, fields.

    python3 -m unittest tests.test_phase_a -v
"""

import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tn3270lib
from tn3270.client import TN3270Timeout
from tn3270.constants import (
    EW, EWA, W, SBA, RA, IAC, TN_EOR, TN3270_DATA, TN3270E_DATA,
    AID_SF, SF_RP_QUERY, SF_RP_QLIST, BAD_ADDRESS, FA_PROTECTED, FA_MDT,
    QR_SUMMARY, QR_USABLE_AREA, QR_CHARACTER_SETS, QR_IMPLICIT_PARTITION,
)
from tn3270.ebcdic import resolve_codec, cgcsgid_of, normalize_codepage
from tn3270.query import parse_query_reply, build_query_reply

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACE = os.path.join(ROOT, 'traces', 'cics-mcmm.jsonl')


class CaptureSocket:
    def __init__(self):
        self.sent = bytearray()

    def sendall(self, data):
        self.sent.extend(data)

    send = sendall

    def recv(self, _size):
        raise socket.timeout('empty')

    def gettimeout(self):
        return None

    def settimeout(self, _t):
        pass

    def close(self):
        pass


class ScriptedSocket:
    """Inbound chunks, then socket.timeout. Records outbound bytes."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = bytearray()
        self._timeout = None

    def recv(self, _size):
        if not self.chunks:
            raise socket.timeout('script exhausted')
        return self.chunks.pop(0)

    def sendall(self, data):
        self.sent.extend(data)

    send = sendall

    def gettimeout(self):
        return self._timeout

    def settimeout(self, t):
        self._timeout = t

    def close(self):
        pass


def client(device_type=None, **kwargs):
    tn = tn3270lib.TN3270(device_type=device_type, **kwargs)
    tn.sock = CaptureSocket()
    return tn


def baddr14(addr):
    return bytes([(addr >> 8) & 0x3F, addr & 0xFF])


def _has_codec(name):
    try:
        resolve_codec(name)
        return True
    except LookupError:
        return False


class WaitAPI(unittest.TestCase):

    def test_already_satisfied_timeout_zero(self):
        tn = client()
        tn.buffer[0:5] = tn._str_to_ebcdic('HELLO')
        self.assertTrue(tn.wait_for_text('HELLO', timeout=0))
        tn.keyboard_locked = False
        self.assertTrue(tn.wait_unlock(timeout=0))
        tn.cursor_addr = 80
        self.assertTrue(tn.wait_cursor(row=2, col=1, timeout=0))
        self.assertTrue(tn.wait_cursor(addr=80, timeout=0))
        self.assertTrue(tn.wait_stable(quiet=0.3, timeout=0))

    def test_timeout_includes_what_and_snippet(self):
        tn = client()
        tn.buffer[0:5] = tn._str_to_ebcdic('HELLO')
        with self.assertRaises(TN3270Timeout) as ctx:
            tn.wait_for_text('NOPE', timeout=0)
        msg = str(ctx.exception)
        self.assertIn("text 'NOPE'", msg)
        self.assertIn('HELLO', msg)
        self.assertIsInstance(ctx.exception, TimeoutError)

    def test_unlock_and_cursor_timeout(self):
        tn = client()
        tn.keyboard_locked = True
        with self.assertRaises(TN3270Timeout) as ctx:
            tn.wait_unlock(timeout=0)
        self.assertIn('keyboard unlock', str(ctx.exception))
        tn.cursor_addr = 0
        with self.assertRaises(TN3270Timeout) as ctx:
            tn.wait_cursor(row=2, col=1, timeout=0)
        self.assertIn('cursor', str(ctx.exception))

    def test_wait_for_text_from_scripted_socket(self):
        tn = tn3270lib.TN3270()
        tn.state = TN3270_DATA
        hello = tn._str_to_ebcdic('HELLO')
        record = bytes([EW, 0xC3]) + hello + bytes([IAC, TN_EOR])
        tn.sock = ScriptedSocket([record])
        self.assertTrue(tn.wait_for_text('HELLO', timeout=2))
        self.assertIn('HELLO', tn._screen_ascii_flat())

    def test_cics_replay_wait_for_text(self):
        if not os.path.isfile(TRACE):
            self.skipTest('no CICS JSONL trace')
        sys.path.insert(0, os.path.join(ROOT, 'traces'))
        import replay
        tn, _sock = replay.replay(TRACE)
        if 'Mels Cargo' not in tn.get_screen():
            for text in replay.screens(tn):
                if 'Mels Cargo' in text:
                    break
            else:
                self.skipTest('CICS trace never painted Mels Cargo')
        self.assertTrue(tn.wait_for_text('Mels Cargo', timeout=0))


class GeometryEWA(unittest.TestCase):

    def test_model2_stays_24x80(self):
        tn = client('IBM-3278-2-E')
        self.assertEqual((tn.rows, tn.cols, tn.screen_size), (24, 80, 1920))
        self.assertEqual((tn.default_rows, tn.alt_rows), (24, 24))
        tn.process_3270(bytes([EWA, 0xC3]))
        self.assertEqual(tn.screen_size, 1920)
        self.assertEqual(len(tn.buffer), 1920)

    def test_model3_ewa_grows_ew_shrinks(self):
        tn = client('IBM-3278-3')
        self.assertEqual(tn.device_type, 'IBM-3278-3')
        self.assertEqual(tn.screen_size, 1920)
        self.assertEqual((tn.alt_rows, tn.alt_cols), (32, 80))
        status = tn.process_3270(bytes([EWA, 0xC3]))
        self.assertNotEqual(status, BAD_ADDRESS)
        self.assertEqual((tn.rows, tn.cols), (32, 80))
        self.assertEqual(tn.screen_size, 2560)
        self.assertEqual(len(tn.buffer), 2560)
        tn.process_3270(bytes([EW, 0xC3]))
        self.assertEqual((tn.rows, tn.cols, tn.screen_size), (24, 80, 1920))
        self.assertEqual(len(tn.buffer), 1920)

    def test_sba_27x132_within_3564(self):
        tn = client('IBM-3278-5')
        self.assertEqual((tn.alt_rows, tn.alt_cols), (27, 132))
        tn.process_3270(bytes([EWA, 0xC3]))
        self.assertEqual(tn.screen_size, 3564)
        status = tn.process_3270(bytes([W, 0xC3, SBA]) + baddr14(3563))
        self.assertNotEqual(status, BAD_ADDRESS)
        status = tn.process_3270(bytes([W, 0xC3, SBA]) + baddr14(3564))
        self.assertEqual(status, BAD_ADDRESS)
        status = tn.process_3270(bytes([W, 0xC3, RA]) + baddr14(3564) + bytes([0xC1]))
        self.assertEqual(status, BAD_ADDRESS)

    def test_sba_ra_past_model3_alt_is_bad(self):
        tn = client('IBM-3278-3')
        tn.process_3270(bytes([EWA, 0xC3]))
        self.assertNotEqual(
            tn.process_3270(bytes([W, 0xC3, SBA]) + baddr14(2559)), BAD_ADDRESS)
        self.assertEqual(
            tn.process_3270(bytes([W, 0xC3, SBA]) + baddr14(2560)), BAD_ADDRESS)
        self.assertEqual(
            tn.process_3270(bytes([W, 0xC3, RA]) + baddr14(2560) + bytes([0xC1])),
            BAD_ADDRESS)

    def test_get_screen_wraps_on_instance_cols(self):
        tn = client('IBM-3279-5')
        tn.process_3270(bytes([EWA, 0xC3]))
        text = tn.get_screen()
        self.assertEqual(text.count('\n'), 27)
        self.assertEqual(len(text), 27 * 133)

    def test_rowcol_helpers(self):
        tn = client()
        self.assertEqual(tn.rowcol_to_addr(1, 1), 0)
        self.assertEqual(tn.addr_to_rowcol(80), (2, 1))
        tn.process_3270(bytes([EWA, 0xC3]))  # model 2: still 80
        self.assertEqual(tn.rowcol_to_addr(24, 80), 1919)


class QueryReplyBuilder(unittest.TestCase):

    def _payload(self, tn):
        tn.state = TN3270E_DATA
        tn.sock = CaptureSocket()
        tn.read_partition(bytes([0xff, SF_RP_QUERY]))
        wire = bytes(tn.sock.sent)
        self.assertTrue(wire.endswith(bytes([IAC, TN_EOR])))
        self.assertFalse(wire.endswith(bytes([IAC, TN_EOR, IAC, TN_EOR])))
        # strip TN3270E header and undouble through EOR
        payload = bytearray()
        i = 5
        while i < len(wire):
            if wire[i] == IAC:
                if wire[i + 1] == IAC:
                    payload.append(IAC)
                    i += 2
                    continue
                if wire[i + 1] == TN_EOR:
                    break
            payload.append(wire[i])
            i += 1
        return bytes(payload)

    def test_length_prefixed_no_leftover(self):
        tn = client()
        payload = self._payload(tn)
        fields = parse_query_reply(payload)
        qcodes = [q for q, _ in fields]
        self.assertEqual(qcodes[0], QR_SUMMARY)
        self.assertEqual(set(qcodes), set(fields[0][1]))
        self.assertIn(0x86, qcodes)  # Color
        self.assertIn(0x87, qcodes)  # Highlighting
        by = dict(fields)
        ua = by[QR_USABLE_AREA]
        cols, rows = struct.unpack('>HH', ua[2:6])
        self.assertEqual((rows, cols), (24, 80))
        ip = by[QR_IMPLICIT_PARTITION]
        self.assertEqual(ip[2], 0x0b)
        def_cols, def_rows, alt_cols, alt_rows = struct.unpack('>HHHH', ip[5:13])
        self.assertEqual((def_rows, def_cols, alt_rows, alt_cols),
                         (24, 80, 24, 80))
        cs = by[QR_CHARACTER_SETS]
        gcsgid, cpgid = struct.unpack('>HH', cs[-4:])
        self.assertEqual((gcsgid, cpgid), cgcsgid_of(tn.codepage))

    def test_model3_implicit_partition_alt_32x80(self):
        tn = client('IBM-3278-3')
        payload = self._payload(tn)
        by = dict(parse_query_reply(payload))
        cols, rows = struct.unpack('>HH', by[QR_USABLE_AREA][2:6])
        self.assertEqual((rows, cols), (32, 80))
        ip = by[QR_IMPLICIT_PARTITION]
        def_cols, def_rows, alt_cols, alt_rows = struct.unpack('>HHHH', ip[5:13])
        self.assertEqual((def_rows, def_cols), (24, 80))
        self.assertEqual((alt_rows, alt_cols), (32, 80))

    def test_qlist_same_chain(self):
        a = build_query_reply(24, 80, 24, 80, 'cp037')
        tn = client()
        tn.state = TN3270_DATA
        tn.read_partition(bytes([0xff, SF_RP_QLIST]))
        self.assertTrue(bytes(tn.sock.sent).startswith(bytes((AID_SF,))))
        parse_query_reply(a)

    def test_iac_doubling_when_ff_present(self):
        tn = client()
        tn.state = TN3270_DATA
        tn.send_tn3270(bytes([AID_SF, 0xff, 0x01]))
        wire = bytes(tn.sock.sent)
        self.assertIn(b'\xff\xff\x01', wire)
        self.assertTrue(wire.endswith(bytes([IAC, TN_EOR])))

    def test_builder_has_no_trailing_eor(self):
        payload = build_query_reply(24, 80, 32, 80, 'cp037')
        self.assertEqual(payload[0], AID_SF)
        self.assertFalse(payload.endswith(bytes([IAC, TN_EOR])))
        parse_query_reply(payload)


@unittest.skipUnless(_has_codec('cp273'), 'cp273 codec not installed')
class CodepageSBCS(unittest.TestCase):

    def test_cp273_round_trip_and_find(self):
        tn = tn3270lib.TN3270(codepage='cp273')
        self.assertEqual(normalize_codepage('273'), 'cp273')
        raw = tn._str_to_ebcdic('Ä')
        self.assertEqual(tn._ebcdic_to_str(raw), 'Ä')
        tn.buffer[0:len(raw)] = raw
        self.assertEqual(tn.find('Ä'), (0, len('Ä') - 1))
        self.assertIn('Ä', tn.get_screen())
        gcsgid, cpgid = cgcsgid_of(tn.codepage)
        self.assertEqual(cpgid, 273)
        payload = build_query_reply(24, 80, 24, 80, tn.codepage)
        cs = dict(parse_query_reply(payload))[QR_CHARACTER_SETS]
        self.assertEqual(struct.unpack('>HH', cs[-4:]), (gcsgid, cpgid))

    def test_accepts_bare_037(self):
        tn = tn3270lib.TN3270(codepage='037')
        self.assertTrue(tn.codepage.lower().startswith('cp037') or
                        tn.codepage == 'cp037')


class MissingCodepage(unittest.TestCase):

    def test_unknown_page_mentions_i18n_extra(self):
        with self.assertRaises(LookupError) as ctx:
            resolve_codec('cp99999')
        self.assertIn('tn3270lib[i18n]', str(ctx.exception))


class FieldAPI(unittest.TestCase):

    def _screen(self):
        tn = client()
        # Protected "USER" + 4-char input, protected "PASSWORD" + 8-char input.
        tn.fa_buffer[0] = FA_PROTECTED
        tn.buffer[1:5] = tn._str_to_ebcdic('USER')
        tn.fa_buffer[5] = 0x40
        tn.fa_buffer[10] = FA_PROTECTED
        tn.buffer[11:19] = tn._str_to_ebcdic('PASSWORD')
        tn.fa_buffer[19] = 0x40
        tn.fa_buffer[28] = FA_PROTECTED
        tn.formatted = True
        tn.cursor_addr = 6
        return tn

    def test_field_fill_tab(self):
        tn = self._screen()
        f = tn.field('USER')
        self.assertEqual(f.start, 6)
        self.assertEqual(f.row, 1)
        self.assertFalse(f.protected)
        tn.fill('user', 'AB')
        self.assertTrue(tn.fa_buffer[5] & FA_MDT)
        self.assertEqual(tn.find('AB'), (6, 7))
        nxt = tn.tab()
        self.assertEqual(nxt, 20)
        self.assertEqual(tn.field('Password').start, 20)
        tn.type('SECRET', field='PASSWORD')
        self.assertIn('SECRET', tn.field('PASSWORD').value)
        all_fields = tn.fields(unprotected_only=False)
        labels = [x.label for x in all_fields if x.protected]
        self.assertTrue(any('USER' in x for x in labels))

    def test_missing_label(self):
        tn = self._screen()
        with self.assertRaises(KeyError):
            tn.field('NO-SUCH')


class Exports(unittest.TestCase):

    def test_timeout_exported(self):
        import tn3270
        self.assertIs(tn3270.TN3270Timeout, tn3270lib.TN3270Timeout)
        self.assertIn('TN3270Timeout', tn3270.__all__)


if __name__ == '__main__':
    unittest.main(verbosity=2)
