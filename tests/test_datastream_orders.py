#!/usr/bin/env python3
"""Offline tests for 3270 write-order parsing and Query Reply framing.

These cover host-triggered hangs (RA/EUA), operand consumption (RA/GE/MF),
truncated records, and IAC doubling of the Read Partition Query Reply.

    python3 -m unittest tests.test_datastream_orders -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tn3270lib
from tn3270.constants import (
    W, WSF, RA, EUA, GE, MF, SBA, SFE, IC, EAU, RM, RMA,
    BAD_ADDRESS, BAD_COMMAND, PDS_BAD_CMD, NO_OUTPUT, OUTPUT,
    SCREEN_SIZE, IAC, TN_EOR, TN3270E_DATA, TN3270_DATA,
    AID_SF, SF_RP_QUERY, options, TN3270E_SEND, FA_PROTECTED, FA_MDT,
    ENTER, CLEAR,
)

BUDGET = 2.0  # seconds; an unbounded RA/EUA loop blows through this


class CaptureSocket:
    """Records every sendall() payload."""

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


def baddr14(addr):
    """14-bit buffer address (high bits of byte1 clear)."""
    return bytes([(addr >> 8) & 0x3F, addr & 0xFF])


def write_orders(tn, *parts):
    """Run a Write command built from ints/bytes parts; return process_3270 status."""
    data = bytearray([W, 0x00])
    for part in parts:
        if isinstance(part, int):
            data.append(part)
        else:
            data.extend(part)
    return tn.process_3270(bytes(data))


def undouble_until_eor(wire, header_len=0):
    """Undouble IAC in the TN3270 payload; return (payload, eor_index)."""
    payload = bytearray()
    i = header_len
    while i < len(wire):
        if wire[i] == IAC:
            if i + 1 >= len(wire):
                raise AssertionError('dangling IAC at end of wire')
            nxt = wire[i + 1]
            if nxt == IAC:
                payload.append(IAC)
                i += 2
                continue
            if nxt == TN_EOR:
                return bytes(payload), i
            raise AssertionError(
                'undoubled IAC command 0x%02x at offset %d (not EOR)' % (nxt, i))
        payload.append(wire[i])
        i += 1
    raise AssertionError('wire missing trailing IAC EOR')


class RepeatToAddress(unittest.TestCase):

    def test_ra_outside_screen_does_not_hang(self):
        tn = client()
        start = time.monotonic()
        # 14-bit 1920 is on the screen boundary; DECODE_BADDR can also
        # return values up to 16383.
        status = write_orders(tn, RA, baddr14(1920), 0xC1)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BUDGET,
                        'RA to address 1920 hung (%.1fs)' % elapsed)
        self.assertEqual(status, BAD_ADDRESS)

        tn = client()
        start = time.monotonic()
        status = write_orders(tn, RA, baddr14(16383), 0xC1)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BUDGET,
                        'RA to address 16383 hung (%.1fs)' % elapsed)
        self.assertEqual(status, BAD_ADDRESS)

    def test_eua_outside_screen_does_not_hang(self):
        tn = client()
        start = time.monotonic()
        status = write_orders(tn, EUA, baddr14(1920))
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, BUDGET,
                        'EUA to address 1920 hung (%.1fs)' % elapsed)
        self.assertEqual(status, BAD_ADDRESS)

    def test_ra_stop_equals_current_fills_whole_buffer(self):
        tn = client()
        self.assertEqual(tn.buffer_address, 0)
        status = write_orders(tn, RA, tn.ENCODE_BADDR(0), 0xC1)
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(tn.buffer.count(0xC1), SCREEN_SIZE)
        self.assertEqual(tn.buffer_address, 0)

    def test_ra_space_is_exclusive_of_stop_and_following_orders_parse(self):
        tn = client()
        stop = 5
        status = write_orders(tn, RA, tn.ENCODE_BADDR(stop), 0x40, IC)
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(bytes(tn.buffer[:stop]), b'\x40' * stop)
        self.assertEqual(tn.buffer[stop], 0)
        self.assertEqual(tn.buffer_address, stop)
        self.assertEqual(tn.cursor_addr, stop)

    def test_ra_nul_operand_is_consumed_not_treated_as_order(self):
        tn = client()
        stop = 3
        status = write_orders(tn, RA, tn.ENCODE_BADDR(stop), 0x00, 0xC1)
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(bytes(tn.buffer[:stop]), b'\x00' * stop)
        # If 0x00 were re-read as a NUL order, cell `stop` would be 0x40
        # (format-control blank) and 0xC1 would land at stop+1.
        self.assertEqual(tn.buffer[stop], 0xC1)
        self.assertEqual(tn.buffer_address, stop + 1)


class GraphicEscapeAndModifyField(unittest.TestCase):

    def test_ge_consumes_graphic_then_following_data(self):
        tn = client()
        status = write_orders(tn, GE, 0xC1, 0xC2)
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(tn.buffer[0], 0xC1)
        self.assertEqual(tn.buffer[1], 0xC2)
        self.assertEqual(tn.buffer_address, 2)

    def test_ge_then_sba_still_parses(self):
        tn = client()
        status = write_orders(tn, GE, 0xC1, SBA, tn.ENCODE_BADDR(10), 0xC2)
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(tn.buffer[0], 0xC1)
        self.assertEqual(tn.buffer[10], 0xC2)
        self.assertEqual(tn.buffer_address, 11)

    def test_mf_skips_type_value_pairs_without_moving_address(self):
        tn = client()
        start_addr = tn.buffer_address
        # Two type/value pairs, then a data character that must still parse.
        status = write_orders(tn, MF, 2, 0xc0, 0x40, 0x41, 0x00, 0xC1)
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(tn.buffer[start_addr], 0xC1)
        self.assertEqual(tn.buffer_address, start_addr + 1)
        self.assertEqual(tn.buffer[start_addr + 1], 0)


class TruncatedRecords(unittest.TestCase):

    def test_truncated_sba_no_indexerror(self):
        tn = client()
        status = write_orders(tn, SBA, 0x40)  # one address byte missing
        self.assertEqual(status, BAD_ADDRESS)

    def test_truncated_sfe_no_indexerror(self):
        tn = client()
        # Claims two attribute pairs but only supplies one extra byte.
        status = write_orders(tn, SFE, 2, 0xc0)
        self.assertEqual(status, BAD_COMMAND)

    def test_wsf_shorter_than_two_bytes(self):
        tn = client()
        status = tn.process_3270(bytes([WSF, 0x00]))
        self.assertEqual(status, PDS_BAD_CMD)

    def test_wsf_fieldlen_larger_than_buffer(self):
        tn = client()
        # Length claims 16 bytes; only 3 bytes of field follow the command.
        status = tn.process_3270(bytes([WSF, 0x00, 0x10, 0x01]))
        self.assertEqual(status, PDS_BAD_CMD)

    def test_tn3270e_header_three_bytes(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.tn_buffer = bytearray(b'\x00\x00\x00')
        self.assertTrue(tn.process_data())
        self.assertEqual(tn.tn_buffer, bytearray())

    def test_empty_3270_record(self):
        tn = client()
        self.assertEqual(tn.process_3270(b''), BAD_COMMAND)

    def test_truncated_write_wcc(self):
        tn = client()
        self.assertEqual(tn.process_3270(bytes([W])), BAD_COMMAND)

    def test_negotiate_tn3270_short_subnegotiation(self):
        tn = client()
        tn.sb_options = bytearray([options['TN3270E']])
        self.assertTrue(tn.negotiate_tn3270())
        tn.sb_options = bytearray([options['TN3270E'], TN3270E_SEND])
        self.assertTrue(tn.negotiate_tn3270())


    def test_sba_outside_screen_is_bad_address(self):
        tn = client()
        status = write_orders(tn, SBA, baddr14(1920), 0xC1)
        self.assertEqual(status, BAD_ADDRESS)
        # Must not have moved the address into the 14-bit value.
        self.assertLess(tn.buffer_address, SCREEN_SIZE)

    def test_ba_to_row(self):
        tn = client()
        self.assertEqual(tn.BA_TO_ROW(79), 1)
        self.assertEqual(tn.BA_TO_ROW(80), 2)
        self.assertEqual(tn.BA_TO_ROW(0), 1)


class EraseUnprotected(unittest.TestCase):

    def _layout(self, tn):
        # Unprotected field 0-9 (attr at 0), protected field 10-19 (attr at 10).
        tn.formatted = True
        tn.fa_buffer[0] = 0x40 | FA_MDT  # unprotected + MDT
        tn.fa_buffer[10] = 0x20          # protected
        tn.fa_buffer[20] = 0xF0
        for i in range(1, 10):
            tn.buffer[i] = 0xC1
        for i in range(11, 20):
            tn.buffer[i] = 0xC2

    def test_eau_clears_unprotected_and_mdt_leaves_protected(self):
        tn = client()
        self._layout(tn)
        tn.keyboard_locked = True
        status = tn.process_3270(bytes([EAU]))
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(bytes(tn.buffer[1:10]), b'\x00' * 9)
        self.assertEqual(bytes(tn.buffer[11:20]), b'\xc2' * 9)
        self.assertEqual(tn.fa_buffer[0] & FA_MDT, 0)
        self.assertFalse(tn.keyboard_locked)

    def test_eua_order_nulls_unprotected_up_to_stop(self):
        tn = client()
        self._layout(tn)
        tn.buffer_address = 1
        status = write_orders(tn, EUA, tn.ENCODE_BADDR(5))
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(bytes(tn.buffer[1:5]), b'\x00' * 4)
        self.assertEqual(tn.buffer[5], 0xC1)
        self.assertEqual(tn.buffer[9], 0xC1)
        self.assertEqual(bytes(tn.buffer[11:20]), b'\xc2' * 9)
        self.assertEqual(tn.fa_buffer[0] & FA_MDT, 0)
        self.assertEqual(tn.buffer_address, 5)

    def test_eua_stop_equals_current_wraps_whole_screen(self):
        tn = client()
        self._layout(tn)
        tn.buffer_address = 1
        status = write_orders(tn, EUA, tn.ENCODE_BADDR(1))
        self.assertEqual(status, NO_OUTPUT)
        self.assertEqual(bytes(tn.buffer[1:10]), b'\x00' * 9)
        self.assertEqual(bytes(tn.buffer[11:20]), b'\xc2' * 9)
        self.assertEqual(tn.buffer_address, 1)


class ReadModifiedVariants(unittest.TestCase):

    def _two_fields(self, tn):
        tn.formatted = True
        tn.fa_buffer[0] = 0x40 | FA_MDT
        tn.fa_buffer[10] = 0x40  # unprotected, no MDT
        tn.fa_buffer[20] = 0xF0
        tn.buffer[1] = 0xC1
        tn.buffer[11] = 0xC2
        tn.cursor_addr = 1

    def test_rm_sends_mdt_only_rma_sends_all_fields(self):
        tn = client()
        self._two_fields(tn)
        tn.process_3270(bytes([RM]))
        rm_wire = bytes(tn.sock.sent)
        tn.sock.sent = bytearray()
        tn.process_3270(bytes([RMA]))
        rma_wire = bytes(tn.sock.sent)
        addr1 = tn.ENCODE_BADDR(1)
        addr11 = tn.ENCODE_BADDR(11)
        self.assertIn(bytes([SBA]) + addr1, rm_wire)
        self.assertNotIn(bytes([SBA]) + addr11, rm_wire)
        self.assertIn(bytes([SBA]) + addr1, rma_wire)
        self.assertIn(bytes([SBA]) + addr11, rma_wire)

    def test_clear_aid_is_one_byte(self):
        tn = client()
        tn.state = TN3270_DATA
        tn.send_aid('CLEAR')
        wire = bytes(tn.sock.sent)
        self.assertTrue(wire.endswith(bytes([IAC, TN_EOR])))
        self.assertEqual(wire[:1], bytes([CLEAR]))
        self.assertEqual(len(wire), 3)

    def test_inbound_pa_short_read_is_aid_only(self):
        from tn3270.constants import PA1
        tn = client()
        tn.state = TN3270_DATA
        tn.aid = PA1
        tn.sock.sent = bytearray()
        tn.process_3270(bytes([RM]))
        wire = bytes(tn.sock.sent)
        self.assertEqual(wire[:1], bytes([PA1]))
        self.assertEqual(len(wire), 3)

    def test_unknown_wsf_id_is_pds_bad_cmd(self):
        tn = client()
        # length 3, unsupported ID 0x99
        status = tn.process_3270(bytes([WSF, 0x00, 0x03, 0x99]))
        self.assertEqual(status, PDS_BAD_CMD)

    def test_query_reply_iac_doubled_and_single_eor(self):
        tn = client()
        tn.state = TN3270E_DATA
        tn.read_partition(bytes([0xff, SF_RP_QUERY]))
        wire = bytes(tn.sock.sent)

        self.assertTrue(wire, 'Query Reply produced no wire bytes')
        self.assertEqual(wire[:5], b'\x00' * 5)
        self.assertNotEqual(wire[:5] + wire[5:10], b'\x00' * 10)
        self.assertTrue(wire.endswith(bytes([IAC, TN_EOR])))
        self.assertFalse(wire.endswith(bytes([IAC, TN_EOR, IAC, TN_EOR])))
        self.assertFalse(wire.endswith(b'\xff\xff\xef\xff\xef'),
                         'payload still contained a trailing IAC EOR')

        payload, eor_at = undouble_until_eor(wire, header_len=5)
        self.assertEqual(wire[eor_at:], bytes([IAC, TN_EOR]))
        self.assertEqual(payload[0], AID_SF)
        self.assertFalse(payload.endswith(bytes([IAC, TN_EOR])))
        if 0xff in payload:
            self.assertEqual(payload.count(0xff) * 2,
                             wire[5:eor_at].count(IAC))

    def test_query_reply_tn3270_mode_has_no_five_byte_header(self):
        tn = client()
        tn.state = TN3270_DATA
        tn.read_partition(bytes([0xff, SF_RP_QUERY]))
        wire = bytes(tn.sock.sent)
        self.assertNotEqual(wire[:5], b'\x00' * 5)
        self.assertEqual(wire[0], AID_SF)
        payload, eor_at = undouble_until_eor(wire, header_len=0)
        self.assertEqual(wire[eor_at:], bytes([IAC, TN_EOR]))
        self.assertEqual(payload[0], AID_SF)
        self.assertFalse(payload.endswith(bytes([IAC, TN_EOR])))


if __name__ == '__main__':
    unittest.main(verbosity=2)
