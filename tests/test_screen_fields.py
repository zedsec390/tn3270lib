#!/usr/bin/env python3
"""Offline field-geometry tests driven by the recorded CICS MCMM session.

The MCMM main menu has one unprotected field (the two-character "Option ==>"
input) and four nondisplay fields; the MCAD address panel has seven
unprotected fields whose contents are known. That makes both screens usable
as fixtures for writeable(), hidden_fields(), and show_hidden rendering.

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'traces'))

import replay
from tn3270.constants import FA_PROTECTED

TRACE = os.path.join(ROOT, 'traces', 'cics-mcmm.jsonl')


def screen_matching(predicate):
    """Replay the CICS trace and stop on the first screen predicate accepts."""
    tn, _sock = replay.replay(TRACE)
    if predicate(tn.get_screen()):
        return tn
    for text in replay.screens(tn):
        if predicate(text):
            return tn
    raise AssertionError('trace never produced the expected screen')


class McmmMainMenu(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tn = screen_matching(lambda s: 'Mels Cargo Main Menu' in s)

    def test_one_unprotected_field(self):
        attrs = [i for i, fa in enumerate(self.tn.fa_buffer)
                 if fa and not (fa & FA_PROTECTED)]
        self.assertEqual(attrs, [1536])

    def test_writeable_starts_after_the_attribute(self):
        # Field attribute at 1536 (row 20, col 17), two-character input at
        # 1537-1538, terminating protected attribute at 1539.
        self.assertEqual(self.tn.writeable(), [[1537, 1539]])

    def test_hidden_fields_have_no_nuls(self):
        fields = self.tn.hidden_fields()
        self.assertTrue(fields)
        for field in fields:
            self.assertNotIn('\x00', field)
        self.assertTrue(fields[0].startswith('99) Delete Order History'))

    def test_hidden_fields_match_their_locations(self):
        locations = self.tn.hidden_fields_location()
        fields = self.tn.hidden_fields()
        self.assertEqual(len(fields) * 2, len(locations))
        for n, field in enumerate(fields):
            start, stop = locations[2 * n], locations[2 * n + 1]
            self.assertEqual(len(field), stop - start - 1)

    def test_show_hidden_false_blanks_nondisplay_fields(self):
        shown = self.tn.get_screen()
        blanked = self.tn.get_screen(show_hidden=False)
        self.assertIn('99) Delete Order History', shown)
        self.assertNotIn('99) Delete Order History', blanked)
        self.assertIn('Mels Cargo Main Menu', blanked)
        self.assertEqual(len(shown), len(blanked))

    def test_raw_screen_still_carries_hidden_text(self):
        self.assertIn('99) Delete Order History', self.tn.get_screen_raw())


class McadAddressPanel(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tn = screen_matching(lambda s: s.lstrip().startswith('MCAD'))

    def test_writeable_extents(self):
        self.assertEqual(
            self.tn.writeable(),
            [[423, 467], [583, 627], [743, 787], [903, 947],
             [1063, 1107], [1223, 1267], [1383, 1387]])

    def test_writeable_contents(self):
        values = []
        for start, stop in self.tn.writeable():
            raw = bytes(self.tn.buffer[start:stop]).replace(b'\x00', b'\x40')
            values.append(raw.decode('cp037').strip())
        self.assertEqual(values, ['PHIL YOUNG', '100 ADELAIDE ST W', 'TORONTO',
                                  'ONTARIO', 'M5H 0B3', 'CANADA', '0000'])

    def test_field_start_is_first_data_character(self):
        # Every writeable start must be a data cell, never the attribute.
        for start, _stop in self.tn.writeable():
            self.assertEqual(self.tn.fa_buffer[start], 0)
            self.assertNotEqual(self.tn.fa_buffer[start - 1], 0)


class WriteableWrap(unittest.TestCase):
    """The VTAM banner on this LPAR puts field attributes at 1839 and 1919."""

    def test_field_wraps_at_the_end_of_the_buffer(self):
        import tn3270lib

        tn = tn3270lib.TN3270()
        tn.fa_buffer[1839] = 0x40  # unprotected command line, row 24
        tn.fa_buffer[1919] = 0xc8  # unprotected, wraps back to offset 0
        self.assertEqual(tn.writeable(), [[1840, 1919], [0, 1839]])

    def test_hidden_field_wraps_at_the_end_of_the_buffer(self):
        import tn3270lib

        tn = tn3270lib.TN3270()
        tn.fa_buffer[1910] = 0x4c  # unprotected, nondisplay (0x0c)
        tn.fa_buffer[5] = 0xc8     # next attribute, wraps past 1919
        tn.buffer[1911] = 0xC1
        tn.buffer[0] = 0xC2
        locs = tn.hidden_fields_location()
        self.assertEqual(locs[0], 1910)
        self.assertEqual(locs[1], 5)
        fields = tn.hidden_fields()
        self.assertTrue(fields)
        self.assertIn('A', fields[0])  # 0xC1
        self.assertIn('B', fields[0])  # 0xC2 at offset 0


if __name__ == '__main__':
    unittest.main(verbosity=2)
