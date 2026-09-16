"""Screen buffer rendering and queries."""

import re

from .constants import *
from .ebcdic import _ebcdic_to_str


class ScreenMixin:
        """Render the screen buffer and answer questions about it."""

        def clear_screen( self ):
                self.buffer_address = 0
                self.buffer = bytearray(SCREEN_SIZE)
                self.fa_buffer = bytearray(SCREEN_SIZE)
                self.overwrite_buf = bytearray(SCREEN_SIZE)
                self.formatted = False

        def clear_unprotected( self ):
                ## We'll ignore this for now since we ignore the protected field anyway
                return

        def print_screen( self ):
                """ Prints the current TN3270 screen buffer """
                self.msg(1,"Printing the current TN3270 buffer:")
                print(self.get_screen())

        def get_screen ( self ):
                """ Returns the current TN3270 screen buffer formatted for printing """
                self.msg(1,"Generating the current TN3270 buffer in ASCII")
                buff = []
                i = 1

                for line in self.buffer:
                        if line == 0:
                                buff.append(" ")
                        else:
                                buff.append(_ebcdic_to_str(line))
                        if i % 80 == 0:
                                buff.append('\n')

                        i = i + 1
                return ''.join(buff)

        def _screen_ascii_flat( self ):
                """Presentation space as ASCII, NULs as spaces, no newlines."""
                out = []
                for b in self.buffer:
                        out.append(' ' if b == 0 else _ebcdic_to_str(b))
                return ''.join(out)

        def get_screen_raw( self ):
                """All 1920 buffer bytes decoded with cp037 (NULs kept, no newlines)."""
                return _ebcdic_to_str(bytes(self.buffer))

        def get_screen_debug( self, lvl=1 ):
                """Log the screen one row at a time. Returns the last (empty) row buffer."""
                self.msg(lvl, "---------------------- Printing the current TN3270 buffer ----------------------")
                row = []
                for i, b in enumerate(self.buffer):
                        row.append(' ' if b == 0 else _ebcdic_to_str(b))
                        if (i + 1) % COLS == 0:
                                self.msg(lvl, ''.join(row))
                                row = []
                self.msg(lvl, "----------------------- End of the current TN3270 buffer ---------------------")
                return ''.join(row)

        def hexdump(self, src, length=8):
                """ Used to debug connection issues """
                if isinstance(src, str):
                        src = src.encode('latin1')
                result = []
                for i in range(0, len(src), length):
                        s = src[i:i+length]
                        hexa = ' '.join("%02X" % b for b in s)
                        text = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in s)
                        result.append("%04X   %-*s   %s" % (i, length * 3, hexa, text))
                return '\n'.join(result)

        def raw_screen_buffer(self):
                """ returns a list containing all the tn3270 data recieved """
                return self.raw_tn

        def writeable(self):
                """ Returns a list with all writeable fields as begining/ending tuples """
                writeable_list = []
                b_loc = 1
                for i in self.fa_buffer:
                        if i != 0x00 and not (i & 0x20): 
                                # find next SFA:
                                j_loc = 1
                                for j in self.fa_buffer[b_loc + 1:]:
                                        #print j
                                        if j != 0x00 and (j & 0x20):
                                                break
                                        j_loc += 1
                                self.msg(1,"Writeable Area: %d Row: %d Col: %d Length: %d", b_loc, self.BA_TO_ROW(b_loc + 1), 
                                                                self.BA_TO_COL(b_loc + 1), j_loc)
                                writeable_list.append([b_loc + 1,b_loc + 1 + j_loc])
                        b_loc += 1
                return writeable_list

        def find( self, needle ):
                """Find needle in the presentation space (spaces for NULs, no newlines).

                Returns False if missing, else a 0-based inclusive (start, end) pair.
                """
                if isinstance(needle, bytes):
                        needle = _ebcdic_to_str(needle)
                buff = self._screen_ascii_flat()
                self.msg(1, "[FIND] Looking for: %s", needle)
                start = buff.find(needle)
                if start < 0:
                        self.msg(1, "[FIND] Couldn't find: %s", needle)
                        return False
                self.msg(1, "[FIND] Found String: %s", needle)
                return start, start + len(needle) - 1

        def isClear( self ):
                """True if the screen has no alphanumeric characters."""
                buff = self._screen_ascii_flat()
                if re.search(r'[0-9A-Za-z]', buff):
                        self.msg(1, "[CLEAR] Screen has text")
                        return False
                self.msg(1, "[CLEAR] Screen is Empty")
                return True

        def any_hidden( self ):
                """True if any field attribute has the 3270 nondisplay bits (0x0c)."""
                hidden_attrib = 0x0c
                for fa in self.fa_buffer:
                        if (fa & hidden_attrib) == hidden_attrib:
                                return True
                return False

        def hidden_fields_location( self ):
                """Flat list of 0-based [start_fa, end_fa, ...] for hidden fields."""
                hidden_attrib = 0x0c
                hidden_location = []
                if not self.any_hidden():
                        return hidden_location
                i = 0
                n = len(self.fa_buffer)
                while i < n:
                        if (self.fa_buffer[i] & hidden_attrib) == hidden_attrib:
                                self.msg(1, "Found hidden field at buffer location: %s", i)
                                hidden_location.append(i)
                                i += 1
                                while i < n and self.fa_buffer[i] == 0:
                                        i += 1
                                hidden_location.append(i)
                        i += 1
                return hidden_location

        def hidden_fields( self ):
                """ASCII contents of hidden fields."""
                locations = self.hidden_fields_location()
                fields = []
                i = 0
                while i + 1 < len(locations):
                        start = locations[i] + 1
                        stop = locations[i + 1] - 1
                        self.msg(1, "Start Location: %s Stop Location %s", start, stop)
                        chunk = []
                        for k in range(start, stop + 1):
                                if 0 <= k < len(self.buffer):
                                        chunk.append(_ebcdic_to_str(self.buffer[k]))
                        fields.append(''.join(chunk))
                        i += 2
                return fields

        def any_overwritten( self ):
                """True if write_char replaced any existing buffer contents."""
                for b in self.overwrite_buf:
                        if b != 0:
                                return True
                return False

        def overwrite_data( self ):
                """Screen-shaped ASCII of overwrite_buf (spaces where nothing was overwritten)."""
                if not self.any_overwritten():
                        return False
                self.msg(1, "Printing the overwritten TN3270 buffer")
                buff = []
                for i, b in enumerate(self.overwrite_buf):
                        buff.append(' ' if b == 0 else _ebcdic_to_str(b))
                        if (i + 1) % COLS == 0:
                                buff.append('\n')
                return ''.join(buff)
