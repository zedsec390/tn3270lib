"""Screen buffer rendering, geometry, and field queries."""

import html as html_lib
import re

from .constants import *


class Field(object):
        """One 3270 field: start is the first data cell (after the attribute).

        Attributes
        ----------
        start, end : int
            Buffer addresses of the first and last data cells.
        row, col : int
            1-based start position.
        length : int
            Data-cell length (not including the field attribute).
        value : str
            Current field contents (decoded).
        protected, mdt, numeric : bool
            Field Attribute bits.
        label : str
            Preceding protected text used by ``field(label)``.
        """

        __slots__ = ('start', 'end', 'row', 'col', 'length', 'value',
                                 'protected', 'mdt', 'numeric', 'label')

        def __init__(self, start, end, row, col, length, value, protected, mdt,
                                 label='', numeric=False):
                self.start = start
                self.end = end
                self.row = row
                self.col = col
                self.length = length
                self.value = value
                self.protected = protected
                self.mdt = mdt
                self.numeric = numeric
                self.label = label

        def __repr__(self):
                return ('Field(start=%r, row=%r, col=%r, length=%r, protected=%r, '
                                'mdt=%r, numeric=%r, label=%r, value=%r)' % (
                                        self.start, self.row, self.col, self.length,
                                        self.protected, self.mdt, self.numeric,
                                        self.label, self.value))


class ScreenMixin:
        """Render the screen buffer and answer questions about it."""

        def _use_default_size( self ):
                self._apply_screen_size(
                        getattr(self, 'default_rows', ROWS),
                        getattr(self, 'default_cols', COLS))

        def _use_alternate_size( self ):
                self._apply_screen_size(
                        getattr(self, 'alt_rows', ROWS),
                        getattr(self, 'alt_cols', COLS))

        def _apply_screen_size( self, rows, cols ):
                self.rows = rows
                self.cols = cols
                self.screen_size = rows * cols

        def _alloc_buffers( self, n=None ):
                """Allocate presentation-space and per-cell attribute buffers."""
                if n is None:
                        n = self.screen_size
                self.buffer = bytearray(n)
                self.fa_buffer = bytearray(n)
                self.overwrite_buf = bytearray(n)
                self.fg_buffer = bytearray(n)
                self.hl_buffer = bytearray(n)
                self.cs_buffer = bytearray(n)
                self.field_fg = bytearray(n)
                self.field_hl = bytearray(n)
                self.field_cs = bytearray(n)
                self._sa_fg = None
                self._sa_hl = None
                self._sa_cs = None

        def rowcol_to_addr( self, row, col ):
                """1-based row/column to 0-based buffer address."""
                return (int(row) - 1) * self.cols + (int(col) - 1)

        def addr_to_rowcol( self, addr ):
                """0-based address to 1-based (row, col)."""
                return self.BA_TO_ROW(addr), self.BA_TO_COL(addr) + 1

        def clear_screen( self ):
                self.buffer_address = 0
                self._alloc_buffers(self.screen_size)
                self.formatted = False

        def clear_unprotected( self ):
                """EAU: null unprotected field contents, reset MDT, unlock keyboard."""
                n = self.screen_size
                for b_loc in range(n):
                        fa = self.fa_buffer[b_loc]
                        if fa == 0x00 or (fa & FA_PROTECTED):
                                continue
                        self.fa_buffer[b_loc] = fa & ~FA_MDT
                        a = self.INC_BUF_ADDR(b_loc)
                        start = a
                        while self.fa_buffer[a] == 0:
                                self.buffer[a] = 0
                                a = self.INC_BUF_ADDR(a)
                                if a == start:
                                        break
                self.keyboard_locked = False
                self._paint_pending = True

        def print_screen( self, show_hidden=True ):
                """ Prints the current TN3270 screen buffer """
                self.msg(1,"Printing the current TN3270 buffer:")
                print(self.get_screen(show_hidden))

        def get_screen ( self, show_hidden=True ):
                """ Returns the current TN3270 screen buffer formatted for printing

                With show_hidden True (the default) every character in the buffer is
                rendered, including the contents of nondisplay fields. Pass False to
                blank those fields instead, which is what a real 3270 terminal shows:
                each character between a nondisplay field attribute and the attribute
                that ends the field becomes a space. get_screen_raw() and
                hidden_fields() still return hidden content either way.
                """
                self.msg(1,"Generating the current TN3270 buffer in ASCII")
                return self._render_text(show_hidden)

        def _cell_char( self, pos, blanked ):
                if self.buffer[pos] == 0 or pos in blanked:
                        return ' '
                return self._ebcdic_to_str(self.buffer[pos])

        def _render_text( self, show_hidden=True ):
                blanked = set() if show_hidden else self._hidden_positions()
                buff = []
                cols = self.cols
                for pos in range(len(self.buffer)):
                        buff.append(self._cell_char(pos, blanked))
                        if cols and (pos + 1) % cols == 0:
                                buff.append('\n')
                return ''.join(buff)

        def _hidden_positions( self ):
                """Set of 0-based buffer offsets that live inside a nondisplay field.

                Built from hidden_fields_location() so the nondisplay attribute test
                is defined in exactly one place.
                """
                positions = set()
                locations = self.hidden_fields_location()
                i = 0
                while i + 1 < len(locations):
                        positions.update(self._field_data_addrs(locations[i], locations[i + 1]))
                        i += 2
                return positions

        def _screen_ascii_flat( self ):
                """Presentation space as ASCII, NULs as spaces, no newlines."""
                out = []
                for b in self.buffer:
                        out.append(' ' if b == 0 else self._ebcdic_to_str(b))
                return ''.join(out)

        def get_screen_raw( self ):
                """All buffer bytes decoded with the session code page (NULs kept, no newlines)."""
                return self._ebcdic_to_str(bytes(self.buffer))

        def get_screen_debug( self, lvl=1, show_hidden=True ):
                """Log the screen one row at a time. Returns the last (empty) row buffer.

                show_hidden works the same way as in get_screen().
                """
                self.msg(lvl, "---------------------- Printing the current TN3270 buffer ----------------------")
                blanked = set() if show_hidden else self._hidden_positions()
                row = []
                for i, b in enumerate(self.buffer):
                        row.append(' ' if b == 0 or i in blanked else self._ebcdic_to_str(b))
                        if (i + 1) % self.cols == 0:
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
                """ Returns a list with all writeable fields as begining/ending tuples

                A field attribute without FA_PROTECTED starts an unprotected field.
                Its data begins at the 0-based offset right after the attribute and
                runs up to the attribute that ends the field, so each entry is
                [first_data_offset, offset_of_terminating_attribute]. Buffer
                addresses wrap at the end of the presentation space, so a field
                that wraps past row 24 reports an end below its start.
                """
                writeable_list = []
                n = len(self.fa_buffer)
                for b_loc in range(n):
                        fa = self.fa_buffer[b_loc]
                        if fa == 0x00 or (fa & FA_PROTECTED):
                                continue
                        start = self.INC_BUF_ADDR(b_loc)
                        stop = start
                        while self.fa_buffer[stop] == 0x00:
                                stop = self.INC_BUF_ADDR(stop)
                                if stop == start:
                                        break
                        self.msg(1,"Writeable Area: %d Row: %d Col: %d Length: %d", b_loc,
                                                        self.BA_TO_ROW(start), self.BA_TO_COL(start),
                                                        (stop - start) % n)
                        writeable_list.append([start, stop])
                return writeable_list

        def find( self, needle ):
                """Find needle in the presentation space (spaces for NULs, no newlines).

                Returns False if missing, else a 0-based inclusive (start, end) pair.
                """
                if isinstance(needle, bytes):
                        needle = self._ebcdic_to_str(needle)
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

        def _field_data_addrs( self, fa_start, fa_stop ):
                """Yield 0-based data offsets between two field attributes, wrapping."""
                a = self.INC_BUF_ADDR(fa_start)
                for _ in range(self.screen_size):
                        if a == fa_stop:
                                return
                        yield a
                        a = self.INC_BUF_ADDR(a)

        def hidden_fields_location( self ):
                """Flat list of 0-based [start_fa, end_fa, ...] for hidden fields."""
                hidden_attrib = 0x0c
                hidden_location = []
                if not self.any_hidden():
                        return hidden_location
                n = len(self.fa_buffer)
                i = 0
                seen = set()
                while i < n:
                        if i in seen:
                                break
                        if (self.fa_buffer[i] & hidden_attrib) == hidden_attrib:
                                self.msg(1, "Found hidden field at buffer location: %s", i)
                                hidden_location.append(i)
                                seen.add(i)
                                j = self.INC_BUF_ADDR(i)
                                while self.fa_buffer[j] == 0:
                                        j = self.INC_BUF_ADDR(j)
                                        if j == i:
                                                break
                                hidden_location.append(j)
                                # Resume at the terminating attribute: it may itself
                                # start another hidden field (TSO/E LOGON does this).
                                if j <= i:
                                        break
                                i = j
                        else:
                                i += 1
                return hidden_location

        def hidden_fields( self ):
                """ASCII contents of hidden fields."""
                locations = self.hidden_fields_location()
                fields = []
                i = 0
                while i + 1 < len(locations):
                        start_fa, stop_fa = locations[i], locations[i + 1]
                        self.msg(1, "Start Location: %s Stop Location %s", start_fa, stop_fa)
                        chunk = []
                        for k in self._field_data_addrs(start_fa, stop_fa):
                                b = self.buffer[k]
                                chunk.append(' ' if b == 0 else self._ebcdic_to_str(b))
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
                        buff.append(' ' if b == 0 else self._ebcdic_to_str(b))
                        if (i + 1) % self.cols == 0:
                                buff.append('\n')
                return ''.join(buff)

        def fields( self, unprotected_only=True ):
                """Return Field objects for presentation-space fields.

                By default only unprotected fields. Pass unprotected_only=False
                for every field (protected labels included). ``label`` on an
                unprotected field is the stripped text of the preceding
                protected field.
                """
                n = len(self.fa_buffer)
                fa_locs = [i for i in range(n) if self.fa_buffer[i]]
                out = []
                last_prot = ''
                for idx, fa_loc in enumerate(fa_locs):
                        fa = self.fa_buffer[fa_loc]
                        start = self.INC_BUF_ADDR(fa_loc)
                        stop = fa_locs[0]
                        if idx + 1 < len(fa_locs):
                                stop = fa_locs[idx + 1]
                        chars = []
                        length = 0
                        for a in self._field_data_addrs(fa_loc, stop):
                                length += 1
                                b = self.buffer[a]
                                chars.append(' ' if b == 0 else self._ebcdic_to_str(b))
                        value = ''.join(chars)
                        protected = bool(fa & FA_PROTECTED)
                        if protected:
                                last_prot = value.strip()
                                label = last_prot
                        else:
                                label = last_prot
                        if unprotected_only and protected:
                                continue
                        row, col = self.addr_to_rowcol(start)
                        out.append(Field(
                                start=start, end=stop, row=row, col=col,
                                length=length, value=value,
                                protected=protected, mdt=bool(fa & FA_MDT),
                                numeric=bool(fa & FA_NUMERIC),
                                label=label))
                return out

        def field( self, label ):
                """Unprotected field whose preceding protected text matches label.

                Match is case-insensitive substring after stripping both sides.
                Raises KeyError if nothing matches.
                """
                needle = label.strip().lower()
                for f in self.fields(unprotected_only=True):
                        if needle in (f.label or '').strip().lower():
                                return f
                raise KeyError('no unprotected field labelled %r' % (label,))

        def fill( self, label, text ):
                """Write text into field(label), set MDT, and move the cursor."""
                f = self.field(label)
                data = text[:f.length]
                self._type_ascii_at(f.start, data)
                return f

        def type( self, text, field=None ):
                """Type text at the cursor, or into field=label / field=address."""
                if field is None:
                        self._type_ascii_at(self.cursor_addr, text)
                        return
                if isinstance(field, int):
                        self._type_ascii_at(field, text)
                        return
                self.fill(field, text)

        def tab( self ):
                """Program Tab from the cursor: next unprotected field."""
                self.buffer_address = self.cursor_addr
                self._program_tab()
                self.cursor_addr = self.buffer_address
                return self.cursor_addr

        def newline( self ):
                """Move to the first unprotected field on a later row, else next field."""
                here = self.cursor_addr
                row = self.BA_TO_ROW(here)
                nxt = self._next_unprotected(here)
                if nxt and self.BA_TO_ROW(nxt) > row:
                        self.cursor_addr = nxt
                        self.buffer_address = nxt
                        return nxt
                end_row = row * self.cols - 1
                nxt = self._next_unprotected(end_row)
                self.cursor_addr = nxt
                self.buffer_address = nxt
                return nxt

        def save_screen( self, path, show_hidden=True ):
                """Write the decoded screen to ``path`` (UTF-8 text)."""
                return self.save_screen_txt(path, show_hidden)

        def save_screen_txt( self, path, show_hidden=True ):
                """Decoded screen using the session code page, wrapped at ``cols``."""
                with open(path, 'w', encoding='utf-8') as fh:
                        fh.write(self.get_screen(show_hidden))

        def save_screen_html( self, path, show_hidden=True ):
                """HTML dump with protected/hidden/color/highlight spans."""
                with open(path, 'w', encoding='utf-8') as fh:
                        fh.write(self.get_screen_html(show_hidden))

        def _cell_classes( self, pos, blanked ):
                fa = self._fa_containing(pos)
                protected = bool(fa is not None and (self.fa_buffer[fa] & FA_PROTECTED))
                hidden = pos in blanked
                if fa is not None and (self.fa_buffer[fa] & 0x0c) == 0x0c:
                        hidden = True
                classes = ['protected' if protected else 'unprotected']
                if hidden:
                        classes.append('hidden')
                fg = 0
                hl = 0
                if getattr(self, 'fg_buffer', None) is not None and pos < len(self.fg_buffer):
                        fg = self.fg_buffer[pos]
                        hl = self.hl_buffer[pos]
                cname = COLOR_NAMES.get(fg)
                if cname and cname != 'default':
                        classes.append('color-%s' % cname)
                hname = HL_NAMES.get(hl)
                if hname and hname != 'default':
                        classes.append('hl-%s' % hname)
                return tuple(classes)

        def get_screen_html( self, show_hidden=True ):
                """Return an HTML <pre> of the screen with field and color spans."""
                blanked = set() if show_hidden else self._hidden_positions()
                cols = self.cols or COLS
                n = len(self.buffer)
                parts = [
                        '<!DOCTYPE html><html><head><meta charset="utf-8">',
                        '<title>TN3270 screen</title><style>',
                        'pre.tn3270{font-family:monospace;background:#111;color:#ddd;padding:8px;}',
                        '.protected{font-weight:bold;} .unprotected{font-weight:normal;}',
                        '.hidden{opacity:0.35;}',
                        '.color-blue{color:#4aa3ff;} .color-red{color:#ff5a5a;}',
                        '.color-pink{color:#ff7ac6;} .color-green{color:#3dcc6d;}',
                        '.color-turquoise{color:#3dccc8;} .color-yellow{color:#e8d44d;}',
                        '.color-white{color:#f5f5f5;} .color-neutral{color:#ddd;}',
                        '.hl-underscore{text-decoration:underline;}',
                        '.hl-reverse{background:#ddd;color:#111;}',
                        '.hl-blink{text-decoration:blink;}',
                        '</style></head><body><pre class="tn3270">',
                ]
                run_cls = None
                run = []
                def flush():
                        if not run:
                                return
                        text = html_lib.escape(''.join(run))
                        if run_cls:
                                parts.append('<span class="%s">%s</span>' % (
                                        ' '.join(run_cls), text))
                        else:
                                parts.append(text)
                        run[:] = []
                for pos in range(n):
                        ch = self._cell_char(pos, blanked)
                        cls = self._cell_classes(pos, blanked)
                        if cls != run_cls:
                                flush()
                                run_cls = cls
                        run.append(ch)
                        if (pos + 1) % cols == 0:
                                flush()
                                parts.append('\n')
                                run_cls = None
                flush()
                parts.append('</pre></body></html>\n')
                return ''.join(parts)
