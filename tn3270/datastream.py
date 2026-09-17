"""3270 data stream processing."""

import struct

from .constants import *
from .query import build_query_reply


class DataStreamMixin:
        """Buffer addressing, orders, inbound reads and structured fields."""

        def _ebcdic_to_str( self, data ):
                from .ebcdic import ebcdic_to_str
                return ebcdic_to_str(data, getattr(self, 'codepage', 'cp037'))

        def _str_to_ebcdic( self, text ):
                from .ebcdic import str_to_ebcdic
                return str_to_ebcdic(text, getattr(self, 'codepage', 'cp037'))

        def DECODE_BADDR(self, byte1, byte2):
                """ Decodes Buffer Addresses.
                        Buffer addresses can come in 14 or 12 (this terminal doesn't support 16 bit)
                        this function takes two bytes (buffer addresses are two bytes long) and returns
                        the decoded buffer address."""
                if (byte1 & 0xC0) == 0:
                        return (((byte1 & 0x3F) << 8) | byte2) 
                else:
                        return ((byte1 & 0x3F) << 6) | (byte2 & 0x3F)  

        def ENCODE_BADDR(self, address):
                """ Encodes Buffer Addresses """
                b1 = struct.pack(">B",code_table[((address >> 6) & 0x3F)])
                b2 = struct.pack(">B",code_table[(address & 0x3F)])
                return b1 + b2

        def BA_TO_ROW( self, addr ):
                """ Returns the current 1-based row of a buffer address """
                cols = getattr(self, 'cols', COLS) or COLS
                return (addr // cols) + 1

        def BA_TO_COL( self, addr ):
                """ Returns the current 0-based column of a buffer address """
                cols = getattr(self, 'cols', COLS) or COLS
                return addr % cols

        def INC_BUF_ADDR( self, addr ):
                """ Increments the buffer address by one """
                n = self.screen_size
                return ((addr + 1) % n)

        def DEC_BUF_ADDR( self, addr ):
                """ Decreases the buffer address by one """
                n = self.screen_size
                return ((addr - 1) % n)

        def BA_EQU( self, a, b ):
                """ True if two buffer addresses refer to the same cell. """
                n = self.screen_size
                return ((a - b) % n) == 0

        def process_3270( self, data ):
                """ Processes TN3270 Data """
            ## the first byte will be the command we have to follow
                if not data:
                        self.msg(1,"Empty 3270 data stream")
                        return BAD_COMMAND
                com = data[0]
                self.msg(1,"Value Received: %r", com)
                if ( com == EAU or com == SNA_EAU ):
                        self.msg(1,"TN3270 Command: Erase All Unprotected")
                        self.clear_unprotected()
                        return NO_OUTPUT
                elif com == EWA or com == SNA_EWA:
                        self.msg(1,"TN3270 Command: Erase Write Alternate")
                        self._use_alternate_size()
                        self.clear_screen()
                        return self.process_write(data)
                elif com == EW or com == SNA_EW:
                        self.msg(1,"TN3270 Command: Erase Write")
                        self._use_default_size()
                        self.clear_screen()
                        return self.process_write(data)
                elif com == W or com == SNA_W:
                        self.msg(1,"TN3270 Command: Write")
                        return self.process_write(data)
                elif com == RB  or com == SNA_RB:
                        self.msg(1,"TN3270 Command: Read Buffer")
                        self.process_read()
                        return OUTPUT
                elif com == RM or com == SNA_RM:
                        self.msg(1,"TN3270 Command: Read Modified")
                        self.process_read_modified(self.aid, all_fields=False)
                        return OUTPUT
                elif com == RMA or com == SNA_RMA:
                        self.msg(1,"TN3270 Command: Read Modified All")
                        self.process_read_modified(self.aid, all_fields=True)
                        return OUTPUT
                elif com == WSF or com == SNA_WSF:
                        self.msg(1,"TN3270 Command: Write Structured Field")
                        return self.w_structured_field(data)
                elif com == NOP or com == SNA_NOP:
                        self.msg(1,"TN3270 Command: No OP (NOP)")
                        return NO_OUTPUT
                else:
                        self.msg(1,"Unknown 3270 Data Stream command: %r", com)
                        return BAD_COMMAND

        ### WCC / tn3270 data stream processor
        def process_write(self, data ):
                """ Processes TN3270 Write commands and
                    writes them to the screen buffer """
                self.msg(1,"Processing TN3270 Write Command")
                prev = ''
                cp = ''
                num_attr = 0
                last_cmd = False
                status = NO_OUTPUT

                if len(data) < 2:
                        self.msg(1,"Write command truncated (no WCC)")
                        return BAD_COMMAND

                i = 1
                self.keyboard_locked = True
                self._reset_sa()
                wcc = data[i]
                if (wcc & WCC_RESET):
                        self.msg(2,"WCC Reset")
                if (wcc & WCC_RESTORE):
                        self.msg(2,"WCC Restore")
                        self.keyboard_locked = False
                if (wcc & WCC_RESET_MDT):
                        self.msg(2,"WCC Reset MDT")
                        self._reset_mdt()


                i = 2 # skip the first two chars
                while i <= len(data) - 1:
                        self.msg(2,"Current Position: " + str(i) + " of " + str(len(data)))
                        cp = data[i]
                        self.msg(2,"Current Item: %r",cp)
                        # awesome, no switch statements here either
                        if cp == SF:
                                self.msg(2,"Start Field")
                                if i + 1 >= len(data):
                                        status = BAD_COMMAND
                                        break
                                prev = 'ORDER'
                                last_cmd = True
                                i = i + 1 # skip SF
                                self.msg(2,"Writting Zero to buffer at address: %r",self.buffer_address)
                                self.msg(2,"Attribute Type: %r", data[i])
                                self.write_char(0)
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                self.write_field_attribute(data[i])
                                self._reset_field_ext(self.DEC_BUF_ADDR(self.buffer_address))
                                self._reset_sa()
                                self.formatted = True
                                #set the current position one ahead (after SF)
                                i = i + 1

                        elif cp == SFE:
                                self.msg(2,"Start Field Extended")
                                if i + 1 >= len(data):
                                        status = BAD_COMMAND
                                        break
                                i = i + 1 # skip SFE
                                num_attr = data[i]
                                if i + 1 + 2 * num_attr > len(data):
                                        self.msg(1,"SFE truncated: %r attrs need %r bytes",
                                                 num_attr, 2 * num_attr)
                                        status = BAD_COMMAND
                                        break
                                self.msg(2,"Number of Attributes: %r", num_attr)
                                self.msg(2,"Writting Zero to buffer at address: %r", self.buffer_address)
                                fa_addr = self.buffer_address
                                self.write_char(0)
                                for j in range(num_attr):
                                        i = i + 1
                                        typ = data[i]
                                        i = i + 1
                                        val = data[i]
                                        self.msg(2,"SFE attr type %r value %r", typ, val)
                                        self._store_field_attr(fa_addr, typ, val)
                                if not self.fa_buffer[fa_addr]:
                                        self.fa_buffer[fa_addr] = 0xC0
                                self._reset_sa()
                                self._paint_cell_attrs(fa_addr)
                                self.formatted = True
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                i = i + 1
                                
                        elif cp == SBA:
                                self.msg(2,"Set Buffer Address (SBA) 0x11")
                                if i + 2 >= len(data):
                                        status = BAD_ADDRESS
                                        break
                                sba_addr = self.DECODE_BADDR(data[i + 1],
                                                                                                                data[i + 2])
                                if sba_addr >= self.screen_size:
                                        self.msg(1,"SBA address %r outside screen", sba_addr)
                                        status = BAD_ADDRESS
                                        break
                                self.buffer_address = sba_addr
                                self.msg(2,"Buffer Address: %r" , self.buffer_address)
                                self.msg(2,"Row: %r" , self.BA_TO_ROW(self.buffer_address))
                                self.msg(2,"Col: %r" , self.BA_TO_COL(self.buffer_address))
                                last_cmd = True
                                prev = 'SBA'
                                # the current position is SBA, the next two bytes are the lengths
                                i = i + 3
                                if len(data) > i:
                                        self.msg(2,"Next Command: %r",data[i])
                        elif cp == IC: # Insert Cursor
                                self.msg(1,"Insert Cursor (IC) 0x13")
                                self.msg(2,"Current Cursor Address: %r" , self.cursor_addr)
                                self.msg(2,"Buffer Address: %r", self.buffer_address)
                                self.msg(2,"Row: %r" , self.BA_TO_ROW(self.buffer_address))
                                self.msg(2,"Col: %r" , self.BA_TO_COL(self.buffer_address))
                                prev = 'ORDER'
                                self.cursor_addr = self.buffer_address
                                last_cmd = True
                                i = i + 1
                        elif cp == RA:
                        # Repeat address repeats whatever the next char is after the two byte buffer address
                        # There's all kinds of weird GE stuff we could do, but not now. Maybe in future vers
                                self.msg(2,"Repeat to Address (RA) 0x3C")
                                if i + 3 >= len(data):
                                        # Missing address bytes vs missing the repeat character.
                                        status = BAD_ADDRESS if i + 2 >= len(data) else BAD_COMMAND
                                        break
                                ra_baddr = self.DECODE_BADDR(data[i + 1],
                                                     data[i + 2])
                                self.msg(2,"Repeat Character: %r" , data[i + 1])
                                self.msg(2,"Repeat to this Address: %r" , ra_baddr)
                                self.msg(2,"Currrent Address: %r", self.buffer_address)
                                if ra_baddr >= self.screen_size:
                                        self.msg(1,"RA address %r outside screen", ra_baddr)
                                        status = BAD_ADDRESS
                                        break
                                prev = 'ORDER'
                                i = i + 3
                                char_to_repeat = data[i]
                                i = i + 1
                                self.msg(2,"Repeat Character: %r" ,char_to_repeat)
                                # Fill is exclusive of the stop address. When stop
                                # equals the current address, fill the whole buffer once.
                                if self.buffer_address == ra_baddr:
                                        for _ in range(self.screen_size):
                                                self.write_char(char_to_repeat)
                                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                else:
                                        n = 0
                                        while self.buffer_address != ra_baddr and n < self.screen_size:
                                                self.write_char(char_to_repeat)
                                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                                n = n + 1
                        elif cp == EUA:
                                self.msg(2,"Erase Unprotected to Address (EUA) 0x12")
                                if i + 2 >= len(data):
                                        status = BAD_ADDRESS
                                        break
                                eua_baddr = self.DECODE_BADDR(data[i + 1],
                                                      data[i + 2])
                                i = i + 3
                                self.msg(2,"EAU to this Address: %r" , eua_baddr)
                                self.msg(2,"Currrent Address: %r",  self.buffer_address)
                                if eua_baddr >= self.screen_size:
                                        self.msg(1,"EUA address %r outside screen", eua_baddr)
                                        status = BAD_ADDRESS
                                        break
                                self._erase_unprotected_to(eua_baddr)
                        elif cp == GE:
                                self.msg(2,"Graphical Escape (GE) 0x08")
                                prev = 'ORDER'
                                if i + 1 >= len(data):
                                        status = BAD_COMMAND
                                        break
                                i = i + 1 # move to next byte
                                ge_char = data[i]
                                self.write_char(ge_char)
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                i = i + 1
                        elif cp == MF:
                                # we don't actually have 'fields' at this point
                                # so there's nothing to be modified
                                self.msg(2,"Modify Field (MF) 0x2C")
                                prev = 'ORDER'
                                if i + 1 >= len(data):
                                        status = BAD_COMMAND
                                        break
                                num_attr = int(data[i + 1])
                                if i + 2 + 2 * num_attr > len(data):
                                        self.msg(1,"MF truncated: %r attrs need %r bytes",
                                                 num_attr, 2 * num_attr)
                                        status = BAD_COMMAND
                                        break
                                fa_addr = self.buffer_address
                                i = i + 2
                                for j in range(num_attr):
                                        self._store_field_attr(fa_addr, data[i], data[i + 1])
                                        i = i + 2
                                self._apply_field_attrs_to_data(fa_addr)
                        elif cp == SA:
                                self.msg(2,"Set Attribute (SA) 0x28")
                                # SA is followed by a 1-byte type and 1-byte value.
                                if i + 2 >= len(data):
                                        status = BAD_COMMAND
                                        break
                                self._store_sa(data[i + 1], data[i + 2])
                                i = i + 3
                        elif cp == PT:
                                self.msg(2,"Program Tab (PT) 0x05")
                                self._program_tab()
                                i = i + 1

                        elif ( cp == NUL or
                       cp == SUB or
                   cp == DUP or
                   cp == FM  or
                   cp == FF  or
                   cp == CR  or
                   cp == NL  or
                   cp == EM  or
                   cp == EO  ):
                                self.msg(2,"Format Control Order received")
                                prev = 'ORDER'
                                # The Lua original writes "\064", a decimal escape,
                                # i.e. 0x40 -- the EBCDIC blank.
                                self.write_char(0x40)
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                i = i + 1
                        else: # whoa we made it.
                                ascii_char = self._ebcdic_to_str(cp)
                                self.msg(2,"Inserting "+ ascii_char + " (%r) at the following location:", data[i])
                                self.msg(2,"  Row: %r" , self.BA_TO_ROW(self.buffer_address))
                                self.msg(2,"  Col: %r" , self.BA_TO_COL(self.buffer_address))
                                self.msg(2,"  Buffer Address: %r" , self.buffer_address)
                                self.write_char(data[i])
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                i = i + 1
                        # end of massive if/else
            # end of while loop
                self._paint_pending = True
                return status

        def write_char( self, char ):
                """ Writes a character to the screen buffer.
                    If a character already exists at that location,
                    write the char in the screen buffer to a backup buffer """
                if isinstance(char, (bytes, bytearray)):
                        char = char[0]
                if self.buffer[self.buffer_address] == 0:
                        self.buffer[self.buffer_address] = char
                else:
                        self.overwrite_buf[self.buffer_address] = self.buffer[self.buffer_address]
                        self.buffer[self.buffer_address] = char
                self._paint_cell_attrs(self.buffer_address)

        def write_field_attribute( self, attr ):
                """ Writes Field attributes to the field attribute buffer """
                if isinstance(attr, (bytes, bytearray)):
                        attr = attr[0]
                self.fa_buffer[self.buffer_address-1] = attr

        def _ensure_attr_buffers( self ):
                n = getattr(self, 'screen_size', 0) or len(getattr(self, 'buffer', b''))
                if getattr(self, 'fg_buffer', None) is None or len(self.fg_buffer) != n:
                        self.fg_buffer = bytearray(n)
                        self.hl_buffer = bytearray(n)
                        self.cs_buffer = bytearray(n)
                        self.field_fg = bytearray(n)
                        self.field_hl = bytearray(n)
                        self.field_cs = bytearray(n)
                if not hasattr(self, '_sa_fg'):
                        self._sa_fg = None
                        self._sa_hl = None
                        self._sa_cs = None

        def _reset_sa( self ):
                self._sa_fg = None
                self._sa_hl = None
                self._sa_cs = None

        def _reset_field_ext( self, fa_addr ):
                self._ensure_attr_buffers()
                if 0 <= fa_addr < len(self.field_fg):
                        self.field_fg[fa_addr] = 0
                        self.field_hl[fa_addr] = 0
                        self.field_cs[fa_addr] = 0

        def _store_field_attr( self, fa_addr, typ, val ):
                """SFE/MF type+value at the field-attribute cell."""
                self._ensure_attr_buffers()
                if typ == SFE_FA:
                        self.fa_buffer[fa_addr] = val
                elif typ in (XA_HIGHLIGHT, SFE_HIGHLIGHT):
                        self.field_hl[fa_addr] = val
                elif typ in (XA_FGCOLOR, SFE_COLOR):
                        self.field_fg[fa_addr] = val
                elif typ in (XA_CHARSET, SFE_CHARSET):
                        self.field_cs[fa_addr] = val

        def _store_sa( self, typ, val ):
                """Character attributes until the next SA or field."""
                if typ == XA_RESET:
                        self._reset_sa()
                        return
                if typ in (XA_HIGHLIGHT, SFE_HIGHLIGHT):
                        self._sa_hl = val
                elif typ in (XA_FGCOLOR, SFE_COLOR):
                        self._sa_fg = val
                elif typ in (XA_CHARSET, SFE_CHARSET):
                        self._sa_cs = val

        def _paint_cell_attrs( self, addr ):
                self._ensure_attr_buffers()
                n = len(self.fg_buffer)
                if addr < 0 or addr >= n:
                        return
                fa = self._fa_containing(addr)
                fg = self._sa_fg
                hl = self._sa_hl
                cs = self._sa_cs
                if fa is not None:
                        if fg is None:
                                fg = self.field_fg[fa]
                        if hl is None:
                                hl = self.field_hl[fa]
                        if cs is None:
                                cs = self.field_cs[fa]
                self.fg_buffer[addr] = fg or 0
                self.hl_buffer[addr] = hl or 0
                self.cs_buffer[addr] = cs or 0

        def _apply_field_attrs_to_data( self, fa_addr ):
                """MF: copy field color/highlight onto cells of this field."""
                self._ensure_attr_buffers()
                n = self.screen_size
                if fa_addr < 0 or fa_addr >= n:
                        return
                self._paint_cell_attrs(fa_addr)
                a = self.INC_BUF_ADDR(fa_addr)
                for _ in range(n):
                        if a == fa_addr:
                                break
                        if self.fa_buffer[a]:
                                break
                        self.fg_buffer[a] = self.field_fg[fa_addr]
                        self.hl_buffer[a] = self.field_hl[fa_addr]
                        self.cs_buffer[a] = self.field_cs[fa_addr]
                        a = self.INC_BUF_ADDR(a)

        def cell_fg( self, addr ):
                self._ensure_attr_buffers()
                return self.fg_buffer[addr]

        def cell_hl( self, addr ):
                self._ensure_attr_buffers()
                return self.hl_buffer[addr]

        def cell_cs( self, addr ):
                self._ensure_attr_buffers()
                return self.cs_buffer[addr]

        def _reset_mdt( self ):
                """Clear the MDT bit on every field attribute (WCC reset MDT)."""
                for i, fa in enumerate(self.fa_buffer):
                        if fa:
                                self.fa_buffer[i] = fa & ~FA_MDT

        def _fa_containing( self, addr ):
                """0-based index of the field attribute that owns addr, or None."""
                n = self.screen_size
                if n == 0:
                        return None
                if self.fa_buffer[addr]:
                        return addr
                a = addr
                for _ in range(n):
                        a = self.DEC_BUF_ADDR(a)
                        if self.fa_buffer[a]:
                                return a
                return None

        def _next_unprotected( self, addr ):
                """First data address of the next unprotected field after addr, or 0."""
                n = self.screen_size
                a = self.INC_BUF_ADDR(addr)
                for _ in range(n):
                        if self.fa_buffer[a] and not (self.fa_buffer[a] & FA_PROTECTED):
                                return self.INC_BUF_ADDR(a)
                        a = self.INC_BUF_ADDR(a)
                return 0

        def _program_tab( self ):
                """PT: null to end of unprotected field, then next unprotected field."""
                fa = self._fa_containing(self.buffer_address)
                in_unprot = (
                        fa is not None
                        and not (self.fa_buffer[fa] & FA_PROTECTED)
                        and self.buffer_address != fa
                )
                if in_unprot:
                        a = self.buffer_address
                        start = a
                        while self.fa_buffer[a] == 0:
                                self.buffer[a] = 0
                                a = self.INC_BUF_ADDR(a)
                                if a == start:
                                        break
                self.buffer_address = self._next_unprotected(self.buffer_address)

        def _set_mdt_at( self, addr ):
                fa = self._fa_containing(addr)
                if fa is not None:
                        self.fa_buffer[fa] = self.fa_buffer[fa] | FA_MDT

        def _erase_unprotected_to( self, stop_addr ):
                """EUA: null unprotected cells up to but not including stop_addr.

                When stop equals the current address, wrap the whole screen once
                (same exclusive-fill rule as RA). Field-attribute cells are left
                intact. MDT is cleared on every unprotected field that was touched.
                """
                if self.buffer_address == stop_addr:
                        n = self.screen_size
                else:
                        n = 0
                        addr = self.buffer_address
                        while addr != stop_addr and n < self.screen_size:
                                n = n + 1
                                addr = self.INC_BUF_ADDR(addr)
                touched = set()
                for _ in range(n):
                        addr = self.buffer_address
                        if self.fa_buffer[addr]:
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                continue
                        owner = self._fa_containing(addr)
                        if owner is None or not (self.fa_buffer[owner] & FA_PROTECTED):
                                self.buffer[addr] = 0
                                if owner is not None:
                                        touched.add(owner)
                        self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                for owner in touched:
                        self.fa_buffer[owner] = self.fa_buffer[owner] & ~FA_MDT

        def process_read( self ):
                """Read Buffer: AID, cursor, then SF+attr or data for every cell."""
                self.output_buffer = []
                self.msg(1,"Generating Read Buffer")
                self.output_buffer.append(self.aid)
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
                mode = getattr(self, 'reply_mode', SF_SRM_FIELD)
                if self.formatted:
                        if mode == SF_SRM_XFIELD:
                                self._read_buffer_extended()
                        elif mode == SF_SRM_CHAR:
                                self._read_buffer_character()
                        else:
                                for i in range(self.screen_size):
                                        if self.fa_buffer[i]:
                                                self.output_buffer.append(SF)
                                                self.output_buffer.append(self.fa_buffer[i])
                                        else:
                                                self.output_buffer.append(self.buffer[i])
                else:
                        self.output_buffer.append(bytes(self.buffer))
                return self.send_tn3270(self.output_buffer)

        def _emit_sfe( self, fa_addr ):
                """SFE with basic FA plus stored highlight/color/charset."""
                self._ensure_attr_buffers()
                pairs = [(SFE_FA, self.fa_buffer[fa_addr])]
                hl = self.field_hl[fa_addr] if fa_addr < len(self.field_hl) else 0
                fg = self.field_fg[fa_addr] if fa_addr < len(self.field_fg) else 0
                cs = self.field_cs[fa_addr] if fa_addr < len(self.field_cs) else 0
                if hl:
                        pairs.append((SFE_HIGHLIGHT, hl))
                if fg:
                        pairs.append((SFE_COLOR, fg))
                if cs:
                        pairs.append((SFE_CHARSET, cs))
                self.output_buffer.append(SFE)
                self.output_buffer.append(len(pairs))
                for typ, val in pairs:
                        self.output_buffer.append(typ)
                        self.output_buffer.append(val)

        def _read_buffer_extended( self ):
                for i in range(self.screen_size):
                        if self.fa_buffer[i]:
                                self._emit_sfe(i)
                        else:
                                self.output_buffer.append(self.buffer[i])

        def _read_buffer_character( self ):
                """Best-effort character mode: SA when fg/hl changes, then data."""
                self._ensure_attr_buffers()
                last_fg = None
                last_hl = None
                for i in range(self.screen_size):
                        if self.fa_buffer[i]:
                                self.output_buffer.append(SF)
                                self.output_buffer.append(self.fa_buffer[i])
                                last_fg = None
                                last_hl = None
                                continue
                        fg = self.fg_buffer[i] if i < len(self.fg_buffer) else 0
                        hl = self.hl_buffer[i] if i < len(self.hl_buffer) else 0
                        if hl != last_hl:
                                self.output_buffer.append(SA)
                                self.output_buffer.append(XA_HIGHLIGHT)
                                self.output_buffer.append(hl)
                                last_hl = hl
                        if fg != last_fg:
                                self.output_buffer.append(SA)
                                self.output_buffer.append(XA_FGCOLOR)
                                self.output_buffer.append(fg)
                                last_fg = fg
                        self.output_buffer.append(self.buffer[i])

        def process_read_modified(self, aid, all_fields=False):
                """Read Modified: AID, cursor, then SBA+data for modified fields.

                CLEAR/PA are a short read (AID only). all_fields True is RMA:
                every field, not only MDT. Extended-field reply mode prefixes
                each field with SFE; character mode is best-effort SA runs.
                """
                if aid is None:
                        aid = self.aid
                self.output_buffer = []
                self.msg(1,"Generating Read Modified Buffer")
                self.output_buffer.append(aid)
                if aid in (CLEAR, PA1, PA2, PA3):
                        return self.send_tn3270(self.output_buffer)
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
                if not self.formatted:
                        for b in self.buffer:
                                if b:
                                        self.output_buffer.append(b)
                        return self.send_tn3270(self.output_buffer)
                mode = getattr(self, 'reply_mode', SF_SRM_FIELD)
                n = self.screen_size
                for i in range(n):
                        fa = self.fa_buffer[i]
                        if not fa:
                                continue
                        if not all_fields and not (fa & FA_MDT):
                                continue
                        start = self.INC_BUF_ADDR(i)
                        self.output_buffer.append(SBA)
                        self.output_buffer.append(self.ENCODE_BADDR(start))
                        if mode == SF_SRM_XFIELD:
                                self._emit_sfe(i)
                        j = start
                        last_fg = None
                        last_hl = None
                        while self.fa_buffer[j] == 0:
                                if mode == SF_SRM_CHAR:
                                        self._ensure_attr_buffers()
                                        fg = self.fg_buffer[j]
                                        hl = self.hl_buffer[j]
                                        if hl != last_hl:
                                                self.output_buffer.append(SA)
                                                self.output_buffer.append(XA_HIGHLIGHT)
                                                self.output_buffer.append(hl)
                                                last_hl = hl
                                        if fg != last_fg:
                                                self.output_buffer.append(SA)
                                                self.output_buffer.append(XA_FGCOLOR)
                                                self.output_buffer.append(fg)
                                                last_fg = fg
                                if self.buffer[j]:
                                        self.output_buffer.append(self.buffer[j])
                                j = self.INC_BUF_ADDR(j)
                                if j == start:
                                        break
                return self.send_tn3270(self.output_buffer)

        def w_structured_field ( self, wsf_data ):
                wsf_cmd = wsf_data[1:] #skip the wsf command
                bufflen = len(wsf_cmd)

                self.msg(1,"Processing TN3270 Write Structured Field Command")
                while bufflen > 0:
                        if bufflen < 2:
                                self.msg(1,"Write Structured Field too short")
                                return PDS_BAD_CMD
                        fieldlen = (wsf_cmd[0] << 8) + wsf_cmd[1]

                        self.msg(1,"[WSF] Field Length: %s", fieldlen)

                        if (fieldlen == 0):
                                fieldlen = bufflen
                        if (fieldlen < 3):
                                self.msg(1,"error: field length", fieldlen," too small")
                                return PDS_BAD_CMD
                        if fieldlen > bufflen:
                                self.msg(1,"error: field length", fieldlen," larger than buffer length %s", bufflen)
                                return PDS_BAD_CMD

                        if wsf_cmd[2] == SF_READ_PART:
                                self.msg(1,"[WSF] Structured Field Read Partition")
                                self.read_partition(wsf_cmd[3:fieldlen])
                        elif wsf_cmd[2] == SF_ERASE_RESET:
                                self.msg(1,"[WSF] Structured Field Erase Reset")
                                self.erase_reset(wsf_cmd[3:fieldlen])
                        elif wsf_cmd[2] == SF_SET_REPLY_MODE:
                                self.msg(1,"[WSF] Structured Field Set Reply Mode")
                                self.set_reply_mode(wsf_cmd[3:fieldlen])
                        elif wsf_cmd[2] == SF_CREATE_PART:
                                self.msg(1,"[WSF] Structured Field Create Partition")
                                #rv_this = self.sf_create_partition(wsf_cmd[3:fieldlen], fieldlen)
                                # Do nothing for now other than print
                        elif wsf_cmd[2] == SF_OUTBOUND_DS:
                                self.msg(1,"[WSF] Structured Field Outbound DS")
                                rv = self.outbound_ds(wsf_cmd[3:fieldlen])
                                if rv in (BAD_COMMAND, BAD_ADDRESS, PDS_BAD_CMD):
                                        return rv
                        elif wsf_cmd[2] ==  SF_TRANSFER_DATA:   #File transfer data
                                self.msg(1,"[WSF] Structured Field File Transfer Data")
                                self.file_transfer(wsf_cmd[:fieldlen])
                        else:
                                self.msg(1,"[WSF] unsupported ID", wsf_cmd[2])
                                return PDS_BAD_CMD
                        wsf_cmd = wsf_cmd[fieldlen:]
                        bufflen = bufflen - fieldlen
                return NO_OUTPUT

        def read_partition(self, data):
                """ Structured field read partition """
                if len(data) < 2:
                        self.msg(1,"[WSF] error: field length %d too short", len(data))
                        return PDS_BAD_CMD
                partition = data[0]
                self.msg(1,"[WSF] Partition ID " + hex(data[0]))
                if data[1] == SF_RP_QUERY or data[1] == SF_RP_QLIST:
                        self.msg(1,"[WSF] Read Partition Query")
                        if partition != 0xff:
                                self.msg(1,"Invalid Partition ID: %r", partition)
                                return PDS_BAD_CMD
                        query_options = build_query_reply(
                                getattr(self, 'default_rows', ROWS),
                                getattr(self, 'default_cols', COLS),
                                getattr(self, 'alt_rows', ROWS),
                                getattr(self, 'alt_cols', COLS),
                                getattr(self, 'codepage', 'cp037'))
                        self.send_tn3270(query_options)
                return

        def outbound_ds(self, data):
                """ Does something with outbound ds """
                if len(data) < 2:
                        self.msg(1,"[WSF] error: field length %d too short", len(data))
                        return PDS_BAD_CMD
                self.msg(1,"[WSF] Outbound DS value " + hex(data[0]))
                if data[0] != 0:
                        self.msg(1,"OUTBOUND_DS: Position 0 expected 0 got %s", data[0])

                if data[1] == SNA_W:
                        self.msg(1,"       - Write ")
                        return self.process_write(data[1:]) #skip the type value when we pass to process write
                elif data[1] == SNA_EW:
                        self.msg(1,"       - Erase/Write")
                        self._use_default_size()
                        self.clear_screen()
                        return self.process_write(data[1:])
                elif data[1] == SNA_EWA:
                        self.msg(1,"       - Erase/Write/Alternate")
                        self._use_alternate_size()
                        self.clear_screen()
                        return self.process_write(data[1:])
                elif data[1] == SNA_EAU:
                        self.msg(1,"       - Erase all Unprotected")
                        self.clear_unprotected()
                        return NO_OUTPUT
                else:
                        self.msg(1,"unknown type "+ hex(data[0]))
                        return PDS_BAD_CMD

        def set_reply_mode( self, data ):
                """Honor Set Reply Mode: field / extended-field / character."""
                if len(data) < 2:
                        self.msg(1,"set_reply_mode truncated")
                        return PDS_BAD_CMD
                partition = data[0]
                mode = data[1]
                self.msg(1,"Set Reply Mode partition=%r mode=%r", partition, mode)
                if mode in (SF_SRM_FIELD, SF_SRM_XFIELD, SF_SRM_CHAR):
                        self.reply_mode = mode
                else:
                        self.msg(1,"unknown reply mode %r, keeping %r",
                                 mode, getattr(self, 'reply_mode', SF_SRM_FIELD))
                return NO_OUTPUT

        def erase_reset(self, data):
                """ Process Structured Field Erase Reset command """
                """ To Do: Add seperate paritions"""
                if len(data) < 2:
                        self.msg(1,"erase_reset truncated")
                        return PDS_BAD_CMD
                if data[1] == SF_ER_DEFAULT:
                        self._use_default_size()
                        self.clear_screen()
                elif data[1] == SF_ER_ALT:
                        self._use_alternate_size()
                        self.clear_screen()
                else:
                        self.msg(1,"Error with data type in erase_reset: %s", data[1])
