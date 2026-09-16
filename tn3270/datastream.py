"""3270 data stream processing."""

import struct
import binascii
import math

from .constants import *
from .ebcdic import _ebcdic_to_str


class DataStreamMixin:
        """Buffer addressing, orders, inbound reads and structured fields."""

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
                """ Returns the current row of a buffer address """
                return math.ceil((addr / COLS) + 0.5)

        def BA_TO_COL( self, addr ):
                """ Returns the current column of a buffer address """
                return addr % COLS

        def INC_BUF_ADDR( self, addr ):
                """ Increments the buffer address by one """
                return ((addr + 1) % (COLS * ROWS))

        def DEC_BUF_ADDR( self, addr ):
                """ Decreases the buffer address by one """
                return ((addr - 1) % (COLS * ROWS))

        def BA_EQU( self, a, b ):
                """ True if two buffer addresses refer to the same cell. """
                return ((a - b) % (COLS * ROWS)) == 0

        def process_3270( self, data ):
                """ Processes TN3270 Data """
            ## the first byte will be the command we have to follow
                com = data[0]
                self.msg(1,"Value Received: %r", com)
                if ( com == EAU or com == SNA_EAU ):
                        self.msg(1,"TN3270 Command: Erase All Unprotected")
                        self.clear_unprotected()
                        return NO_OUTPUT
                elif ( com == EWA or com == SNA_EWA or
                           com == EW  or com == SNA_EW  ):
                        self.msg(1,"TN3270 Command: Erase Write (Alternate)")
                        self.clear_screen()
                        self.process_write(data) ##so far should only return No Output
                        return NO_OUTPUT
                elif com == W or com == SNA_W:
                        self.msg(1,"TN3270 Command: Write")
                        self.process_write(data)
                        return NO_OUTPUT
                elif com == RB  or com == SNA_RB:
                        self.msg(1,"TN3270 Command: Read Buffer")
                        self.process_read()
                        return OUTPUT
                elif ( com == RM  or com == SNA_RM  or
                           com == RMA or com == SNA_RMA ):
                        self.msg(1,"TN3270 Command: Read Modified (All)")
                        self.process_read_modified(self.aid)
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

                i = 1
                self.keyboard_locked = True
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
                                prev = 'ORDER'
                                last_cmd = True
                                i = i + 1 # skip SF
                                self.msg(2,"Writting Zero to buffer at address: %r",self.buffer_address)
                                self.msg(2,"Attribute Type: %r", data[i])
                                self.write_char(0)
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                self.write_field_attribute(data[i])
                                self.formatted = True
                                #set the current position one ahead (after SF)
                                i = i + 1

                        elif cp == SFE:
                                self.msg(2,"Start Field Extended")
                                i = i + 1 # skip SFE
                                num_attr = data[i]
                                self.msg(2,"Number of Attributes: %r", num_attr)
                                self.msg(2,"Writting Zero to buffer at address: %r", self.buffer_address)
                                self.write_char(0)
                                for j in range(num_attr):
                                        i = i + 1
                                        if data[i] == 0xc0:
                                                # 0xc0 represent field attributes
                                                # since we don't support colors (yet)
                                                # we ignore the other values
                                                self.msg(2,"Attribute Type: %r", data[i+1])
                                                self.fa_buffer[self.buffer_address] = data[i+1]
                                        i = i + 1
                                self.formatted = True
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                i = i + 1
                                
                        elif cp == SBA:
                                self.msg(2,"Set Buffer Address (SBA) 0x11")
                                self.buffer_address = self.DECODE_BADDR(data[i + 1],
                                                                                                                data[i + 2])
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
                                ra_baddr = self.DECODE_BADDR(data[i + 1],
                                                     data[i + 2])
                                self.msg(2,"Repeat Character: %r" , data[i + 1])
                                self.msg(2,"Repeat to this Address: %r" , ra_baddr)
                                self.msg(2,"Currrent Address: %r", self.buffer_address)
                                prev = 'ORDER'
                                i = i + 3
                                char_to_repeat = data[i]
                                self.msg(2,"Repeat Character: %r" ,char_to_repeat)
                                while (self.buffer_address != ra_baddr):
                                        self.write_char(char_to_repeat)
                                        self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                        elif cp == EUA:
                                self.msg(2,"Erase All Unprotected (EAU) 0x12")
                                eua_baddr = self.DECODE_BADDR(data[i + 1],
                                                      data[i + 2])
                                i = i + 3
                                self.msg(2,"EAU to this Address: %r" , eua_baddr)
                                self.msg(2,"Currrent Address: %r",  self.buffer_address)
                                while (self.buffer_address != eua_baddr):
                                        # do nothing for now. this feature isn't supported/required at the moment
                                        # we're technically supposed to delete the buffer
                                        # but we might want to see whats on there!
                                        self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                        elif cp == GE:
                                self.msg(2,"Graphical Escape (GE) 0x08")
                                prev = 'ORDER'
                                i = i + 1 # move to next byte
                                ge_char = data[i]
                                self.write_char(ge_char)
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                        elif cp == MF:
                                # we don't actually have 'fields' at this point
                                # so there's nothing to be modified
                                self.msg(2,"Modify Field (MF) 0x2C")
                                prev = 'ORDER'
                                i = i + 1
                                num_attr = int(data[i])
                                for j in range(num_attr):
                                #placeholder in case we need to do something here
                                        i = i + 1
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                        elif cp == SA:
                                self.msg(2,"Set Attribute (SA) 0x28")
                                # SA is followed by a 1-byte type and 1-byte value.
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
                                self.write_char(0o64)
                                self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                                i = i + 1
                        else: # whoa we made it.
                                ascii_char = _ebcdic_to_str(cp)
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

        def write_field_attribute( self, attr ):
                """ Writes Field attributes to the field attribute buffer """
                if isinstance(attr, (bytes, bytearray)):
                        attr = attr[0]
                self.fa_buffer[self.buffer_address-1] = attr

        def _reset_mdt( self ):
                """Clear the MDT bit on every field attribute (WCC reset MDT)."""
                for i, fa in enumerate(self.fa_buffer):
                        if fa:
                                self.fa_buffer[i] = fa & ~FA_MDT

        def _fa_containing( self, addr ):
                """0-based index of the field attribute that owns addr, or None."""
                n = COLS * ROWS
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
                n = COLS * ROWS
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

        def process_read( self ):
                """Read Buffer: AID, cursor, then SF+attr or data for every cell."""
                self.output_buffer = []
                self.msg(1,"Generating Read Buffer")
                self.output_buffer.append(self.aid)
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
                if self.formatted:
                        for i in range(SCREEN_SIZE):
                                if self.fa_buffer[i]:
                                        self.output_buffer.append(SF)
                                        self.output_buffer.append(self.fa_buffer[i])
                                else:
                                        self.output_buffer.append(self.buffer[i])
                else:
                        self.output_buffer.append(bytes(self.buffer))
                return self.send_tn3270(self.output_buffer)

        def process_read_modified(self, aid):
                """Read Modified: AID, cursor, then SBA+data for each MDT field (nulls omitted)."""
                if aid is None:
                        aid = self.aid
                self.output_buffer = []
                self.msg(1,"Generating Read Modified Buffer")
                self.output_buffer.append(aid)
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
                if aid in (CLEAR, PA1, PA2, PA3):
                        return self.send_tn3270(self.output_buffer)
                if not self.formatted:
                        for b in self.buffer:
                                if b:
                                        self.output_buffer.append(b)
                        return self.send_tn3270(self.output_buffer)
                n = SCREEN_SIZE
                for i in range(n):
                        fa = self.fa_buffer[i]
                        if not fa or not (fa & FA_MDT):
                                continue
                        start = self.INC_BUF_ADDR(i)
                        self.output_buffer.append(SBA)
                        self.output_buffer.append(self.ENCODE_BADDR(start))
                        j = start
                        while self.fa_buffer[j] == 0:
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
                        fieldlen = (wsf_cmd[0] << 8) + wsf_cmd[1]

                        self.msg(1,"[WSF] Field Length: %s", fieldlen)

                        if (fieldlen == 0):
                                fieldlen = bufflen
                        if (fieldlen < 3):
                                self.msg(1,"error: field length", fieldlen," too small")
                                return False
                        if fieldlen > bufflen:
                                self.msg(1,"error: field length", fieldlen," larger than buffer length %s", bufflen)

                        if wsf_cmd[2] == SF_READ_PART:
                                self.msg(1,"[WSF] Structured Field Read Partition")
                                self.read_partition(wsf_cmd[3:fieldlen])
                        elif wsf_cmd[2] == SF_ERASE_RESET:
                                self.msg(1,"[WSF] Structured Field Erase Reset")
                                self.erase_reset(wsf_cmd[3:fieldlen])
                        elif wsf_cmd[2] == SF_SET_REPLY_MODE:
                                self.msg(1,"[WSF] Structured Field Set Reply Mode")
                                #rv_this = self.set_reply_mode(wsf_cmd[3:fieldlen], fieldlen)
                                # Do nothing for now other than print
                        elif wsf_cmd[2] == SF_CREATE_PART:
                                self.msg(1,"[WSF] Structured Field Create Partition")
                                #rv_this = self.sf_create_partition(wsf_cmd[3:fieldlen], fieldlen)
                                # Do nothing for now other than print
                        elif wsf_cmd[2] == SF_OUTBOUND_DS:
                                self.msg(1,"[WSF] Structured Field Outbound DS")
                                self.outbound_ds(wsf_cmd[3:fieldlen])
                        elif wsf_cmd[2] ==  SF_TRANSFER_DATA:   #File transfer data
                                self.msg(1,"[WSF] Structured Field File Transfer Data")
                                self.file_transfer(wsf_cmd[:fieldlen])
                        else:
                                self.msg(1,"[WSF] unsupported ID", wsf_cmd[2])
                                rv_this = PDS_BAD_CMD
                        wsf_cmd = wsf_cmd[fieldlen:]
                        bufflen = bufflen - fieldlen

        def read_partition(self, data):
                """ Structured field read partition """
                partition = data[0]
                if len(data) < 2:
                        self.msg(1,"[WSF] error: field length %d too short", len(data))
                        return PDS_BAD_CMD
                self.msg(1,"[WSF] Partition ID " + hex(data[0]))
                if data[1] == SF_RP_QUERY:
                        self.msg(1,"[WSF] Read Partition Query")
                        if partition != 0xff:
                                self.msg(1,"Invalid Partition ID: %r", parition)
                                return PDS_BAD_CMD
                        # this ugly thing passes the query options
                        # I hate it but its better than actually writing query options
                        # Use Wireshark to see what exactly is happening here
                        query_options = binascii.unhexlify(
                                        "88000e81808081848586878895a1a60017818101000050001801000a0" +
                                        "2e50002006f090c07800008818400078000001b81858200090c000000" +
                                        "000700100002b900250110f103c3013600268186001000f4f1f1f2f2f" +
                                        "3f3f4f4f5f5f6f6f7f7f8f8f9f9fafafbfbfcfcfdfdfefeffffffff00" +
                                        "0f81870500f0f1f1f2f2f4f4f8f800078188000102000c81950000100" +
                                        "010000101001281a1000000000000000006a3f3f2f7f0001181a6000" +
                                        "00b01000050001800500018ffef")
                        if self.state == TN3270E_DATA: query_options = (b'\x00' * 5) + query_options
                        self.send_data(query_options)
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
                        self.process_write(data[1:]) #skip the type value when we pass to process write
                elif data[1] == SNA_EW:
                        self.msg(1,"       - Erase/Write")
                        self.clear_screen()
                        self.process_write(data[1:])
                elif data[1] == SNA_EWA:
                        self.msg(1,"       - Erase/Write/Alternate")
                        self.clear_screen()
                        self.process_write(data[1:])
                elif data[1] == SNA_EAU:
                        self.msg(1,"       - Erase all Unprotected")
                        self.clear_unprotected()
                else:
                        self.msg(1,"unknown type "+ hex(data[0]))

        def erase_reset(self, data):
                """ Process Structured Field Erase Reset command """
                """ To Do: Add seperate paritions"""
                if data[1] == SF_ER_DEFAULT or data[1] == SF_ER_ALT:
                        self.clear_screen()
                else:
                        self.msg(1,"Error with data type in erase_reset: %s", data[1])
