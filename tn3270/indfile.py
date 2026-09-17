"""IND$FILE DFT file transfer.

Kept apart from the rest of the client so host-side TSO quirks
stay contained in this module."""

import re
import struct

from .constants import *


def _chunk_len(chunk):
    if isinstance(chunk, int):
        return 1
    return len(chunk)


# Quoted fully-qualified DSN, or unquoted name: letters, digits, period, parens.
_DSN_RE = re.compile(r"^(?:'[A-Za-z0-9.()]{1,56}'|[A-Za-z0-9.()]{1,56})$")


def _valid_dataset(dataset):
    """True if dataset cannot inject a TSO command through IND$FILE."""
    if not isinstance(dataset, str) or not dataset:
        return False
    if any(c in dataset for c in ';\n\r|& \t'):
        return False
    return _DSN_RE.fullmatch(dataset) is not None


def _chunk_len(chunk):
    if isinstance(chunk, int):
        return 1
    return len(chunk)


class IndFileMixin:
        """Transfer files to and from the host with IND$FILE.

        IND$FILE runs under TSO, so `dataset` follows TSO naming rules: an
        unquoted name is prefixed with the logged-on userid. Pass
        "'PHIL.TN3270.TEXT'" (quotes included) to address a fully qualified
        name; "PHIL.TN3270.TEXT" would become PHIL.PHIL.TN3270.TEXT.
        """

        def file_transfer(self, data):
                """ Handles Write Structured Fields file transfer requests 
                    based on ft_dft_data.c and modified for this library """

                if self.ft_state == FT_NONE:
                        return

                length = data[0:2]
                command = data[2]
                request_type = data[3:5]
                if len(data) > 5:
                        compress_indicator = data[5:7]
                        begin_data = data[7]
                        data_len = data[8:10]
                        received_data = data[10:]

                data_length = self.ret_16(length)
                data_type   = self.ret_16(request_type)
                if data_type == TR_OPEN_REQ:
                        
                        if data_length == 35:
                                name = received_data[18:]
                                #name = ""
                                self.msg(1,"[WSF] File Transfer: Open Recieved: Message: %s", name)
                        elif data_length == 41:
                                name = received_data[24:]
                                recsz = self.ret_16(received_data[20:22])
                                self.msg(1,"[WSF] File Transfer: Message Received: %s, Size: %d", name, recsz)
                        else:
                                self.abort(TR_OPEN_REQ)
                        
                        if name == b"FT:MSG ":
                                self.message_flag = True
                        else:
                                self.message_flag = False
                        
                        self.dft_eof = False
                        self.recnum = 1
                        self.dft_ungetc_count = 0
                        self.msg(1,"[WSF] File Transfer: Sending Open Acknowledgement")
                        self.output_buffer = []
                        self.output_buffer.append(AID_SF)
                        self.output_buffer.append(self.set_16(5))
                        self.output_buffer.append(SF_TRANSFER_DATA)
                        self.output_buffer.append(self.set_16(9))
                        # Send the acknowledgement package
                        self.send_tn3270(self.output_buffer)

                elif data_type == TR_DATA_INSERT:
                        self.msg(1,"[WSF] File Transfer: Data Insert")
                        my_len = data_length - 5

                        if self.message_flag:
                                if received_data[0:7] == b"TRANS03":
                                        self.msg(1,"[WSF] File Transfer: File Transfer Complete!")
                                        self.msg(1,"[WSF] File Transfer: Message: %s", received_data.strip())
                                        self.ft_state = FT_NONE
                                else:
                                        self.msg(1,"[WSF] File Transfer: ERROR ERROR ERROR. There was a problem.")
                                        self.msg(1,"[WSF] File Transfer: Message: %s", received_data)
                                        self.ft_state = FT_NONE
                        elif (my_len > 0):
                                #We didn't get a message so it must be data!
                                self.msg(1,"[WSF] File Transfer Insert: record number: %d | bytes: %d", self.recnum, my_len)
                                bytes_writen = 0
                                blob = received_data
                                if isinstance(blob, (bytes, bytearray)):
                                        pass
                                else:
                                        blob = bytes(blob)
                                if self.ascii_file:
                                        blob = bytes(b for b in blob if b not in (0x0d, 0x1a))
                                if blob:
                                        self.file.write(blob)
                                        bytes_writen = len(blob)
                                self.msg(1,"[WSF] File Transfer Insert: Bytes Writen: %d", bytes_writen)
                        self.msg(1,"[WSF] File Transfer Insert: Data Ack: record number: %d", self.recnum)
                        self.output_buffer = []
                        self.output_buffer.append(AID_SF)
                        self.output_buffer.append(self.set_16(11))
                        self.output_buffer.append(SF_TRANSFER_DATA)
                        self.output_buffer.append(self.set_16(TR_NORMAL_REPLY))
                        self.output_buffer.append(self.set_16(TR_RECNUM_HDR))
                        self.output_buffer.append(self.set_32(self.recnum))
                        self.recnum = self.recnum + 1
                        # Send the acknowledgement package
                        self.send_tn3270(self.output_buffer)

                elif data_type == TR_GET_REQ:
                        self.msg(1,"[WSF] File Transfer: Get Data")

                        total_read = 0
                        temp_buf = []
                        # Alright lets send some data!
                        if self.ft_buffersize == 0:
                                self.ft_buffersize = DFT_BUF

                        if self.ft_buffersize > DFT_MAX_BUF:
                                self.ft_buffersize = DFT_MAX_BUF
                        elif self.ft_buffersize < DFT_MIN_BUF:
                                self.ft_buffersize = DFT_MIN_BUF

                        numbytes = self.ft_buffersize - 27 #how many bytes can we send
                        self.msg(1,"[WSF] File Transfer Current Buffer Size: %d", self.ft_buffersize)
                        self.output_buffer = []#skip the header values for now
                        self.output_buffer.append(AID_SF)
                        self.output_buffer.append(0) # blank size for now
                        self.output_buffer.append(0)
                        self.output_buffer.append(SF_TRANSFER_DATA)

                        temp_buf, total_read, self.dft_eof = self._read_ft_chunk(numbytes)
                        if(total_read > 0):
                                self.msg(1,"[WSF] File Transfer: Record Number: %d | Sent %d bytes", self.recnum, total_read)
                                self.output_buffer.append(self.set_16(TR_GET_REPLY))
                                self.output_buffer.append(self.set_16(TR_RECNUM_HDR))
                                self.output_buffer.append(self.set_32(self.recnum))
                                self.recnum = self.recnum + 1
                                self.output_buffer.append(self.set_16(TR_NOT_COMPRESSED))
                                self.output_buffer.append(TR_BEGIN_DATA)
                                self.output_buffer.append(self.set_16(total_read + 5))
                                self.output_buffer.extend(temp_buf)
                        else:
                                self.msg(1,"[WSF] File Transfer: EOF")
                                self.output_buffer.append(self.HIGH8(TR_GET_REQ))
                                self.output_buffer.append(TR_ERROR_REPLY)
                                self.output_buffer.append(self.set_16(TR_ERROR_HDR))
                                self.output_buffer.append(self.set_16(TR_ERR_EOF))
                                self.dft_eof = True

                        # Set the length now
                        o_len = 0
                        for i in self.output_buffer:
                                o_len += _chunk_len(i)
                        t_len = self.set_16(o_len-1) # minus one because we shouldn't count AID_SF
                        self.output_buffer[1] = t_len[0]
                        self.output_buffer[2] = t_len[1]
                        self.send_tn3270(self.output_buffer)
                elif data_type == TR_CLOSE_REQ:
                        self.msg(1,"[WSF] Close Request")
                        self.output_buffer = []
                        self.output_buffer.append(AID_SF)
                        self.output_buffer.append(self.set_16(5))
                        self.output_buffer.append(SF_TRANSFER_DATA)
                        self.output_buffer.append(self.set_16(TR_CLOSE_REPLY))
                        self.send_tn3270(self.output_buffer)
                elif data_type == TR_INSERT_REQ:
                        self.msg(1,"[WSF] File Transfer: Insert") #We literally don't do anything

                elif data_type == TR_SET_CUR_REQ:
                        self.msg(1,"[WSF] File Transfer: Set Cursor") #We don't do anything here either

        def ret_16(self, value):
                """ unpacks 3270 byte order """
                byte1 = value[0]
                byte2 = value[1]
                return byte2 + (byte1 << 8)

        def set_16(self, value):
                """ packs 3270 byte order """
                b1 = struct.pack(">B",(value & 0xFF00) >> 8)
                b2 = struct.pack(">B",(value & 0xFF))
                return ( b1 + b2 )

        def set_32(self, value):
                """ converts number in to 4 bytes for structured fields """
                b1 = struct.pack(">B",(value & 0xFF000000) >> 24)
                b2 = struct.pack(">B",(value & 0xFF0000) >> 16)
                b3 = struct.pack(">B",(value & 0xFF00) >> 8)
                b4 = struct.pack(">B",(value & 0xFF))
                return b1 + b2 + b3 + b4

        def HIGH8(self, s):
                return struct.pack(">B",(s >> 8 ) & 0xFF)

        def _read_ft_chunk(self, numbytes):
                """Read up to numbytes from the local file (ASCII NL -> CR/LF)."""
                if getattr(self, 'dft_eof', False) or numbytes <= 0:
                        return [], 0, True
                if self.ascii_file:
                        raw = self.file.read(max(1, numbytes // 2))
                else:
                        raw = self.file.read(numbytes)
                if not raw:
                        return [], 0, True
                if self.ascii_file:
                        out = raw.replace(b'\n', b'\r\n')
                        if len(out) > numbytes:
                                out = out[:numbytes]
                else:
                        out = raw
                return [out], len(out), False

        def abort(self, code):
                self.msg(1,"File Transfer - ABORT ABORT ABORT")
                self.output_buffer = []
                self.output_buffer.append(AID_SF)
                self.output_buffer.append(self.set_16(9))
                self.output_buffer.append(SF_TRANSFER_DATA)
                self.output_buffer.append(self.HIGH8(code))
                self.output_buffer.append(TR_ERROR_REPLY)
                self.output_buffer.append(self.set_16(TR_ERROR_HDR))
                self.output_buffer.append(self.set_16(TR_ERR_CMDFAIL))
                self.send_tn3270(self.output_buffer)
                self.output_buffer = []
                self.ft_state = FT_NONE

        def _drive_transfer(self, timeout=2, max_idle=8):
                """Pump the DFT exchange until the host reports the transfer done.

                Gives up once the host has been silent for max_idle rounds. Without
                that bail-out a rejected IND$FILE command (bad data set name, IND$FILE
                not installed) leaves the caller receiving forever with a live session
                on the host.
                """
                idle = 0
                while self.ft_state != FT_NONE:
                        before = len(self.raw_tn)
                        self.get_all_data(timeout)
                        if len(self.raw_tn) == before:
                                idle += 1
                                if idle >= max_idle:
                                        self.msg(1,"FILE TRANSFER: host stopped responding, abandoning transfer")
                                        self.ft_state = FT_NONE
                                        return False
                        else:
                                idle = 0
                return True

        def send_ascii_file(self, dataset,filename):
                """ Sends an ascii file using IND$FILE
                    This will replace NL with CL/RF """
                if not _valid_dataset(dataset):
                        self.msg(1,"FILE TRANSFER: rejected dataset name %r", dataset)
                        return False
                self.msg(1,"FILE TRANSFER: Writing %s to dataset %s at %s:%d in ASCII format", filename, dataset, self.host, self.port)
                self.ft_state = FT_AWAIT_ACK
                self.ascii_file = True
                self.filename = filename
                try:
                        with open(filename, "rb") as fh:
                                self.file = fh
                                self.send_cursor("IND$FILE PUT "+dataset+" ASCII CRLF")
                                ok = self._drive_transfer()
                finally:
                        self.file = None
                        self.ascii_file = False
                return ok

        def send_binary_file(self, dataset,filename):
                """ Sends a file using IND$FILE """
                if not _valid_dataset(dataset):
                        self.msg(1,"FILE TRANSFER: rejected dataset name %r", dataset)
                        return False
                self.msg(1,"FILE TRANSFER: Writing %s to dataset %s at %s:%d", filename, dataset, self.host, self.port)
                self.ft_state = FT_AWAIT_ACK
                self.ascii_file = False
                self.filename = filename
                try:
                        with open(filename, "rb") as fh:
                                self.file = fh
                                self.send_cursor("IND$FILE PUT "+dataset)
                                ok = self._drive_transfer()
                finally:
                        self.file = None
                return ok

        def get_ascii_file(self, dataset, filename):
                """ Gets a dataset from the Mainframe using ASCII
                    translation (mainframe does the translation) """
                if not _valid_dataset(dataset):
                        self.msg(1,"FILE TRANSFER: rejected dataset name %r", dataset)
                        return False
                self.msg(1,"FILE TRANSFER: Getting dataset %s from %s:%d writing to %s as ASCII", dataset, self.host, self.port, filename)
                self.ft_state = FT_AWAIT_ACK
                self.ascii_file = True
                self.filename = filename
                try:
                        with open(filename, 'wb') as fh:
                                self.file = fh
                                self.send_cursor("IND$FILE GET "+dataset+" ASCII CRLF")
                                ok = self._drive_transfer()
                finally:
                        self.file = None
                        self.ascii_file = False
                return ok

        def get_binary_file(self, dataset, filename):
                """ Gets a dataset from the mainframe without
                    any translation """
                if not _valid_dataset(dataset):
                        self.msg(1,"FILE TRANSFER: rejected dataset name %r", dataset)
                        return False
                self.msg(1,"FILE TRANSFER: Getting dataset %s from %s:%d writing to %s", dataset, self.host, self.port, filename)
                self.ft_state = FT_AWAIT_ACK
                self.ascii_file = False
                self.filename = filename
                try:
                        with open(filename, 'wb') as fh:
                                self.file = fh
                                self.send_cursor("IND$FILE GET "+dataset)
                                ok = self._drive_transfer()
                finally:
                        self.file = None
                return ok
