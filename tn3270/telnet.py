"""Telnet option negotiation and the TN3270E record layer."""

from .constants import *
from .transport import _bytes
from .bind import parse_bind_image


class TelnetMixin:
        """Negotiate telnet options and frame TN3270E records."""

        def process_packets( self ):
                """ Processes Telnet data """
                for i in self.telnet_data:
                        self.msg(2,"Processing: %r", i)
                        r = self.ts_processor(i)
                        if not r: return False
                        self.telnet_data = b'' #once all the data has been processed we clear out the buffer
                return True

        def ts_processor( self, data ):
                """ Consumes/Interprets Telnet/TN3270 data """
                TNS_DATA   = 0
                TNS_IAC    = 1
                TNS_WILL   = 2
                TNS_WONT   = 3
                TNS_DO     = 4
                TNS_DONT   = 5
                TNS_SB     = 6
                TNS_SB_IAC = 7
                DO_reply   = _bytes(IAC, DO)
                DONT_reply = _bytes(IAC, DONT)
                WILL_reply = _bytes(IAC, WILL)
                WONT_reply = _bytes(IAC, WONT)

                #self.msg('State is: %r', self.telnet_state)
                if self.telnet_state == TNS_DATA:
                  if data == IAC:
                        ## got an IAC
                        self.telnet_state = TNS_IAC
                        return True
                  if self.state not in (TN3270_DATA, TN3270E_DATA):
                        self._append_nvt(data)
                        return True
                  self.store3270(data)
                elif self.telnet_state == TNS_IAC:
                  if data == IAC:
                        ## insert this 0xFF in to the buffer
                        if self.state not in (TN3270_DATA, TN3270E_DATA):
                          self._append_nvt(data)
                        else:
                          self.store3270(data)
                        self.telnet_state = TNS_DATA
                  elif data == TN_EOR:
                        ## we're at the end of the TN3270 data
                        ## let's process it and see what we've got
                        ## but only if we're in 3270 mode
                        if self.state == TN3270_DATA or self.state == TN3270E_DATA:
                          self.process_data()
                          if self._paint_pending:
                                self.first_screen = True
                                self._paint_pending = False
                        self.telnet_state = TNS_DATA
                  elif data == WILL: self.telnet_state = TNS_WILL
                  elif data == WONT: self.telnet_state = TNS_WONT
                  elif data == DO  : self.telnet_state = TNS_DO
                  elif data == DONT: self.telnet_state = TNS_DONT
                  elif data == SB  : 
                        self.telnet_state = TNS_SB
                        self.sb_options = bytearray()
                  else:
                        # RFC 854 NOP / DM / GA / ... and any other unknown IAC:
                        # ignore and return to data. Do not leave TNS_IAC.
                        self.msg(2, "Ignoring IAC 0x%02x", data)
                        self.telnet_state = TNS_DATA
                elif self.telnet_state == TNS_WILL:
                   if data in supported_options and not (data in self.unsupported_opts) :
                        self.msg(1, "<< IAC WILL %s", supported_options[data])
                        if not self.server_options.get(data, False): ## if we haven't already replied to this, let's reply
                          self.server_options[data] = True
                          self.send_data(_bytes(DO_reply, data))
                          self.msg(1,">> IAC DO %s", supported_options[data])
                          self.in3270()
                   else:
                        self.send_data(_bytes(DONT_reply, data))
                        self.msg(1,">> IAC DONT %r", data)
                   self.telnet_state = TNS_DATA
                elif self.telnet_state == TNS_WONT:
                  if self.server_options.get(data, False):
                        self.server_options[data] = False
                        self.send_data(_bytes(DONT_reply, data))
                        self.msg(1,"Sent WONT Reply %r", data)
                        self.in3270()
                  self.telnet_state = TNS_DATA
                elif self.telnet_state == TNS_DO:
                  if data in supported_options and not (data in self.unsupported_opts) :
                        self.msg(1,"<< IAC DO %s", supported_options[data])
                        if not self.client_options.get(data, False):
                          self.client_options[data] = True
                          self.send_data(_bytes(WILL_reply, data))
                          self.msg(1,">> IAC WILL %s", supported_options[data])
                          self.in3270()
                  else:
                        self.send_data(_bytes(WONT_reply, data))
                        self.msg(1,"Unsupported 'DO'.")
                        if data in options:
                                self.msg(1,">> IAC WONT %s", options[data])
                        else:
                                self.msg(1,">> IAC WONT %r", data)
                  self.telnet_state = TNS_DATA
                elif self.telnet_state == TNS_DONT:
                  if self.client_options.get(data, False):
                        self.client_options[data] = False
                        self.send_data(_bytes(WONT_reply, data))
                        self.msg(1,">> IAC DONT %r", data)
                        self.in3270()
                  self.telnet_state = TNS_DATA
                elif self.telnet_state == TNS_SB:
                  if data == IAC:
                        self.telnet_state = TNS_SB_IAC
                  else:
                        self.sb_options.append(data)
                elif self.telnet_state == TNS_SB_IAC:
                  if data == IAC:
                        # IAC IAC inside SB is a literal 0xFF.
                        self.sb_options.append(IAC)
                        self.telnet_state = TNS_SB
                  elif data == SE:
                        self.sb_options.append(data)
                        self.telnet_state = TNS_DATA
                        if self.state != TN3270E_DATA:
                                phrase = ''
                                for i in self.sb_options: 
                                        if i in telnet_options: phrase += telnet_options[i] + ' '
                                        elif i in telnet_commands: phrase += telnet_commands[i] + ' '
                                        elif i in supported_options: phrase += supported_options[i] + ' '
                                        else: phrase += '\\x%02x ' % i
                                self.msg(1,"<< IAC SB %s", phrase)
                        dtype = getattr(self, 'device_type', DEVICE_TYPE)
                        if (len(self.sb_options) >= 2 and
                            self.sb_options[0] == options['TTYPE'] and
                            self.sb_options[1] == SEND ):
                          self.msg(1,">> IAC SB TTYPE IS DEVICE_TYPE IAC SE")
                          self.send_data(_bytes(IAC, SB, options['TTYPE'], IS, dtype, IAC, SE))
                        elif (self.sb_options and
                              self.client_options.get(options['TN3270'], False) and
                              self.sb_options[0] == options['TN3270']):
                          if not self.negotiate_tn3270():
                                return False
                  else:
                        # Malformed SB (IAC not doubled and not SE): drop back to SB.
                        self.telnet_state = TNS_SB
                return True

        def negotiate_tn3270(self):
                """ Negotiates TN3270E Options. Which are different than Telnet 
                    starts if the server options requests IAC DO TN3270 """
                #self.msg(1,"TN3270E Option Negotiation")
                TN3270_REQUEST = {
                0 : 'BIND_IMAGE',
                1 : 'DATA_STREAM_CTL',
                2 : 'RESPONSES',
                3 : 'SCS_CTL_CODES',
                4 : 'SYSREQ'
                }

                phrase = ''
                tn_request = False

                for i in self.sb_options:
                        if tn_request and i in TN3270_REQUEST:
                                phrase += TN3270_REQUEST[i] + ' '
                                tn_request = False
                        elif i in tn3270_options: 
                                phrase += tn3270_options[i] + ' '
                                if i == TN3270E_REQUEST: tn_request = True
                        elif i in telnet_options: phrase += telnet_options[i] + ' '
                        elif i in telnet_commands: phrase += telnet_commands[i] + ' '
                        elif i in supported_options: phrase += supported_options[i] + ' '
                        else: phrase += '\\x%02x ' % i
                self.msg(1,"<< IAC SB %s", phrase)
                #print self.hexdump(self.sb_options)
                if len(self.sb_options) < 2:
                        self.msg(1,"TN3270E subnegotiation too short")
                        return True
                if self.sb_options[1] ==  TN3270E_SEND:
                        if len(self.sb_options) < 3:
                                self.msg(1,"TN3270E SEND subnegotiation too short")
                                return True
                        if self.sb_options[2] == TN3270E_DEVICE_TYPE:
                                dtype = getattr(self, 'device_type', DEVICE_TYPE)
                                if self.connected_lu == '':
                                        self.msg(1,">> IAC SB TN3270 TN3270E_DEVICE_TYPE TN3270E_REQUEST %s IAC SE", dtype)
                                        self.send_data(_bytes(IAC, SB, options['TN3270E'], TN3270E_DEVICE_TYPE, TN3270E_REQUEST, dtype, IAC, SE))
                                else:
                                        self.msg(1,">> IAC SB TN3270 TN3270E_DEVICE_TYPE TN3270E_REQUEST "+dtype+" CONNECT "+self.connected_lu+" IAC SE")
                                        self.send_data(_bytes(IAC, SB, options['TN3270E'], TN3270E_DEVICE_TYPE, TN3270E_REQUEST, dtype, TN_CONNECT, self.connected_lu, IAC, SE))
                elif self.sb_options[1] == TN3270E_DEVICE_TYPE:
                        if len(self.sb_options) < 3:
                                self.msg(1,"TN3270E DEVICE_TYPE subnegotiation too short")
                                return True
                        if self.sb_options[2] == TN3270E_REJECT:
                                self.msg(1, 'Received TN3270E_REJECT after sending LU %s', self.connected_lu)
                                return False
                        SE_location = self.sb_options.find(bytes((SE,)))
                        CONNECT_option = self.sb_options.find(bytes((TN3270E_CONNECT,)))
                        if CONNECT_option > 1 and CONNECT_option < SE_location:
                                self.connected_dtype = bytes(self.sb_options[3:CONNECT_option]).decode('ascii', 'replace')
                        else:
                                self.connected_dtype = bytes(self.sb_options[3:SE_location]).decode('ascii', 'replace')
                        if CONNECT_option > 1: 
                                self.connected_lu = bytes(self.sb_options[CONNECT_option+1:SE_location]).decode('ascii', 'replace')
                                #self.tn3270e_options(TN3270E_REQUEST)
                        self.msg(1,'Confirmed Terminal Type: %s',self.connected_dtype)
                        self.msg(1,'LU Name: %s', self.connected_lu)
                        self.msg(1,'>> IAC SB TN3270 TN3270E_FUNCTIONS TN3270E_REQUEST IAC SE')
                        self.send_data(_bytes(IAC, SB, options['TN3270E'], TN3270E_FUNCTIONS, TN3270E_REQUEST, IAC, SE))
                elif self.sb_options[1] == TN3270E_FUNCTIONS:
                        verb = self.sb_options[2] if len(self.sb_options) > 2 else None
                        if verb == TN3270E_IS:
                                funcs = bytes(self.sb_options[3:])
                                se_at = funcs.find(bytes((SE,)))
                                if se_at >= 0:
                                        funcs = funcs[:se_at]
                                self.tn3270e_functions = set(funcs) & TN3270E_SUPPORTED_FUNCTIONS
                                self.negotiated = True
                                self.msg(1,"TN3270 Negotiation Complete!")
                                self.in3270()
                        elif verb == TN3270E_REQUEST:
                                # Honor RESPONSES and SYSREQ. BIND_IMAGE is a
                                # data type we parse, not a FUNCTIONS bit.
                                funcs = bytes(self.sb_options[3:])
                                se_at = funcs.find(bytes((SE,)))
                                if se_at >= 0:
                                        funcs = funcs[:se_at]
                                accepted = bytes(b for b in funcs if b in TN3270E_SUPPORTED_FUNCTIONS)
                                self.tn3270e_functions = set(accepted)
                                self.msg(1,'>> IAC SB TN3270 TN3270E_FUNCTIONS TN3270E_IS IAC SE')
                                self.send_data(_bytes(IAC, SB, options['TN3270E'], TN3270E_FUNCTIONS, TN3270E_IS, accepted, IAC, SE))
                                self.negotiated = True
                                self.in3270()
                        else:
                                self.msg(1,'>> IAC SB TN3270 TN3270E_FUNCTIONS TN3270E_REQUEST IAC SE')
                                self.send_data(_bytes(IAC, SB, options['TN3270E'], TN3270E_FUNCTIONS, TN3270E_REQUEST, IAC, SE))
                return True

        ## Stores a character on a buffer to be processed
        def store3270(self, char ):
                """ Stores a character on the tn3270 buffer """
                if isinstance(char, int):
                        self.tn_buffer.append(char)
                else:
                        self.tn_buffer.extend(char)

        ## Also known as process_eor in x3270
        def process_data( self ):
                """Process one TN3270/TN3270E record.

                3270-DATA is painted. BIND_IMAGE is parsed (best-effort) and
                stored. UNBIND clears bind state. SSCP-LU and NVT are surfaced
                in dedicated buffers. SCS is logged and ignored. If RESPONSES
                was agreed, ALWAYS-RESPONSE records still get an ACK.
                """
                reply = 0
                self.msg(1,"Processing TN3270 Data")
                if self.state == TN3270E_DATA:
                        if len(self.tn_buffer) < 5:
                                self.msg(1, "TN3270E header too short (%r bytes)", len(self.tn_buffer))
                                self.tn_buffer = bytearray()
                                return True
                        self.msg(1, 'Parsing TN3270E Header')
                        self.tn3270_header['data_type']   = self.tn_buffer[0]
                        self.tn3270_header['request_flag']  = self.tn_buffer[1]
                        self.tn3270_header['response_flag'] = self.tn_buffer[2]
                        self.tn3270_header['seq_number']    = bytes(self.tn_buffer[3:5])
                        dtype = self.tn3270_header['data_type']
                        payload = bytes(self.tn_buffer[5:])
                        if dtype == DT_3270_DATA:
                                self.sscp_mode = False
                                reply = self.process_3270(payload) or 0
                                self.raw_tn.append(payload)
                        elif dtype == DT_BIND_IMAGE:
                                self._handle_bind_image(payload)
                        elif dtype == DT_UNBIND:
                                self._handle_unbind(payload)
                        elif dtype == DT_SSCP_LU_DATA:
                                self._handle_sscp(payload)
                        elif dtype == DT_NVT_DATA:
                                self._handle_nvt(payload)
                        elif dtype == DT_REQUEST:
                                self.msg(1, "TN3270E REQUEST (0x%02x)",
                                         payload[0] if payload else 0)
                        elif dtype == DT_SCS_DATA:
                                self.msg(1, "Ignoring SCS-DATA (printer sessions out of scope)")
                        else:
                                self.msg(1, "Ignoring TN3270E data type 0x%02x", dtype)
                        req = self.tn3270_header['request_flag']
                        if self._tn3270e_responses_on():
                                if reply in (BAD_COMMAND, BAD_ADDRESS) and req != NO_RESPONSE:
                                        self.tn3270e_nak(reply)
                                elif req == ALWAYS_RESPONSE and reply != OUTPUT:
                                        self.tn3270e_ack()
                else:
                        reply = self.process_3270(self.tn_buffer) or 0
                        self.raw_tn.append(bytes(self.tn_buffer))

                self._record_count = getattr(self, '_record_count', 0) + 1
                self.tn_buffer = bytearray()
                return  True

        def _append_nvt( self, data ):
                if isinstance(data, int):
                        chunk = bytes((data & 0xff,))
                else:
                        chunk = bytes(data)
                text = chunk.decode('latin1', 'replace')
                self._nvt_buf = getattr(self, '_nvt_buf', '') + text

        def _handle_bind_image( self, payload ):
                parsed = parse_bind_image(payload)
                self.bind_image = parsed['raw']
                self.bind = parsed
                if parsed.get('slu') and not getattr(self, 'connected_lu', ''):
                        self.connected_lu = parsed['slu']
                self.msg(1, "BIND_IMAGE PLU=%r SLU=%r size=%sx%s (%d bytes)",
                         parsed.get('plu'), parsed.get('slu'),
                         parsed.get('rows'), parsed.get('cols'), len(payload))

        def _handle_unbind( self, payload ):
                self.msg(1, "UNBIND type=%r", payload[:1])
                self.bind_image = b''
                self.bind = {
                        'raw': b'', 'plu': '', 'slu': '',
                        'rows': None, 'cols': None, 'logmode': '',
                }
                self.sscp_mode = False

        def _handle_sscp( self, payload ):
                self.sscp_mode = True
                text = self._ebcdic_to_str(payload)
                self._sscp_text = getattr(self, '_sscp_text', '') + text
                self.msg(1, "SSCP-LU %d bytes: %r", len(payload), text[:80])

        def _handle_nvt( self, payload ):
                text = bytes(payload).decode('ascii', 'replace')
                self._nvt_buf = getattr(self, '_nvt_buf', '') + text
                self.msg(1, "NVT %d bytes: %r", len(payload), text[:80])

        def get_sscp( self ):
                """Decoded SSCP-LU text accumulated this session."""
                return getattr(self, '_sscp_text', '')

        def get_nvt( self ):
                """NVT (ASCII) line buffer: pre-3270 telnet and DT_NVT."""
                return getattr(self, '_nvt_buf', '')

        def _iac_double( self, data ):
                iac = bytes((IAC,))
                out = bytearray()
                for char in data:
                        raw = _bytes(char)
                        out.extend(raw.replace(iac, iac + iac))
                return bytes(out)

        def _next_tn3270e_seq( self ):
                seq = getattr(self, 'header_sequence', 0) & 0xffff
                self.header_sequence = (seq + 1) & 0xffff
                return seq

        def _tn3270e_header_bytes( self, data_type, request_flag=0, response_flag=0, seq=None ):
                if seq is None:
                        seq = self._next_tn3270e_seq()
                hdr = bytes((
                        data_type & 0xff,
                        request_flag & 0xff,
                        response_flag & 0xff,
                        (seq >> 8) & 0xff,
                        seq & 0xff,
                ))
                return self._iac_double(hdr)

        def send_tn3270e_record( self, data_type, payload=b'', request_flag=0 ):
                """Send one TN3270E record (header + payload + IAC EOR)."""
                packet = bytearray()
                packet.extend(self._tn3270e_header_bytes(data_type, request_flag))
                packet.extend(self._iac_double(payload or b''))
                packet.extend((IAC, TN_EOR))
                self.send_data(bytes(packet))

        def _tn3270e_responses_on( self ):
                return TN3270E_FN_RESPONSES in getattr(self, 'tn3270e_functions', set())

        def _tn3270e_seq_for_reply( self ):
                seq = self.tn3270_header['seq_number'] or b'\x00\x00'
                if isinstance(seq, str):
                        seq = seq.encode('latin1')
                seq = bytes(seq[:2])
                if len(seq) < 2:
                        seq = seq + b'\x00' * (2 - len(seq))
                iac = bytes((IAC,))
                return seq.replace(iac, iac + iac)

        def tn3270e_nak( self, reply ):
                """Send a TN3270E negative response for the current sequence number."""
                if reply == BAD_COMMAND:
                        neg = bytes((NEG_COMMAND_REJECT,))
                elif reply == BAD_ADDRESS:
                        neg = bytes((NEG_OPERATION_CHECK,))
                else:
                        neg = b''
                self.send_data(
                        bytes((DT_RESPONSE, 0, NEGATIVE_RESPONSE))
                        + self._tn3270e_seq_for_reply()
                        + neg
                        + bytes((IAC, TN_EOR)))

        def tn3270e_ack( self ):
                """Send a TN3270E positive response for the current sequence number."""
                self.send_data(
                        bytes((DT_RESPONSE, 0, POSITIVE_RESPONSE))
                        + self._tn3270e_seq_for_reply()
                        + bytes((POS_DEVICE_END, IAC, TN_EOR)))

        def in3270(self):
                if self.client_options.get(options['TN3270'], False):
                        #if self.negotiated:
                        self.state = TN3270E_DATA
                elif (  self.server_options.get(options['EOR'], False)    and
                                self.server_options.get(options['BINARY'], False) and
                                self.client_options.get(options['BINARY'], False) and
                                self.client_options.get(options['TTYPE'], False)  ):
                        self.state = TN3270_DATA
                now = self.state == TN3270_DATA or self.state == TN3270E_DATA
                if now and not getattr(self, '_in_3270', False):
                        ## first entry to 3270 mode: empty presentation space
                        n = getattr(self, 'screen_size', SCREEN_SIZE)
                        self.msg(1,'Entering TN3270 Mode:')
                        self.msg(1,"\tCreating Empty IBM-3278-2 Buffer")
                        self._alloc_buffers(n)
                        self.msg(1,"\tCreated buffers of length: %r", n)
                self._in_3270 = now
                self.msg(1,"Current State: %r", WORD_STATE[self.state])

        def send_tn3270( self, data ):
                """Sends tn3270 data: TN3270E header, IAC-doubled payload, IAC EOR."""
                packet = bytearray()
                if self.state == TN3270E_DATA:
                        packet.extend(self._tn3270e_header_bytes(DT_3270_DATA))
                iac = bytes((IAC,))
                nbytes = 0
                for char in data:
                        raw = _bytes(char)
                        packet.extend(raw.replace(iac, iac + iac))
                        nbytes += len(raw)
                packet.extend((IAC, TN_EOR))
                self.msg(1, "send_tn3270 %d payload bytes", nbytes)
                self.send_data(bytes(packet))
