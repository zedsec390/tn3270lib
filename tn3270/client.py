"""The TN3270 client."""

import socket
import select
import logging

from .constants import *
from .ebcdic import _str_to_ebcdic
from .transport import TransportMixin
from .telnet import TelnetMixin
from .datastream import DataStreamMixin
from .screen import ScreenMixin
from .indfile import IndFileMixin


class TN3270(TransportMixin, TelnetMixin, DataStreamMixin, ScreenMixin, IndFileMixin):
        """A TN3270/TN3270E terminal emulator (IBM-3278-2, 24x80).

        >>> import tn3270lib
        >>> tn = tn3270lib.TN3270()
        >>> tn.initiate('10.10.0.10', 23)
        True
        >>> print(tn.get_screen())
        """

        def __init__(self, host=None, port=0,
                                 timeout=10):

                self.debuglevel = DEBUGLEVEL
                self.host       = host
                self.port       = port
                self.timeout    = timeout
                self.eof        = 0
                self.sock       = None
                self._has_poll  = hasattr(select, 'poll')
                self.unsupported_opts = {}
                self.telnet_state   = 0 # same as TNS_DATA to begin with
                self.server_options = {}
                self.client_options = {} 
                self.sb_options     = bytearray()
                self.connected_lu   = ''
                self.connected_dtype= ''
                #self.negotiated     = False
                self.first_screen   = False
                self.aid            = NO_AID  #initial Attention Identifier is No AID
                self.telnet_data    = b''
                self.tn_buffer      = bytearray()
                self.raw_tn         = [] #Stores raw TN3270 'frames' for use
                self.state          = 0
                self.buffer_address = 0
                self.formatted      = False
                self.keyboard_locked = False
                self.negotiated     = False
                self._paint_pending = False

                #TN3270 Buffer Address Location
                self.buffer_addr = 0
                #TN3270 Cursor Tracking Location
                self.cursor_addr = 0
                self.screen          = []
                self.printableScreen = []
                self.header          = []

                #TN3270 Buffers (1920-byte, 0-based presentation space)
                self.buffer         = bytearray(SCREEN_SIZE)
                self.fa_buffer      = bytearray(SCREEN_SIZE)
                self.output_buffer  = []
                self.overwrite_buf  = bytearray(SCREEN_SIZE)
                self._try_ssl       = True
                self.ssl            = False
                self.header_sequence = 0
                #TN3270E Header variables
                self.tn3270_header = {
                        'data_type'     : '',
                        'request_flag'  : '',
                        'response_flag' : '',
                        'seq_number'    : ''
                }

                # File Transfer
                self.ft_buffersize = 0
                self.ft_state = FT_NONE

                if host is not None:
                        self.initiate(host, port, timeout)

        def __del__(self):
                """Destructor ## close the connection."""
                self.disconnect()

        def msg(self, level, msg, *args):
                """Log a debug message, when the debug level is > 0.

                If extra arguments are present, they are substituted in the
                message using the standard string formatting operator.

                """
                if self.debuglevel >= level:
                        text = msg % args if args else msg
                        LOGGER.debug('TN3270(%s,%s): %s', self.host, self.port, text)

        def set_debuglevel(self, debuglevel=1):
                """Set the debug level.

                The higher it is, the more debug output you get (logger 'tn3270').
                So far only levels 1 (verbose) and 2 (debug) exist.

                """
                self.debuglevel = debuglevel
                if debuglevel > 0:
                        LOGGER.setLevel(logging.DEBUG)
                        if not LOGGER.handlers and not logging.getLogger().handlers:
                                handler = logging.StreamHandler()
                                handler.setFormatter(logging.Formatter('%(message)s'))
                                LOGGER.addHandler(handler)
                                LOGGER.propagate = False

        def set_LU(self, LU):
                """ Sets an LU to use on connection """
                self.connected_lu = LU

        def get_lu(self):
                """ Returns the LU name negotiated with the host, if any. """
                return self.connected_lu

        def disable_enhanced(self, disable=True):
                self.msg(1,'Disabling TN3270E Option')
                if disable:
                        self.unsupported_opts[options['TN3270E']] = 'TN3270E'
                else:
                        self.unsupported_opts.pop(options['TN3270E'], None)

        def initiate( self, host, port=0, timeout=5 ):
                """ Initiates a TN3270 connection until it gets the first 'screen' """
                #if not self.check_tn3270(host, port):
                #       return False
                if not self.connect(host,port, timeout):
                        return False

                self.client_options = {}
                self.server_options = {}
                self.state = NEGOTIATING
                self.first_screen = False

                while not self.first_screen:
                        try:
                                self.telnet_data = self.recv_data()
                                self.msg(2,"Got telnet_data: %r", self.telnet_data)
                                if not self.telnet_data:
                                        return False
                                r = self.process_packets()
                                if not r:
                                        return False
                        except (socket.timeout, OSError) as e:
                                self.msg(1, "initiate timed out waiting for EOR: %r", e)
                                return bool(self.first_screen)
                return True

        def get_data( self ):
                """ Gets the tn3270 buffer currently on the stack """
                status = True
                self.first_screen = False
                while not self.first_screen and status:
                        try:
                                self.telnet_data = self.recv_data()
                                self.process_packets()
                        except socket.timeout as e:
                                err = e.args[0]
                                if err == 'timed out':
                                        #sleep(1)
                                        self.msg(1,"recv timed out! We're done here")
                                        break
                        except socket.error as e:
                                err = e.args[0]
                                if 'timed out' in err: # This means the SSL socket timed out, not a regular socket so we catch it here
                                        self.msg(1,"recv timed out! We're done here")
                                        break
                        # Something else happened, handle error, exit, etc.
                                self.msg(1,"Get Data Socket Error Received: %r", e)

        def get_all_data( self, timeout=2 ):
                """ Mainframes will often send a 'confirmed' screen before it sends
                    the screen we care about, this function clumsily gets all screens
                    sent so far.

                    timeout is in seconds (Python); Lua's nmap socket uses ms.
                """
                self.first_screen = False
                self.sock.settimeout(timeout)
                count = 0
                while True and count <=200:
                        try:
                                self.telnet_data = self.recv_data()
                                
                                # Needed when mainframe closes socket on us
                                if len(self.telnet_data) > 0:
                                    self.msg(1,"Recv'd %i bytes", len(self.telnet_data))
                                else:
                                    count += 1
                                    if count % 100: self.msg(1,'Receiving 0 bytes')
                                    
                                self.process_packets()
                        except socket.timeout as e:
                                err = e.args[0]
                                if err == 'timed out':
                                        #sleep(1)
                                        self.msg(1,"recv timed out! We're done here")
                                        break
                        except socket.error as e:
                        # Something else happened, handle error, exit, etc.
                                self.msg(1,"Error Received: %r", e)
                                break
                self.sock.settimeout(None)

        def send_cursor( self, data ):
                """Type ASCII at the current cursor. Cursor in the AID is at addr+len(data)."""
                self.output_buffer = []
                self.msg(1,"Generating Output Buffer for send_cursor")
                self.output_buffer.append(ENTER)
                cursor_after = self.cursor_addr + len(data)
                self.msg(1,"Cursor Location ("+ str(cursor_after) +"): Row: %r, Column: %r ",
                                        self.BA_TO_ROW(cursor_after),
                                        self.BA_TO_COL(cursor_after) )
                self.output_buffer.append(self.ENCODE_BADDR(cursor_after))
                self.output_buffer.append(SBA)
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
                ebcdic = _str_to_ebcdic(data)
                self.msg(1, 'Adding %r to the output buffer', ebcdic)
                self.output_buffer.append(ebcdic)
                self.aid = ENTER
                self._set_mdt_at(self.cursor_addr)
                return self.send_tn3270(self.output_buffer)

        def send_location( self, location, data ):
                """Type ASCII at a 0-based buffer address and press ENTER."""
                cursor_after = location + len(data)
                self.output_buffer = []
                self.output_buffer.append(ENTER)
                self.output_buffer.append(self.ENCODE_BADDR(cursor_after))
                self.msg(1,"Cursor Location ("+ str(cursor_after) +"): Row: %r, Column: %r ",
                                        self.BA_TO_ROW(cursor_after),
                                        self.BA_TO_COL(cursor_after) )
                self.msg(1, "Inserting %s at location %d", data, location)
                self.output_buffer.append(SBA)
                self.output_buffer.append(self.ENCODE_BADDR(location))
                self.output_buffer.append(_str_to_ebcdic(data))
                self.aid = ENTER
                self._set_mdt_at(location)
                return self.send_tn3270(self.output_buffer)

        def send_locations( self, location_tuple ):
                """Fill several fields, then ENTER.

                location_tuple is a sequence of (location, data) pairs, 0-based.
                Example: send_locations([(579, "dade"), (630, "secret")])
                """
                last_loc, last_data = location_tuple[-1]
                cursor_after = last_loc + len(last_data)
                self.output_buffer = []
                self.output_buffer.append(ENTER)
                self.output_buffer.append(self.ENCODE_BADDR(cursor_after))
                self.msg(1,"Cursor Location ("+ str(cursor_after) +"): Row: %r, Column: %r ",
                                        self.BA_TO_ROW(cursor_after),
                                        self.BA_TO_COL(cursor_after) )
                for location, data in location_tuple:
                        self.msg(1, "Inserting %s at location %d", data, location)
                        self.output_buffer.append(SBA)
                        self.output_buffer.append(self.ENCODE_BADDR(location))
                        self.output_buffer.append(_str_to_ebcdic(data))
                        self._set_mdt_at(location)
                self.aid = ENTER
                return self.send_tn3270(self.output_buffer)

        def send_clear( self ):
                """Send the CLEAR AID (with TN3270E header when in TN3270E)."""
                self.aid = CLEAR
                return self.send_tn3270([CLEAR])

        def send_pf( self, pf ):
                """ Sends an F1 through F24 """
                if ( pf > 24 ) or ( pf < 0) :
                        self.msg(1,"PF Value must be between 1 and 24. Recieved %s", pf)
                        return False
        
                self.output_buffer = []
                self.msg(1,"Generating Output Buffer for send_pf: %s", "PF"+str(pf))
                self.aid = AIDS["PF" + str(pf)]
                self.output_buffer.append(self.aid)
                self.msg(1,"Cursor Location ("+ str(self.cursor_addr) +"): Row: %r, Column: %r ",
                                        self.BA_TO_ROW(self.cursor_addr),
                                        self.BA_TO_COL(self.cursor_addr) )
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))

                return self.send_tn3270(self.output_buffer)

        def send_aid( self, aid ):
                """ Sends an F1 through F24 """
                aid = aid.upper()
                aids = ['NO','QREPLY','ENTER','PF1','PF2','PF3','PF4','PF5','PF6',
                                'PF7','PF8','PF9','PF10','PF11','PF12','PF13','PF14','PF15','PF16',
                                'PF17','PF18','PF19','PF20','PF21','PF22','PF23','PF24','OICR',
                                'MSR_MHS','SELECT','PA1','PA2','PA3','CLEAR','SYSREQ']
                if aid not in aids :
                        self.msg(1,"%s not a valid AID", aid)
                        return False
        
                self.output_buffer = []
                self.msg(1,"Generating Output Buffer for send_aid: %s", aid)
                self.aid = AIDS[aid]
                self.output_buffer.append(self.aid)
                self.msg(1,"Cursor Location ("+ str(self.cursor_addr) +"): Row: %r, Column: %r ",
                                        self.BA_TO_ROW(self.cursor_addr),
                                        self.BA_TO_COL(self.cursor_addr) )
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))

                return self.send_tn3270(self.output_buffer)

        def send_enter( self ):
                        self.output_buffer = []
                        self.msg(1,"Generating Output Buffer for send_enter")
                        self.aid = ENTER
                        self.output_buffer.append(ENTER)
                        self.msg(1,"Cursor Location ("+ str(self.cursor_addr) +"): Row: %r, Column: %r ",
                                        self.BA_TO_ROW(self.cursor_addr),
                                        self.BA_TO_COL(self.cursor_addr) )
                        self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
                        return self.send_tn3270(self.output_buffer)
