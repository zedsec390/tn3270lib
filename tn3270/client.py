"""The TN3270 client."""

import re
import socket
import select
import ssl
import logging
import time

from .constants import *
from .ebcdic import resolve_codec
from .transport import TransportMixin
from .telnet import TelnetMixin
from .datastream import DataStreamMixin
from .screen import ScreenMixin
from .indfile import IndFileMixin

# socket.timeout is TimeoutError on 3.10+; a TLS read timeout arrives as
# socket.timeout('The read operation timed out') and a non-blocking TLS socket
# can raise SSLWantReadError instead. All of them mean "nothing more to read".
_RECV_TIMEOUTS = (socket.timeout, TimeoutError,
                                  ssl.SSLWantReadError, ssl.SSLWantWriteError)

# Hard ceiling on receive iterations so a repeating timeout or a chatty host
# can never spin forever. Every pass through the loop consumes one iteration.
_MAX_RECV_LOOPS = 200


class TN3270Timeout(TimeoutError):
        """A wait_* call expired before the condition became true.

        Attributes
        ----------
        screen : str
            Presentation space at timeout.
        cursor : tuple or int
            Cursor location.
        keyboard_locked : bool
            Keyboard lock flag.
        aid : int
            Last AID.
        raw : list
            Raw TN3270 records.
        """

        def __init__(self, message, screen='', cursor=None,
                                 keyboard_locked=None, aid=None, raw=None):
                TimeoutError.__init__(self, message)
                self.screen = screen
                self.cursor = cursor
                self.keyboard_locked = keyboard_locked
                self.aid = aid
                self.raw = raw or []


class TN3270KeyboardLocked(Exception):
        """AID send attempted while the keyboard is locked."""


def parse_device_geometry(device_type, rows=None, cols=None):
        """Return ((def_rows, def_cols), (alt_rows, alt_cols))."""
        model = '2'
        if device_type:
                m = re.search(r'327[89]-([2-5])', str(device_type), re.I)
                if m:
                        model = m.group(1)
        default, alt = DEVICE_MODEL_GEOMETRY.get(model, DEVICE_MODEL_GEOMETRY['2'])
        if rows and cols:
                size = (int(rows), int(cols))
                if model == '2':
                        default = alt = size
                else:
                        alt = size
        return default, alt


class TN3270(TransportMixin, TelnetMixin, DataStreamMixin, ScreenMixin, IndFileMixin):
        """TN3270/TN3270E test-automation client (IBM-3278 models 2–5).

        Not an x3270 clone. ``import tn3270lib; tn3270lib.TN3270()`` is the
        supported facade.

        >>> import tn3270lib
        >>> tn = tn3270lib.TN3270()
        >>> tn.initiate('10.10.0.10', 23)
        True
        >>> print(tn.get_screen())
        """

        def __init__(self, host=None, port=0,
                                 timeout=10, verify=False, ssl_context=None,
                                 require_tls=False, allow_plaintext=False,
                                 device_type=None, rows=None, cols=None,
                                 codepage='cp037', certfile=None, keyfile=None):
                """Create a TN3270 client.

                Parameters
                ----------
                host : str, optional
                    If given, ``initiate`` is called immediately.
                port : int
                    Telnet/TN3270 port (``0`` means 23).
                timeout : float
                    Socket timeout in seconds.
                verify : bool
                    Require a valid server certificate. Default ``False`` is the
                    z/OS AT-TLS path (legacy ciphers, ``CERT_NONE``).
                ssl_context : ssl.SSLContext, optional
                    Replaces the built-in context.
                require_tls : bool
                    Fail the connect if TLS handshake fails (no plaintext).
                allow_plaintext : bool
                    Fall back to cleartext after TLS failure.
                device_type : str, optional
                    TN3270E device type (default ``IBM-3278-2-E``). Models 3/4/5
                    set the alternate size used by EWA.
                rows, cols : int, optional
                    Override geometry (model 2: default and alt; 3–5: alt only).
                codepage : str
                    SBCS codec name (``cp037``, ``037``, ``cp273``, ...).
                certfile, keyfile : str, optional
                    Client certificate for mTLS.
                """

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
                self._in_3270       = False
                self._record_count  = 0
                self.tn3270e_functions = set()
                self.device_type    = device_type or DEVICE_TYPE
                self.verify         = verify
                self.ssl_context    = ssl_context
                self.require_tls    = require_tls
                self.allow_plaintext = allow_plaintext
                self.certfile       = certfile
                self.keyfile        = keyfile
                self.on_timeout     = None
                self.codepage       = resolve_codec(codepage)

                default, alt = parse_device_geometry(self.device_type, rows, cols)
                self.default_rows, self.default_cols = default
                self.alt_rows, self.alt_cols = alt
                self.rows = self.default_rows
                self.cols = self.default_cols
                self.screen_size = self.rows * self.cols

                #TN3270 Buffer Address Location
                self.buffer_addr = 0
                #TN3270 Cursor Tracking Location
                self.cursor_addr = 0
                self.screen          = []
                self.printableScreen = []
                self.header          = []

                #TN3270 Buffers (instance geometry; default 24x80)
                self._alloc_buffers(self.screen_size)
                self.output_buffer  = []
                self._try_ssl       = True
                self.ssl            = False
                self.header_sequence = 0
                self.reply_mode     = SF_SRM_FIELD
                self.bind_image     = b''
                self.bind           = {
                        'raw': b'', 'plu': '', 'slu': '',
                        'rows': None, 'cols': None, 'logmode': '',
                }
                self.sscp_mode      = False
                self._sscp_text     = ''
                self._sscp_out      = ''
                self._nvt_buf       = ''
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
                        if not self.initiate(host, port, timeout):
                                self.disconnect()
                                raise ConnectionError(
                                        'TN3270 initiate failed for %s:%s' % (host, port))

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

        def __enter__(self):
                return self

        def __exit__(self, exc_type, exc, tb):
                self.disconnect()
                return False

        def set_LU(self, LU):
                """ Sets an LU to use on connection """
                self.connected_lu = LU

        def set_lu(self, LU):
                """Alias of set_LU."""
                return self.set_LU(LU)

        def get_lu(self):
                """ Returns the LU name negotiated with the host, if any. """
                return self.connected_lu

        def get_LU(self):
                """Alias of get_lu."""
                return self.get_lu()

        def disable_enhanced(self, disable=True):
                """Disable (or re-enable) TN3270E; fall back to basic TN3270."""
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
                self.negotiated = False
                self._in_3270 = False
                self.tn3270e_functions = set()
                self.sscp_mode = False
                self.header_sequence = 0

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

        def _reset_session( self ):
                """Clear 3270E functions, bind, SSCP/NVT, and presentation space."""
                self.telnet_state = 0
                self.server_options = {}
                self.client_options = {}
                self.sb_options = bytearray()
                self.first_screen = False
                self.aid = NO_AID
                self.telnet_data = b''
                self.tn_buffer = bytearray()
                self.raw_tn = []
                self.state = 0
                self.buffer_address = 0
                self.formatted = False
                self.keyboard_locked = False
                self.negotiated = False
                self._paint_pending = False
                self._in_3270 = False
                self._record_count = 0
                self.tn3270e_functions = set()
                self.cursor_addr = 0
                self.header_sequence = 0
                self.reply_mode = SF_SRM_FIELD
                self.bind_image = b''
                self.bind = {
                        'raw': b'', 'plu': '', 'slu': '',
                        'rows': None, 'cols': None, 'logmode': '',
                }
                self.sscp_mode = False
                self._sscp_text = ''
                self._sscp_out = ''
                self._nvt_buf = ''
                self.rows = self.default_rows
                self.cols = self.default_cols
                self.screen_size = self.rows * self.cols
                self._alloc_buffers(self.screen_size)

        def reconnect( self, timeout=None ):
                """Disconnect, reset 3270E/bind/buffers, and initiate again.

                Host idle-kill is a 0-byte recv; call this to start a new session
                on the stored host/port.
                """
                host = self.host
                port = self.port or 0
                to = timeout if timeout is not None else (self.timeout or 10)
                self.disconnect()
                self._reset_session()
                if not host:
                        return False
                return self.initiate(host, port, to)

        def get_data( self ):
                """ Gets the tn3270 buffer currently on the stack """
                self.first_screen = False
                for _ in range(_MAX_RECV_LOOPS):
                        if self.first_screen:
                                break
                        try:
                                self.telnet_data = self.recv_data()
                        except _RECV_TIMEOUTS as e:
                                self.msg(1,"recv timed out! We're done here (%r)", e)
                                break
                        except OSError as e:
                                self.msg(1,"Get Data Socket Error Received: %r", e)
                                break
                        if not self.telnet_data:
                                self.msg(1,'Received 0 bytes, the host closed the socket')
                                break
                        self.process_packets()
                else:
                        self.msg(1,"Gave up receiving after %i reads", _MAX_RECV_LOOPS)

        def get_all_data( self, timeout=2 ):
                """ Mainframes will often send a 'confirmed' screen before it sends
                    the screen we care about, this function clumsily gets all screens
                    sent so far.

                    timeout is in seconds (Python); Lua's nmap socket uses ms.
                """
                self.first_screen = False
                prev_timeout = None
                if self.sock is not None:
                        prev_timeout = self.sock.gettimeout()
                        self.sock.settimeout(timeout)
                try:
                        for _ in range(_MAX_RECV_LOOPS):
                                try:
                                        self.telnet_data = self.recv_data()
                                except _RECV_TIMEOUTS as e:
                                        self.msg(1,"recv timed out! We're done here (%r)", e)
                                        break
                                except OSError as e:
                                        self.msg(1,"Error Received: %r", e)
                                        break

                                # Needed when mainframe closes socket on us
                                if not self.telnet_data:
                                        self.msg(1,'Received 0 bytes, the host closed the socket')
                                        break
                                self.msg(1,"Recv'd %i bytes", len(self.telnet_data))
                                self.process_packets()
                        else:
                                self.msg(1,"Gave up receiving after %i reads", _MAX_RECV_LOOPS)
                finally:
                        if self.sock is not None:
                                self.sock.settimeout(prev_timeout)

        def _type_ascii_at( self, location, data ):
                """Write ASCII into the presentation space at a 0-based address."""
                if getattr(self, 'sscp_mode', False):
                        if isinstance(data, (bytes, bytearray)):
                                self._sscp_out = getattr(self, '_sscp_out', '') + self._ebcdic_to_str(data)
                        else:
                                self._sscp_out = getattr(self, '_sscp_out', '') + str(data)
                        return self._str_to_ebcdic(data)
                if not isinstance(data, (bytes, bytearray)):
                        self._check_numeric_text(location, data)
                ebcdic = self._str_to_ebcdic(data)
                saved = self.buffer_address
                n = self.screen_size or SCREEN_SIZE
                addr = location % n if n else 0
                self.buffer_address = addr
                for b in ebcdic:
                        self.write_char(b)
                        self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
                self.cursor_addr = self.buffer_address
                self._set_mdt_at(location)
                self.buffer_address = saved
                return ebcdic

        def _check_numeric_text( self, location, text ):
                fa = self._fa_containing(location)
                if fa is None:
                        return
                if not (self.fa_buffer[fa] & FA_NUMERIC):
                        return
                if any(not c.isdigit() for c in str(text)):
                        raise ValueError('numeric field rejects non-digits: %r' % (text,))

        def _require_unlocked( self ):
                if self.keyboard_locked:
                        raise TN3270KeyboardLocked(
                                'keyboard locked; wait_unlock() or host WCC restore')

        def _sysreq_negotiated( self ):
                return (
                        self.state == TN3270E_DATA
                        and TN3270E_FN_SYSREQ in getattr(self, 'tn3270e_functions', set())
                )

        def sysreq( self ):
                """TN3270E SYSREQ: toggle 3270-DATA <-> SSCP-LU (RFC 2355).

                When SYSREQ was not negotiated, sends the 3270 SYSREQ AID instead.
                In SSCP-LU mode, type() accumulates a line and send_enter() sends
                it as DT_SSCP_LU_DATA (not Read Modified).
                """
                if not self._sysreq_negotiated():
                        return self._send_aid_now(SYSREQ)
                self._require_unlocked()
                self.send_tn3270e_record(DT_REQUEST, b'')
                self.sscp_mode = not self.sscp_mode
                self.keyboard_locked = False
                self.msg(1, "SYSREQ -> %s", 'SSCP-LU' if self.sscp_mode else '3270-DATA')
                return True

        def _send_sscp_line( self ):
                """Outbound SSCP-LU record from the typed line."""
                self._require_unlocked()
                text = getattr(self, '_sscp_out', '')
                payload = self._str_to_ebcdic(text)
                self.send_tn3270e_record(DT_SSCP_LU_DATA, payload)
                self._sscp_out = ''
                return True

        def _send_aid_now( self, aid ):
                """Read Modified (or short read) then lock the keyboard."""
                if getattr(self, 'sscp_mode', False) and aid == ENTER:
                        return self._send_sscp_line()
                self._require_unlocked()
                self.aid = aid
                rv = self.process_read_modified(aid)
                self.keyboard_locked = True
                return rv

        def send_cursor( self, data ):
                """Type ASCII at the current cursor, then Read Modified (ENTER)."""
                self._require_unlocked()
                self.msg(1,"send_cursor: %d characters at %r", len(data), self.cursor_addr)
                self._type_ascii_at(self.cursor_addr, data)
                return self._send_aid_now(ENTER)

        def send_location( self, location, data ):
                """Type ASCII at a 0-based buffer address and press ENTER."""
                self._require_unlocked()
                self.msg(1, "send_location: %d characters at %d", len(data), location)
                self._type_ascii_at(location, data)
                return self._send_aid_now(ENTER)

        def send_locations( self, location_tuple ):
                """Fill several fields, then ENTER.

                location_tuple is a sequence of (location, data) pairs, 0-based.
                Example: send_locations([(579, "dade"), (630, "secret")])
                """
                self._require_unlocked()
                for location, data in location_tuple:
                        self.msg(1, "send_locations: %d characters at %d", len(data), location)
                        self._type_ascii_at(location, data)
                return self._send_aid_now(ENTER)

        def send_clear( self ):
                """Send the CLEAR AID (short read: AID only)."""
                return self._send_aid_now(CLEAR)

        def send_pf( self, pf ):
                """ Sends an F1 through F24 as Read Modified. """
                if ( pf > 24 ) or ( pf < 1) :
                        self.msg(1,"PF Value must be between 1 and 24. Recieved %s", pf)
                        return False
        
                self.msg(1,"Generating Read Modified for send_pf: %s", "PF"+str(pf))
                return self._send_aid_now(AIDS["PF" + str(pf)])

        def send_aid( self, aid ):
                """Send a named AID. ENTER/PF are Read Modified; CLEAR/PA are AID-only."""
                aid = aid.upper()
                aids = ['NO','QREPLY','ENTER','PF1','PF2','PF3','PF4','PF5','PF6',
                                'PF7','PF8','PF9','PF10','PF11','PF12','PF13','PF14','PF15','PF16',
                                'PF17','PF18','PF19','PF20','PF21','PF22','PF23','PF24','OICR',
                                'MSR_MHS','SELECT','PA1','PA2','PA3','CLEAR','SYSREQ']
                if aid not in aids :
                        self.msg(1,"%s not a valid AID", aid)
                        return False
        
                self.msg(1,"Generating Read Modified for send_aid: %s", aid)
                if aid == 'SYSREQ' and self._sysreq_negotiated():
                        return self.sysreq()
                return self._send_aid_now(AIDS[aid])

        def send_enter( self ):
                """Send the ENTER AID (Read Modified). Raises TN3270KeyboardLocked if locked."""
                self.msg(1,"Generating Read Modified for send_enter")
                return self._send_aid_now(ENTER)

        def _screen_snippet( self ):
                flat = self._screen_ascii_flat()
                return flat[:80].replace('\n', ' ').rstrip()

        def _timeout_exc( self, what ):
                screen = self.get_screen(show_hidden=False)
                lines = screen.splitlines()
                if len(lines) > 28:
                        shown = '\n'.join(lines[:12] + ['...'] + lines[-8:])
                else:
                        shown = screen
                row, col = self.addr_to_rowcol(self.cursor_addr)
                aid = self.aid if isinstance(self.aid, int) else 0
                raw_parts = []
                for rec in getattr(self, 'raw_tn', [])[-3:]:
                        h = bytes(rec).hex()
                        if len(h) > 128:
                                h = h[:128] + '...'
                        raw_parts.append(h)
                msg = (
                        'timeout waiting for %s; cursor row=%s col=%s addr=%s '
                        'keyboard_locked=%s aid=0x%02x; screen: %r\n%s\nraw=%s'
                        % (what, row, col, self.cursor_addr, self.keyboard_locked,
                           aid & 0xff, self._screen_snippet(), shown, raw_parts)
                )
                sscp = getattr(self, '_sscp_text', '')
                nvt = getattr(self, '_nvt_buf', '')
                if sscp:
                        msg += '\nsscp=%r' % sscp[:160]
                if nvt:
                        msg += '\nnvt=%r' % nvt[:160]
                exc = TN3270Timeout(
                        msg, screen=screen,
                        cursor=(row, col, self.cursor_addr),
                        keyboard_locked=self.keyboard_locked,
                        aid=self.aid, raw=raw_parts)
                exc.sscp = sscp
                exc.nvt = nvt
                hook = getattr(self, 'on_timeout', None)
                if callable(hook):
                        hook(exc)
                return exc

        def _recv_until( self, timeout ):
                """Process incoming telnet for up to timeout seconds. True if any data."""
                if self.sock is None or timeout <= 0:
                        return False
                deadline = time.monotonic() + timeout
                got = False
                prev = None
                try:
                        prev = self.sock.gettimeout()
                except Exception:
                        prev = None
                try:
                        while time.monotonic() < deadline:
                                remaining = deadline - time.monotonic()
                                try:
                                        self.sock.settimeout(max(0.001, remaining))
                                except Exception:
                                        pass
                                try:
                                        self.telnet_data = self.recv_data()
                                except _RECV_TIMEOUTS:
                                        break
                                except OSError:
                                        break
                                if not self.telnet_data:
                                        break
                                got = True
                                self.process_packets()
                finally:
                        if self.sock is not None:
                                try:
                                        self.sock.settimeout(prev)
                                except Exception:
                                        pass
                return got

        def _wait_for( self, check, timeout, what ):
                if timeout is None:
                        timeout = self.timeout if self.timeout else 10
                if check():
                        return True
                deadline = time.monotonic() + timeout
                if timeout <= 0 or self.sock is None:
                        raise self._timeout_exc(what)
                while time.monotonic() < deadline:
                        self._recv_until(min(0.25, deadline - time.monotonic()))
                        if check():
                                return True
                raise self._timeout_exc(what)

        def wait_for_text( self, text, timeout=10 ):
                """Block until the decoded screen contains ``text`` (session code page)."""
                return self._wait_for(
                        lambda: text in self._screen_ascii_flat(),
                        timeout, 'text %r' % (text,))

        def wait_unlock( self, timeout=10 ):
                """Block until the keyboard is not locked."""
                return self._wait_for(
                        lambda: not self.keyboard_locked,
                        timeout, 'keyboard unlock')

        def wait_cursor( self, row=None, col=None, addr=None, timeout=10 ):
                """Block until the cursor is at addr (0-based) or 1-based row/col."""
                def check():
                        if addr is not None:
                                return self.cursor_addr == addr
                        r, c = self.addr_to_rowcol(self.cursor_addr)
                        if row is not None and r != row:
                                return False
                        if col is not None and c != col:
                                return False
                        return row is not None or col is not None
                return self._wait_for(check, timeout, 'cursor row=%s col=%s addr=%s' % (row, col, addr))

        def wait_stable( self, quiet=0.3, timeout=10 ):
                """Block until no new 3270 records arrive for ``quiet`` seconds."""
                if timeout is None:
                        timeout = self.timeout if self.timeout else 10
                if timeout <= 0 or self.sock is None:
                        return True
                deadline = time.monotonic() + timeout
                last = time.monotonic()
                gen = self._record_count
                while True:
                        now = time.monotonic()
                        if now - last >= quiet:
                                return True
                        if now >= deadline:
                                raise self._timeout_exc('stable screen (quiet=%s)' % quiet)
                        slice_t = min(quiet - (now - last), deadline - now)
                        self._recv_until(max(0.001, slice_t))
                        if self._record_count != gen:
                                gen = self._record_count
                                last = time.monotonic()
