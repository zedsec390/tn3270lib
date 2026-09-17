"""Socket transport for the TN3270 client."""

import socket
import ssl

from .constants import *


def _bytes(*parts):
    """Join ints, bytes, and ASCII str into a bytes object for the wire."""
    out = bytearray()
    for part in parts:
        if part is None:
            continue
        if isinstance(part, int):
            out.append(part)
        elif isinstance(part, (bytes, bytearray, memoryview)):
            out.extend(part)
        elif isinstance(part, str):
            out.extend(part.encode('ascii'))
        else:
            raise TypeError('unsupported telnet part: %r' % (type(part),))
    return bytes(out)


def _make_ssl_context(verify=False, certfile=None, keyfile=None):
    """A TLS context permissive enough for legacy hosts.

    z/OS AT-TLS ports routinely offer only old suites such as AES256-SHA, which
    OpenSSL 3 refuses at its default security level. The default does no
    certificate checking (verify=False). Pass verify=True for CERT_REQUIRED
    (this is not the AT-TLS path; host certs usually fail hostname/CA checks).
    certfile/keyfile load a client certificate for mTLS.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_default_certs()
        except OSError:
            pass
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    except ssl.SSLError:
        pass
    if certfile:
        ctx.load_cert_chain(certfile, keyfile)
    return ctx


class TransportMixin:
        """Connect, send, receive, and probe for TN3270 support."""

        def connect(self, host, port=0, timeout=30):
                """Connects to a TN3270 Server. aka a Mainframe!"""
                self.ssl = False
                if not port:
                        port = TELNET_PORT
                self.host = host
                self.port = port
                self.timeout = timeout
                sock, used_ssl = self._open_socket(host, port, timeout)
                if sock is None:
                        return False
                self.sock = sock
                self.ssl = used_ssl
                return True

        def _open_socket(self, host, port, timeout):
                """Open TLS and/or plaintext. Returns (sock, used_ssl) or (None, False).

                Default: try TLS with the legacy-permissive context. Plaintext is
                used only when TLS is disabled (disable_ssl) or the caller set
                allow_plaintext=True. require_tls=True never falls back.
                """
                raw = None
                try_ssl = getattr(self, '_try_ssl', True)
                require_tls = getattr(self, 'require_tls', False)
                allow_plaintext = getattr(self, 'allow_plaintext', False)
                if require_tls:
                        try_ssl = True
                        allow_plaintext = False

                if try_ssl:
                        try:
                                self.msg(1, 'Trying SSL/TLS')
                                raw = socket.create_connection((host, port), timeout)
                                raw.settimeout(timeout)
                                ctx = getattr(self, 'ssl_context', None)
                                if ctx is None:
                                        ctx = _make_ssl_context(
                                                verify=getattr(self, 'verify', False),
                                                certfile=getattr(self, 'certfile', None),
                                                keyfile=getattr(self, 'keyfile', None))
                                ssl_sock = ctx.wrap_socket(raw, server_hostname=host)
                                return ssl_sock, True
                        except (ssl.SSLError, OSError) as e:
                                self.msg(1, 'SSL/TLS Failed: %r', e)
                                if raw is not None:
                                        try:
                                                raw.close()
                                        except OSError:
                                                pass
                                        raw = None
                                if require_tls or not allow_plaintext:
                                        return None, False
                        except Exception as e:
                                self.msg(1, '[SSL] Error: %r', e)
                                if raw is not None:
                                        try:
                                                raw.close()
                                        except OSError:
                                                pass
                                return None, False
                try:
                        sock = socket.create_connection((host, port), timeout)
                        sock.settimeout(timeout)
                        return sock, False
                except OSError as e:
                        self.msg(1, 'Error: %r', e)
                        return None, False

        def disable_ssl(self, disable=True):
                """Skip the TLS attempt on the next connect (Lua disableSSL)."""
                self._try_ssl = not disable
                self.msg(1, 'Disabling SSL connections' if disable else 'Enabling SSL connections')

        def disconnect(self):
                """Close the connection."""
                sock = self.sock
                self.sock = None
                if sock:
                        try:
                                sock.close()
                        except OSError:
                                pass

        def get_socket(self):
                """Return the socket object used internally."""
                return self.sock

        def send_data(self, data):
                """Sends raw data to the TN3270 server """
                if self.sock is None:
                        self.msg(1, "send_data: not connected")
                        return
                if isinstance(data, str):
                        data = data.encode('latin1')
                elif isinstance(data, int):
                        data = bytes((data,))
                elif isinstance(data, bytearray):
                        data = bytes(data)
                self.msg(2, "send %d bytes", len(data))
                self.sock.sendall(data)

        def recv_data(self):
                """ Receives 256 bytes of data; blocking"""
                if self.sock is None:
                        self.msg(1, "recv_data: not connected")
                        return b''
                self.msg(2,"Getting Data")
                buf = self.sock.recv(256)
                self.msg(2,"Got %d bytes", len(buf))
                return buf

        def check_tn3270( self, host, port=0, timeout=3 ):
                """ Checks if a host & port supports TN3270 """
                if not port:
                        port = TELNET_PORT
                sock, _used_ssl = self._open_socket(host, port, timeout)
                if sock is None:
                        return False
                try:
                        data = sock.recv(256)
                        if self._iac_option_present(data, DO, options['TN3270E']) or \
                           self._iac_option_present(data, WILL, options['TN3270E']):
                                return True
                        if self._iac_option_present(data, DO, options['TTYPE']):
                                sock.sendall(_bytes(IAC, WILL, options['TTYPE']))
                                data = sock.recv(256)
                                ttype_sb = _bytes(IAC, SB, options['TTYPE'], SEND, IAC, SE)
                                if ttype_sb not in data and data != ttype_sb:
                                        return False
                                dtype = getattr(self, 'device_type', DEVICE_TYPE)
                                sock.sendall(_bytes(IAC, SB, options['TTYPE'], IS, dtype, IAC, SE))
                                data = sock.recv(256)
                                if self._iac_option_present(data, DO, options['TN3270E']) or \
                                   self._iac_option_present(data, DO, options['BINARY']) or \
                                   self._iac_option_present(data, DO, options['EOR']):
                                        return True
                                if len(data) >= 2 and data[0:2] == _bytes(IAC, DO):
                                        return True
                        return False
                except OSError as e:
                        self.msg(1, 'check_tn3270 error: %r', e)
                        return False
                finally:
                        try:
                                sock.close()
                        except OSError:
                                pass

        def _iac_option_present(self, data, cmd, opt):
                """True if IAC cmd opt appears in a (possibly concatenated) banner."""
                if not data:
                        return False
                i = 0
                n = len(data)
                while i < n:
                        if data[i] != IAC:
                                i += 1
                                continue
                        if i + 1 >= n:
                                break
                        nxt = data[i + 1]
                        if nxt == IAC:
                                i += 2
                                continue
                        if nxt in (DO, WILL, DONT, WONT):
                                if i + 2 < n and data[i + 2] == opt and nxt == cmd:
                                        return True
                                i += 3
                                continue
                        i += 2
                return False

        def is_ssl(self):
                """ returns True if the connection is SSL. False if not. """
                return self.ssl
