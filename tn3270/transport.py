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


def _make_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
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
                """Try TLS then plaintext. Returns (sock, used_ssl) or (None, False).
                is_ssl() is True only after a successful SSLContext wrap.
                disable_ssl() skips the TLS attempt entirely."""
                raw = None
                if self._try_ssl:
                        try:
                                self.msg(1, 'Tryin SSL/TSL')
                                raw = socket.create_connection((host, port), timeout)
                                raw.settimeout(timeout)
                                ssl_sock = _make_ssl_context().wrap_socket(
                                        raw, server_hostname=host)
                                return ssl_sock, True
                        except (ssl.SSLError, OSError) as e:
                                self.msg(1, 'SSL/TLS Failed. Trying Plaintext')
                                if raw is not None:
                                        try:
                                                raw.close()
                                        except OSError:
                                                pass
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
                self.sock = 0
                if sock:
                        sock.close()

        def get_socket(self):
                """Return the socket object used internally."""
                return self.sock

        def send_data(self, data):
                """Sends raw data to the TN3270 server """
                if isinstance(data, str):
                        data = data.encode('latin1')
                elif isinstance(data, int):
                        data = bytes((data,))
                elif isinstance(data, bytearray):
                        data = bytes(data)
                self.msg(2,"send %r", data)
                self.sock.sendall(data)

        def recv_data(self):
                """ Receives 256 bytes of data; blocking"""
                self.msg(2,"Getting Data")
                buf = self.sock.recv(256)
                self.msg(2,"Got Data: %r", buf)
                return buf

        def check_tn3270( self, host, port=0, timeout=3 ):
                """ Checks if a host & port supports TN3270 """
                if not port:
                        port = TELNET_PORT
                sock, _used_ssl = self._open_socket(host, port, timeout)
                if sock is None:
                        return False

                data = sock.recv(256)
                if data == _bytes(IAC, DO, options['TN3270E']):
                        sock.close()
                        return True
                elif data == _bytes(IAC, DO, options['TTYPE']):
                        sock.sendall(_bytes(IAC, WILL, options['TTYPE']))
                        data = sock.recv(256)
                        if data != _bytes(IAC, SB, options['TTYPE'], SEND, IAC, SE) or data == b'':
                                sock.close()
                                return False
                        sock.sendall(_bytes(IAC, SB, options['TTYPE'], IS, DEVICE_TYPE, IAC, SE))
                        data = sock.recv(256)
                        if data[0:2] == _bytes(IAC, DO):
                                sock.close()
                                return True
                sock.close()
                return False

        def is_ssl(self):
                """ returns True if the connection is SSL. False if not. """
                return self.ssl
