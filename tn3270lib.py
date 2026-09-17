#!/usr/bin/env python3
# TN3270 Library based heavily on x3270 and python telnet lib
# Created by Phil "Soldier of Fortran" Young
#
# The implementation now lives in the tn3270 package; this module is kept as a
# facade so existing callers keep working unchanged:
#
# >>> import tn3270lib
# >>> tn3270 = tn3270lib.TN3270()
# To connect to a host use the initiate function.
# This library will attempt TLS first (legacy-permissive by default).
# Plaintext is used only if you pass allow_plaintext=True or disable_ssl(True).
# require_tls=True fails the connect when the handshake fails.
# >>> host = "10.10.0.10"
# >>> port = 23
# >>> tn3270.initiate(host, port)
# True
# >>> data = tn3270.get_screen()
# >>> print(data)
# z/OS V1R13 PUT Level 1209                          IP Address = 10.10.0.13
#                                                    VTAM Terminal =
#
#                        Application Developer System
#
#                                 //  OOOOOOO   SSSSS
#                                //  OO    OO SS
#                        zzzzzz //  OO    OO SS
#                          zz  //  OO    OO SSSS
#                        zz   //  OO    OO      SS
#                      zz    //  OO    OO      SS
#                    zzzzzz //   OOOOOOO  SSSS
#
#
#                    System Customization - ADCD.Z113H.*
#
#
#
#
#  ===> Enter "LOGON" followed by the TSO userid. Example "LOGON IBMUSER" or
#  ===> Enter L followed by the APPLID
#  ===> Examples: "L TSO", "L CICSTS41", "L CICSTS42", "L IMS11", "L IMS12"
# >>> tn3270.disconnect()
#
# A check function has also been created to check if the server accepts tn3270 connections.
# Returns True if the socket supports tn3270, False if not.
#
# >>> tn3270.check_tn3270(host, port)
# True
#
# 9/27/2015: IND$FILE Transfer added
# With this library you can now send and receive files/datasets
# EBCDIC to ASCII translation is done by z/OS if you use the get/send_ascii 
# functions
#
# Send Files with send_ascii_file/send_binary_file:
# >>> tn3270.send_ascii_file("'ibmuser.jcltest'","/home/dade/awesome.jcl")
# >>> tn3270.send_binary_file("'ibmuser.exec'","/home/dade/a.out")
# 
# Receive files with get_ascii_file/get_binary_file
# >>> tn3270.get_ascii_file("'ibmuser.jcltest'","/home/dade/new.jcl")
# >>> tn3270.get_binary_file("'ibmuser.asm(compiled)'","/home/dade/compiled.asm")
#
#########
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#########
#  TO DO:
#     - Add Partitions
#     - Switch fields
#

import socket
import sys

from tn3270.constants import *
from tn3270.ebcdic import _ebcdic_to_str, _str_to_ebcdic
from tn3270.transport import _bytes, _make_ssl_context
from tn3270.indfile import _chunk_len
from tn3270.client import TN3270, TN3270Timeout, TN3270KeyboardLocked
from tn3270 import __version__  # noqa: F401


def test():
        """Test program for tn3270lib.

        Usage: python tn3270lib.py [-d] ... [host [port]]

        Default host is localhost; default port is 23.

        """
        debuglevel = 0
        while sys.argv[1:] and sys.argv[1] == '-d':
            debuglevel = debuglevel+1
            del sys.argv[1]
        host = 'localhost'
        if sys.argv[1:]:
            host = sys.argv[1]
        port = 0
        if sys.argv[2:]:
            portstr = sys.argv[2]
            try:
                port = int(portstr)
            except ValueError:
                port = socket.getservbyname(portstr, 'tcp')
        tn = TN3270()
        tn.set_debuglevel(debuglevel)
        tn.initiate(host, port)
        tn.print_screen()
        tn.disconnect()

if __name__ == '__main__':
        test()
