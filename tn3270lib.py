# TN3270 Library based heavily on x3270 and python telnet lib
# Created by Phil "Soldier of Fortran" Young
#
# To use this library create a tn3270 object
# >>> import tn3270lib
# >>> tn3270 = tn3270lib.TN3270()
# To connect to a host use the initiate function.
# This library will attempt SSL first
# then connect without ssl if that fails.
# >>> host = "10.10.0.10"
# >>> port = 23
# >>> tn3270.initiate(host, port)
# True
# >>> data = tn3270.get_screen()
# >>> print data
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


import errno
import sys
import socket
import ssl
import select
import struct
import binascii
import math


# Tunable parameters
DEBUGLEVEL = 0 

# Telnet protocol commands
SE   = chr(240) #End of subnegotiation parameters
SB   = chr(250) #Sub-option to follow
WILL = chr(251) #Will; request or confirm option begin
WONT = chr(252) #Wont; deny option request
DO   = chr(253) #Do = Request or confirm remote option
DONT = chr(254) #Don't = Demand or confirm option halt
IAC  = chr(255) #Interpret as Command
SEND = chr(001) #Sub-process negotiation SEND command
IS   = chr(000) #Sub-process negotiation IS command


#TN3270 Telnet Commands
TN_ASSOCIATE  = chr(0)
TN_CONNECT    = chr(1)
TN_DEVICETYPE = chr(2)
TN_FUNCTIONS  = chr(3)
TN_IS         = chr(4)
TN_REASON     = chr(5)
TN_REJECT     = chr(6)
TN_REQUEST    = chr(7)
TN_RESPONSES  = chr(2)
TN_SEND       = chr(8)
TN_TN3270     = chr(40)
TN_EOR        = chr(239) #End of Record

#Supported Telnet Options
options = {
	'BINARY'  : chr(0),
	'EOR'     : chr(25),
	'TTYPE'   : chr(24),
	'TN3270'  : chr(40),
	'TN3270E' : chr(28)
  }

supported_options = {
	 chr(0)  : 'BINARY',
	 chr(25) : 'EOR',
	chr(24)  : 'TTYPE',
	chr(40)  : 'TN3270',
	chr(28)  : 'TN3270E'
  }

#TN3270 Stream Commands: TCPIP
EAU   = chr(15)
EW    = chr(5)
EWA   = chr(13)
RB    = chr(2)
RM    = chr(6)
RMA   = ''
W     = chr(1)
WSF   = chr(17)
NOP   = chr(3)
SNS   = chr(4)
SNSID = chr(228)
#TN3270 Stream Commands: SNA
SNA_RMA   = chr(110)
SNA_EAU   = chr(111)
SNA_EWA   = chr(126)
SNA_W     = chr(241)
SNA_RB    = chr(242)
SNA_WSF   = chr(243)
SNA_EW    = chr(245)
SNA_NOP   = chr(003)
SNA_RM    = chr(246)


#TN3270 Stream Orders
SF  = chr(29)
SFE = chr(41)
SBA = chr(17)
SA  = chr(40)
MF  = chr(44)
IC  = chr(19)
PT  = chr(5)
RA  = chr(60)
EUA = chr(18)
GE  = chr(8)


#TN3270 Format Control Orders
NUL = chr(0)
SUB = chr(63)
DUP = chr(28)
FM  = chr(30)
FF  = chr(12)
CR  = chr(13)
NL  = chr(21)
EM  = chr(25)
EO  = chr(255)

#TN3270 Attention Identification (AIDS)
#####
# SoF ## Left this as hex because i coulnd't
#        be bothered to convert to decimal
#####
NO      = chr(0x60) #no aid
QREPLY  = chr(0x61) #reply
ENTER   = chr(0x7d) #enter
PF1     = chr(0xf1)
PF2     = chr(0xf2)
PF3     = chr(0xf3)
PF4     = chr(0xf4)
PF5     = chr(0xf5)
PF6     = chr(0xf6)
PF7     = chr(0xf7)
PF8     = chr(0xf8)
PF9     = chr(0xf9)
PF10    = chr(0x7a)
PF11    = chr(0x7b)
PF12    = chr(0x7c)
PF13    = chr(0xc1)
PF14    = chr(0xc2)
PF15    = chr(0xc3)
PF16    = chr(0xc4)
PF17    = chr(0xc5)
PF18    = chr(0xc6)
PF19    = chr(0xc7)
PF20    = chr(0xc8)
PF21    = chr(0xc9)
PF22    = chr(0x4a)
PF23    = chr(0x4b)
PF24    = chr(0x4c)
OICR    = chr(0xe6)
MSR_MHS = chr(0xe7)
SELECT  = chr(0x7e)
PA1     = chr(0x6c)
PA2     = chr(0x6e)
PA3     = chr(0x6b)
CLEAR   = chr(0x6d)
SYSREQ  = chr(0xf0)

# used for Structured Fields
AID_SF      = chr(0x88)
SFID_QREPLY	= chr(0x81)

 #TN3270 Code table to translate buffer addresses

code_table=[0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
			0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
			0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
			0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
			0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
			0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
			0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
			0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F]

#TN3270 Datatream Processing flags
NO_OUTPUT      = 0
OUTPUT         = 1
BAD_COMMAND    = 2
BAD_ADDRESS    = 3
NO_AID         = 0x60



#Header response flags.
NO_RESPONSE       = 0x00
ERROR_RESPONSE    = 0x01
ALWAYS_RESPONSE   = 0x02
POSITIVE_RESPONSE = 0x00
NEGATIVE_RESPONSE = 0x01

#Header data type names.
DT_3270_DATA    = 0x00
DT_SCS_DATA     = 0x01
DT_RESPONSE     = 0x02
DT_BIND_IMAGE   = 0x03
DT_UNBIND       = 0x04
DT_NVT_DATA     = 0x05
DT_REQUEST      = 0x06
DT_SSCP_LU_DATA = 0x07
DT_PRINT_EOJ    = 0x08

#Header response data.
POS_DEVICE_END             = 0x00
NEG_COMMAND_REJECT         = 0x00
NEG_INTERVENTION_REQUIRED  = 0x01
NEG_OPERATION_CHECK        = 0x02
NEG_COMPONENT_DISCONNECTED = 0x03

# Structured fields
# From x3270 sf.c
SF_READ_PART      = chr(0x01)	# read partition
SF_RP_QUERY       = chr(0x02)	#query
SF_RP_QLIST       = chr(0x03)	#query list
SF_RPQ_LIST       = chr(0x00)	# QCODE list
SF_RPQ_EQUIV      = chr(0x40)	# equivalent+ QCODE list
SF_RPQ_ALL        = chr(0x80)	# all
SF_ERASE_RESET    = chr(0x03)	# erase/reset
SF_ER_DEFAULT     = chr(0x00)	#default
SF_ER_ALT         = chr(0x80)	#alternate
SF_SET_REPLY_MODE = chr(0x09)	# set reply mode
SF_SRM_FIELD      = chr(0x00)	#field
SF_SRM_XFIELD     = chr(0x01)	#extended field
SF_SRM_CHAR       = chr(0x02)	#character
SF_CREATE_PART    = chr(0x0c)	#create partition
CPFLAG_PROT       = chr(0x40)	#protected flag
CPFLAG_COPY_PS    = chr(0x20)	#local copy to presentation space
CPFLAG_BASE       = chr(0x07)	#base character set index
SF_OUTBOUND_DS    = chr(0x40)	#outbound 3270 DS
SF_TRANSFER_DATA  = chr(0xd0)   #file transfer open request

#Data Transfer
# Host requests.
TR_OPEN_REQ			= 0x0012	#open request
TR_CLOSE_REQ		= 0x4112	 	#close request
TR_SET_CUR_REQ		= 0x4511	#set cursor request
TR_GET_REQ			= 0x4611	#get request
TR_INSERT_REQ		= 0x4711	#insert request
TR_DATA_INSERT		= 0x4704	#data to insert

# PC replies.
TR_GET_REPLY		= 0x4605	#data for get
TR_NORMAL_REPLY		= 0x4705	#insert normal reply
TR_ERROR_REPLY		= 0x08	#error reply (low 8 bits)
TR_CLOSE_REPLY		= 0x4109	#close acknowledgement

# Other headers.
TR_RECNUM_HDR		= 0x6306	#record number header
TR_ERROR_HDR		= 0x6904	#error header
TR_NOT_COMPRESSED	= 0xc080	#data not compressed
TR_BEGIN_DATA		= 0x61	#beginning of data

# Error codes.
TR_ERR_EOF			= 0x2200	#get past end of file
TR_ERR_CMDFAIL		= 0x0100	#command failed

DFT_BUF             = 4096  # Default buffer size
DFT_MIN_BUF         = 256   # Minimum file send buffer size
DFT_MAX_BUF	        = 32768 # Max buffer size

# File Transfer Constants
FT_NONE       = 1   # No transfer in progress
FT_AWAIT_ACK  = 2   # IND$FILE sent, awaiting acknowledgement message



#TN3270E Negotiation Options

TN3270E_ASSOCIATE	= chr(0x00)
TN3270E_CONNECT		= chr(0x01)
TN3270E_DEVICE_TYPE	= chr(0x02)
TN3270E_FUNCTIONS   = chr(0x03)
TN3270E_IS			= chr(0x04)
TN3270E_REASON		= chr(0x05)
TN3270E_REJECT		= chr(0x06)
TN3270E_REQUEST		= chr(0x07)
TN3270E_SEND		= chr(0x08)

#Global Vars
NEGOTIATING    = 0
CONNECTED      = 1
TN3270_DATA    = 2
TN3270E_DATA   = 3
#We only support 3270 model 2 wich was 24x80.
#
#DEVICE_TYPE    = "IBM-3278-2"
#
DEVICE_TYPE    = "IBM-3279-2-E"
COLS           = 80 # hardcoded width.
ROWS           = 24 # hardcoded rows.
WORD_STATE     = ["Negotiating", "Connected", "TN3270 mode", "TN3270E mode"]
TELNET_PORT    = 23

# For easy debugging/printing:
telnet_commands = {
	SE   : 'SE',
	SB   : 'SB',
	WILL : 'WILL',
	WONT : 'WONT',
	DO   : 'DO',
	DONT : 'DONT',
	IAC  : 'IAC',
	SEND : 'SEND',
	IS   : 'IS'
}

telnet_options = {
	TN_ASSOCIATE  : 'ASSOCIATE',
	TN_CONNECT    : 'CONNECT',
	TN_DEVICETYPE : 'DEVICE_TYPE',
	TN_FUNCTIONS  : 'FUNCTIONS',
	TN_IS         : 'IS',
	TN_REASON     : 'REASON',
	TN_REJECT     : 'REJECT',
	TN_REQUEST    : 'REQUEST',
	TN_RESPONSES  : 'RESPONSES',
	TN_SEND       : 'SEND',
	TN_TN3270     : 'TN3270',
	TN_EOR        : 'EOR'
}

tn3270_options = {
	TN3270E_ASSOCIATE	:'TN3270E_ASSOCIATE',
	TN3270E_CONNECT		:'TN3270E_CONNECT',
	TN3270E_DEVICE_TYPE :'TN3270E_DEVICE_TYPE',
	TN3270E_FUNCTIONS	:'TN3270E_FUNCTIONS',
	TN3270E_IS			:'TN3270E_IS',
	TN3270E_REASON		:'TN3270E_REASON',
	TN3270E_REJECT		:'TN3270E_REJECT',
	TN3270E_REQUEST		:'TN3270E_REQUEST',
	TN3270E_SEND		:'TN3270E_SEND'
}


class TN3270:
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
		self.sb_options     = ''
		self.connected_lu   = ''
		self.connected_dtype= ''
		#self.negotiated     = False
		self.first_screen   = False
		self.aid            = NO_AID  #initial Attention Identifier is No AID
		self.telnet_data    = ''
		self.tn_buffer      = ''
		self.raw_tn         = [] #Stores raw TN3270 'frames' for use
		self.state          = 0
		self.buffer_address = 0
		self.formatted      = False,

		#TN3270 Buffer Address Location
		self.buffer_addr = 0
		#TN3270 Cursor Tracking Location
		self.cursor_addr = 0
		self.screen          = []
		self.printableScreen = []
		self.header          = []

		#TN3270 Buffers
		self.buffer         = []
		self.fa_buffer      = []
		self.output_buffer  = []
		self.overwrite_buf  = []
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

	def connect(self, host, port=0, timeout=30):
		"""Connects to a TN3270 Server. aka a Mainframe!"""
		self.ssl = False
		if not port:
			port = TELNET_PORT
		self.host = host
		self.port = port
		self.timeout = timeout
		#Try SSL First
		try:
			self.msg(1,'Tryin SSL/TSL')
			non_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = ssl.wrap_socket(sock=non_ssl,cert_reqs=ssl.CERT_NONE)
			ssl_sock.settimeout(timeout)
			ssl_sock.connect((host,port))
			self.sock = ssl_sock
		except (ssl.SSLError,socket.error), e:
			non_ssl.close()
			self.msg(1, 'SSL/TLS Failed. Trying Plaintext')
			try:
				self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.sock.settimeout(timeout)
				self.sock.connect((host,port))
			except Exception, e:
				self.msg( 1,'Error: %r', e)
				return False
		except Exception, e:
			self.msg( 1,'[SSL] Error: %r', e)
			return False
		
		return True

	def __del__(self):
		"""Destructor ## close the connection."""
		self.disconnect()

	def msg(self, level, msg, *args):
		"""Print a debug message, when the debug level is > 0.

		If extra arguments are present, they are substituted in the
		message using the standard string formatting operator.

		"""
		if self.debuglevel  >= level:
			print 'TN3270(%s,%s):' % (self.host, self.port),
			if args:
				print msg % args
			else:
				print msg

	def set_debuglevel(self, debuglevel=1):
		"""Set the debug level.

		The higher it is, the more debug output you get (on sys.stdout).
		So far only levels 1 (verbose) and 2 (debug) exist.

		"""
		self.debuglevel = debuglevel

        def set_LU(self, LU):
                """ Sets an LU to use on connection """
                self.connected_lu = LU

	def disable_enhanced(self, disable=True):
		self.msg(1,'Disabling TN3270E Option')
		if disable:
			self.unsupported_opts[chr(40)] = 'TN3270'
		else:
			self.unsupported_opts.pop('TN3270', None)

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
		self.msg(2,"send %r", data)
		self.sock.sendall(data)

	def recv_data(self):
		""" Receives 256 bytes of data; blocking"""
		self.msg(2,"Getting Data")
		buf = self.sock.recv(256)
		self.msg(2,"Got Data: %r", buf)
		return buf

	def DECODE_BADDR(self, byte1, byte2):
		""" Decodes Buffer Addresses.
			Buffer addresses can come in 14 or 12 (this terminal doesn't support 16 bit)
			this function takes two bytes (buffer addresses are two bytes long) and returns
			the decoded buffer address."""
		if (byte1 & 0xC0) == 0:
			return (((byte1 & 0x3F) << 8) | byte2) + 1
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
		return ((addr + 1) % (COLS * ROWS))

	def check_tn3270( self, host, port=0, timeout=3 ):
		""" Checks if a host & port supports TN3270 """
		if not port:
			port = TELNET_PORT
		try:
			non_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = ssl.wrap_socket(sock=non_ssl,cert_reqs=ssl.CERT_NONE)
			ssl_sock.settimeout(timeout)
			ssl_sock.connect((host,port))
			sock = ssl_sock
		except ssl.SSLError, e:
			non_ssl.close()
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(timeout)
				sock.connect((host,port))
			except Exception, e:
				self.msg( 1,'Error: %r', e)
				return False
		except Exception, e:
			self.msg( 1,'Error: %r', e)
			return False


		data = sock.recv(256)
		if data == IAC + DO + options['TN3270']:
			sock.close()
			return True
		elif data == IAC + DO + options['TTYPE']:
			sock.sendall(IAC + WILL + options['TTYPE'])
			data = sock.recv(256)
			if data != IAC + SB + options['TTYPE'] + SEND + IAC + SE or data == '':
				return False
			sock.sendall(IAC + SB + options['TTYPE'] + IS + DEVICE_TYPE + IAC + SE)
			data = sock.recv(256)
			if data[0:2] == IAC + DO:
				sock.close()
				return True
		return False

	def initiate( self, host, port=0, timeout=5 ):
		""" Initiates a TN3270 connection until it gets the first 'screen' """
		#if not self.check_tn3270(host, port):
		#	return False
		if not self.connect(host,port, timeout):
			return False

		self.client_options = {}
		self.server_options = {}
		self.state = NEGOTIATING
		self.first_screen = False

		while not self.first_screen:
			self.telnet_data = self.recv_data()
			self.msg(2,"Got telnet_data: %r", self.telnet_data)
			r = self.process_packets()
			if not r: 
				return False
		return True

	def get_data( self ):
		""" Gets the tn3270 buffer currently on the stack """
		status = True
		self.first_screen = False
		while not self.first_screen and status:
			try:
				self.telnet_data = self.recv_data()
				self.process_packets()
			except socket.timeout, e:
				err = e.args[0]
				if err == 'timed out':
					#sleep(1)
					self.msg(1,"recv timed out! We're done here")
					break
			except socket.error, e:
				err = e.args[0]
				if 'timed out' in err: # This means the SSL socket timed out, not a regular socket so we catch it here
					self.msg(1,"recv timed out! We're done here")
					break
		        # Something else happened, handle error, exit, etc.
				self.msg(1,"Get Data Socket Error Received: %r", e)
				
	def get_all_data( self ):
		""" Mainframes will often send a 'confirmed' screen before it sends
		    the screen we care about, this function clumsily gets all screens
		    sent so far """
		self.first_screen = False
		self.sock.settimeout(2)
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
			except socket.timeout, e:
				err = e.args[0]
				if err == 'timed out':
					#sleep(1)
					self.msg(1,"recv timed out! We're done here")
					break
			except socket.error, e:
		        # Something else happened, handle error, exit, etc.
				self.msg(1,"Error Received: %r", e)
				#break
		self.sock.settimeout(None)

	def process_packets( self ):
		""" Processes Telnet data """
		for i in self.telnet_data:
			self.msg(2,"Processing: %r", i)
			r = self.ts_processor(i)
			if not r: return False
			self.telnet_data = '' #once all the data has been processed we clear out the buffer
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
		DO_reply   = IAC + DO
		DONT_reply = IAC + DONT
		WILL_reply = IAC + WILL
		WONT_reply = IAC + WONT

		#self.msg('State is: %r', self.telnet_state)
		if self.telnet_state == TNS_DATA:
		  if data == IAC:
			## got an IAC
			self.telnet_state = TNS_IAC
			return True
		  self.store3270(data)
		elif self.telnet_state == TNS_IAC:
		  if data == IAC:
			## insert this 0xFF in to the buffer
			self.store3270(data)
			self.telnet_state = TNS_DATA
		  elif data == TN_EOR:
			## we're at the end of the TN3270 data
			## let's process it and see what we've got
			## but only if we're in 3270 mode
			if self.state == TN3270_DATA or self.state == TN3270E_DATA:
			  self.process_data()
			self.telnet_state = TNS_DATA
		  elif data == WILL: self.telnet_state = TNS_WILL
		  elif data == WONT: self.telnet_state = TNS_WONT
		  elif data == DO  : self.telnet_state = TNS_DO
		  elif data == DONT: self.telnet_state = TNS_DONT
		  elif data == SB  : 
		  	self.telnet_state = TNS_SB
		  	self.sb_options = ''
		elif self.telnet_state == TNS_WILL:
		   if data in supported_options and not (data in self.unsupported_opts) :
			self.msg(1, "<< IAC WILL %s", supported_options[data])
			if not self.server_options.get(data, False): ## if we haven't already replied to this, let's reply
			  self.server_options[data] = True
			  self.send_data(DO_reply + data)
			  self.msg(1,">> IAC DO %s", supported_options[data])
			  self.in3270()
		   else:
			self.send_data(DONT_reply+data)
			self.msg(1,">> IAC DONT %r", data)
		   self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_WONT:
		  if self.server_options.get(data, False):
			self.server_options[data] = False
			self.send_data(DONT_reply + data)
			self.msg(1,"Sent WONT Reply %r", data)
			self.in3270()
		  self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_DO:
		  if data in supported_options and not (data in self.unsupported_opts) :
		  	self.msg(1,"<< IAC DO %s", supported_options[data])
			if not self.client_options.get(data, False):
			  self.client_options[data] = True
			  self.send_data(WILL_reply + data)
			  self.msg(1,">> IAC WILL %s", supported_options[data])
			  self.in3270()
		  else:
			self.send_data(WONT_reply+data)
			self.msg(1,"Unsupported 'DO'.")
			if data in options:
				self.msg(1,">> IAC WONT %s", options[data])
			else:
				self.msg(1,">> IAC WONT %r", data)
		  self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_DONT:
		  if self.client_options.get(data, False):
			self.client_options[data] = False
			self.send_data(WONT_reply + data)
			self.msg(1,">> IAC DONT %r", data)
			self.in3270()
		  self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_SB:
		  if data == IAC:
			self.telnet_state = TNS_SB_IAC
		  else:
			self.sb_options = self.sb_options + data
		elif self.telnet_state == TNS_SB_IAC:
		  #self.msg(1,"<< IAC SB")
		  self.sb_options = self.sb_options + data
		  if data == SE:
		  	#self.msg(1,"Found 'SE' %r", self.sb_options)
			self.telnet_state = TNS_DATA
			if self.state != TN3270E_DATA:
				phrase = ''
				for i in self.sb_options: 
					if i in telnet_options: phrase += telnet_options[i] + ' '
					elif i in telnet_commands: phrase += telnet_commands[i] + ' '
					elif i in supported_options: phrase += supported_options[i] + ' '
					else: phrase += i + ' '
				self.msg(1,"<< IAC SB %s", phrase)
			if (self.sb_options[0] == options['TTYPE'] and
			    self.sb_options[1] == SEND ):
			  self.msg(1,">> IAC SB TTYPE IS DEVICE_TYPE IAC SE")
			  self.send_data(IAC + SB + options['TTYPE'] + IS + DEVICE_TYPE + IAC + SE)
			elif self.client_options.get(options['TN3270'], False) and self.sb_options[0] == options['TN3270']:
			  if not self.negotiate_tn3270():
				return False
		return True

	def negotiate_tn3270(self):
		""" Negotiates TN3270E Options. Which are different than Telnet 
		    starts if the server options requests IAC DO TN3270 """
		#self.msg(1,"TN3270E Option Negotiation")
		TN3270_REQUEST = {
		chr(0) : 'BIND_IMAGE',
		chr(1) : 'DATA_STREAM_CTL',
		chr(2) : 'RESPONSES',
		chr(3) : 'SCS_CTL_CODES',
		chr(4) : 'SYSREQ'
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
			else: phrase += i + ' '
		self.msg(1,"<< IAC SB %s", phrase)
		#print self.hexdump(self.sb_options)
		if self.sb_options[1] ==  TN3270E_SEND:
			if self.sb_options[2] == TN3270E_DEVICE_TYPE:
				DEVICE_TYPE = 'IBM-3278-2-E'
				if self.connected_lu == '':
					self.msg(1,">> IAC SB TN3270 TN3270E_DEVICE_TYPE TN3270E_REQUEST %s IAC SE", DEVICE_TYPE)
					self.send_data(IAC + SB + options['TN3270'] + TN3270E_DEVICE_TYPE + TN3270E_REQUEST + DEVICE_TYPE + IAC + SE)
				else:
					self.msg(1,">> IAC SB TN3270 TN3270E_DEVICE_TYPE TN3270E_REQUEST "+DEVICE_TYPE+" CONNECT "+self.connected_lu+" IAC SE")
					self.send_data(IAC + SB + options['TN3270'] + TN3270E_DEVICE_TYPE + TN3270E_REQUEST + DEVICE_TYPE + TN_CONNECT + self.connected_lu + IAC + SE)
		elif self.sb_options[1] == TN3270E_DEVICE_TYPE:
			if self.sb_options[2] == TN3270E_REJECT:
				self.msg(1, 'Received TN3270E_REJECT after sending LU %s', self.connected_lu)
				return False
			SE_location = self.sb_options.find(SE)
			CONNECT_option = self.sb_options.find(TN3270E_CONNECT)
			if CONNECT_option > 1 and CONNECT_option < SE_location:
				self.connected_dtype = self.sb_options[3:CONNECT_option]
			else:
				self.connected_dtype = self.sb_options[3:SE_location]
			if CONNECT_option > 1: 
				self.connected_lu= self.sb_options[CONNECT_option+1:SE_location]
				#self.tn3270e_options(TN3270E_REQUEST)
			self.msg(1,'Confirmed Terminal Type: %s',self.connected_dtype)
			self.msg(1,'LU Name: %s', self.connected_lu)
			self.msg(1,'>> IAC SB TN3270 TN3270E_FUNCTIONS TN3270E_REQUEST IAC SE')
			self.send_data(IAC + SB + options['TN3270'] + TN3270E_FUNCTIONS + TN3270E_REQUEST + IAC + SE)
		elif self.sb_options[1] == TN3270E_FUNCTIONS:
			if self.sb_options[1] != TN3270E_IS:
			# Seriously dog? We don't support anything can you just let it go?
				self.msg(1,'>> IAC SB TN3270 TN3270E_FUNCTIONS TN3270E_REQUEST IAC SE')
				self.send_data(IAC + SB + options['TN3270'] + TN3270E_FUNCTIONS + TN3270E_REQUEST + IAC + SE)
			else:
				self.msg(1,"TN3270 Negotiation Complete!")
			## At this point we should be done negotiating options and recieve tn3270 data with a tn3270e header
		return True

	#def tn3270e_options(self, option_type):

	## Stores a character on a buffer to be processed
	def store3270(self, char ):
		""" Stores a character on the tn3270 buffer """
		self.tn_buffer += char

	## Also known as process_eor in x3270
	def process_data( self ):
		""" Processes TN3270 data """
		reply = 0
		self.msg(1,"Processing TN3270 Data")
	## We currently don't support TN3270E but this is here for future expansion
	## J/K We totally do now! SoF 8/24/2016
		if self.state == TN3270E_DATA:
			self.msg(1, 'Parsing TN3270E Header')
			self.tn3270_header['data_type']   = self.tn_buffer[0]
			self.tn3270_header['request_flag']  = self.tn_buffer[1]
			self.tn3270_header['response_flag'] = self.tn_buffer[2]
			self.tn3270_header['seq_number']    = self.tn_buffer[3:5]
			if self.tn3270_header['data_type'] == "\000": #3270_DATA
				self.process_3270(self.tn_buffer[5:])
				self.raw_tn.append(self.tn_buffer[5:])



	#			reply = self:process_3270(self.tn_buffer:sub(6))
    # if reply < 0 and self.tn3270_header.request_flag ~= self.TN3270E_RSF_NO_RESPONSE:
    #    self.tn3270e_nak(reply)
    #  elseif reply == self.NO_OUTPUT and
    #         self.tn3270_header.request_flag == self.ALWAYS_RESPONSE then
    #    self.tn3270e_ack()
    #  end
		else:
			self.process_3270(self.tn_buffer)
			self.raw_tn.append(self.tn_buffer)
    #end
    #nsedebug.print_hex(self.tn_buffer)

		self.tn_buffer = ''
		return  True

	def in3270(self):
		if self.client_options.get(options['TN3270'], False):
			#if self.negotiated:
			self.state = TN3270E_DATA
		elif (  self.server_options.get(options['EOR'], False)    and
				self.server_options.get(options['BINARY'], False) and
				self.client_options.get(options['BINARY'], False) and
				self.client_options.get(options['TTYPE'], False)  ):
			self.state = TN3270_DATA
		if self.state == TN3270_DATA or self.state == TN3270E_DATA:
			## since we're in TN3270 mode, let's create an empty buffer
			self.msg(1,'Entering TN3270 Mode:')
			self.msg(1,"\tCreating Empty IBM-3278-2 Buffer")
			self.buffer = list("\0" * 1920)
			self.fa_buffer = list("\0" * 1920)
			self.overwrite_buf = list("\0" * 1920)
			self.msg(1,"\tCreated buffers of length: %r", 1920)
		self.msg(1,"Current State: %r", WORD_STATE[self.state])

	def clear_screen( self ):
		self.buffer_address = 0
		self.buffer = list("\0" * 1920)
		self.fa_buffer = list("\0" * 1920)
		self.overwrite_buf = list("\0" * 1920)

	def clear_unprotected( self ):
		## We'll ignore this for now since we ignore the protected field anyway
		return

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
		# We don't do anything with these (for now)
		# But they're here for informational purposes
		if (struct.unpack(">B", data[i])[0] & 0x40): #WCC_RESET
			self.msg(2,"WCC Reset")

		if (struct.unpack(">B", data[i])[0] & 0x02): #WCC_KEYBOARD_RESTORE
			self.msg(2,"WCC Restore")


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
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
				self.write_field_attribute(data[i])
				#set the current position one ahead (after SF)
				i = i + 1
				self.write_char("\00")

			elif cp == SFE:
				self.msg(2,"Start Field Extended")
				i = i + 1 # skip SFE
				num_attr = struct.unpack(">B",data[i])[0]
				self.msg(2,"Number of Attributes: %r", num_attr)
				for j in range(num_attr):
					i = i + 1
					if struct.unpack(">B", data[i])[0] == 0xc0:
						# 0xc0 represent field attributes
						# since we don't support colors (yet)
						# we ignore the other values
						self.msg(2,"Writting Zero to buffer at address: %r", self.buffer_address)
						self.msg(2,"Attribute Type: %r", data[i+1])
						self.write_char("\0")
						self.write_field_attribute(data[i+1])
					i = i + 1
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
				i = i + 1
				
			elif cp == SBA:
				self.msg(2,"Set Buffer Address (SBA) 0x11")
				self.buffer_address = self.DECODE_BADDR(struct.unpack(">B", data[i + 1])[0],
														struct.unpack(">B", data[i + 2])[0])
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
				ra_baddr = self.DECODE_BADDR(struct.unpack(">B", data[i + 1])[0],
		                                     struct.unpack(">B", data[i + 2])[0])
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
				eua_baddr = self.DECODE_BADDR(struct.unpack(">B", data[i + 1])[0],
		                                      struct.unpack(">B", data[i + 2])[0])
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
			# SHHH don't tell anyone that we just skip these
			# But here is where Set Attribue is done. Things like Hidden and Protected

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
				self.write_char(chr(064))
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
				i = i + 1
			else: # whoa we made it.
				ascii_char = cp.decode('EBCDIC-CP-BE').encode('utf-8')
				self.msg(2,"Inserting "+ ascii_char + " (%r) at the following location:", data[i])
				self.msg(2,"Row: %r" , self.BA_TO_ROW(self.buffer_address))
				self.msg(2,"Col: %r" , self.BA_TO_COL(self.buffer_address))
				self.msg(2,"Buffer Address: %r" , self.buffer_address)
				self.write_char(data[i])
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
				self.first_screen = True
				i = i + 1
			# end of massive if/else
	    # end of while loop
    		self.formatted = True

    




	def write_char( self, char ):
		""" Writes a character to the screen buffer.
		    If a character already exists at that location,
		    write the char in the screen buffer to a backup buffer """
		if self.buffer[self.buffer_address-1] == "\0":
			self.buffer[self.buffer_address-1] = char
		else:
			self.overwrite_buf[self.buffer_address-1] = self.buffer[self.buffer_address]
			self.buffer[self.buffer_address-1] = char

	def write_field_attribute( self, attr ):
		""" Writes Field attributes to the field attribute buffer """
		self.fa_buffer[self.buffer_address-1] = attr

	def print_screen( self ):
		""" Prints the current TN3270 screen buffer """
		self.msg(1,"Printing the current TN3270 buffer:")
		print self.get_screen()

	def get_screen ( self ):
		""" Returns the current TN3270 screen buffer formatted for printing """
		self.msg(1,"Generating the current TN3270 buffer in ASCII")
		buff = ''
		i = 1
		for line in self.buffer:
			if line == "\0":
				buff += " "
			else:
				buff += line.decode('EBCDIC-CP-BE').encode('utf-8')
			if i % 80 == 0:
				buff += '\n'

			i = i + 1
		return buff

	def process_read( self ):
		""" Processes READ commands from server """
		output_addr = 0
		self.output_buffer = []
		self.msg(1,"Generating Read Buffer")
		self.output_buffer.insert(output_addr, struct.pack(">B",self.aid))
		output_addr = output_addr + 1
		self.msg(1,"Output Address: %r", output_addr)
		self.output_buffer.insert(output_addr, self.ENCODE_BADDR(self.cursor_addr))
		self.send_tn3270(self.output_buffer)
    	#need to add while loop for MF, <3 <3 someday

	def process_read_modified(self, aid):
		""" Process Read modified. This is a shell since all it really does is say 'nothing' """
		output_addr = 0
		self.output_buffer = []
		self.msg(1,"Generating Read Buffer")
		self.output_buffer.insert(output_addr, struct.pack(">B",self.aid))
		output_addr = output_addr + 1
		self.msg(1,"Output Address: %r", output_addr)
		self.output_buffer.insert(output_addr, self.ENCODE_BADDR(self.cursor_addr))
		self.send_tn3270(self.output_buffer)


	def send_tn3270( self, data ):
		"""Sends tn3270 data to the server. Adding 3270E options and doubling IACs"""
		packet = ''
		if self.state == TN3270E_DATA:
			packet = "\x00\x00\x00\x00\x00"
			# we need to create the tn3270E (the E is important) header
			# which, in basic 3270E is 5 bytes of 0x00

			# Since we're only in basic mode at the moment this is just a skeleton
			# It will likely never be used.
			#packet = struct.pack(">B",self.DT_3270_DATA)       + #type
			#struct.pack(">B",0)                       + # request
			#struct.pack(">B",0)                       + # response
			#struct.pack(">S",0)
			#self.tn3270_header.seq_number
		# create send buffer and double up IACs
		for char in data:
			self.msg(1,"Adding %r to the read buffer", char)
			packet += char
		if IAC in packet:
			packet = packet.replace(IAC, IAC+IAC)
		packet += IAC + TN_EOR
		self.send_data(packet) # send the output buffer

    # ------------------ BEGIN STRUCTURED FIELDS ---------------------------------

	def w_structured_field ( self, wsf_data ):
		wsf_cmd = wsf_data[1:] #skip the wsf command
		bufflen = len(wsf_cmd)

		self.msg(1,"Processing TN3270 Write Structured Field Command")
		while bufflen > 0:
			if bufflen < 2:
				self.msg(1,"Write Structured Field too short")
			fieldlen = (struct.unpack(">B", wsf_cmd[0])[0] << 8) + struct.unpack(">B", wsf_cmd[1])[0]

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
		self.msg(1,"[WSF] Partition ID " + ''.join(hex(ord(n)) for n in data[0]))
		if data[1] == SF_RP_QUERY:
			self.msg(1,"[WSF] Read Partition Query")
			if partition != chr(0xff):
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
			if self.state == TN3270E_DATA: query_options = ("\x00" * 5) + query_options
			self.send_data(query_options)
		return

	def outbound_ds(self, data):
		""" Does something with outbound ds """
		if len(data) < 2:
			self.msg(1,"[WSF] error: field length %d too short", len(data))
			return PDS_BAD_CMD
		self.msg(1,"[WSF] Outbound DS value " + ''.join(hex(ord(n)) for n in data[0]))
		if struct.unpack(">B", data[0])[0] != 0:
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
			self.msg(1,"unknown type "+ ''.join(hex(ord(n)) for n in data[0]))

	def erase_reset(self, data):
		""" Process Structured Field Erase Reset command """
		""" To Do: Add seperate paritions"""
		if data[1] == SF_ER_DEFAULT or data[1] == SF_ER_ALT:
			self.clear_screen()
		else:
			self.msg(1,"Error with data type in erase_reset: %s", data[1])


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
			
			if name == "FT:MSG ":
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
				if received_data[0:7] == "TRANS03":
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
				for i in received_data:
					if self.ascii_file and (i == "\r" or i == chr(0x1a)):
						continue
					else:
						bytes_writen += 1
						self.file.write(i)
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
			self.output_buffer.append("") # blank size for now
			self.output_buffer.append("")
			self.output_buffer.append(SF_TRANSFER_DATA)

			while (not self.dft_eof) and (numbytes > 0):
				if self.ascii_file: #Reading an ascii file and replacing NL with LF/CR
					self.msg(1,"[WSF] File Transfer ASCII: Reading one byte from %s", self.filename)
					# Reads one byte from the file
					# replace new lines with linefeed/carriage return
					c = self.file.read(1)
					if c == "":
						self.dft_eof = True
						break
					if c == "\n":
						temp_buf.append("\r")
						temp_buf.append("\n")
					else:
						temp_buf.append(c)
					numbytes = numbytes - 1
					total_read = total_read + 1
				else:
					self.msg(1,"[WSF] File Transfer Binary: Reading one byte from %s", self.filename)
					# Reads one byte from the file
					# replace new lines with linefeed/carriage return
					c = self.file.read(1)
					if c == "":
						self.dft_eof = True
						break
					else:
						temp_buf.append(c)
					numbytes = numbytes - 1
					total_read = total_read + 1
			if(total_read > 0):
				self.msg(1,"[WSF] File Transfer: Record Number: %d | Sent %d bytes", self.recnum, total_read)
				self.output_buffer.append(self.set_16(TR_GET_REPLY))
				self.output_buffer.append(self.set_16(TR_RECNUM_HDR))
				self.output_buffer.append(self.set_32(self.recnum))
				self.recnum = self.recnum + 1
				self.output_buffer.append(self.set_16(TR_NOT_COMPRESSED))
				self.output_buffer.append(chr(TR_BEGIN_DATA))
				self.output_buffer.append(self.set_16(total_read + 5))
				self.output_buffer.extend(temp_buf)
			else:
				self.msg(1,"[WSF] File Transfer: EOF")
				self.output_buffer.append(self.HIGH8(TR_GET_REQ))
				self.output_buffer.append(chr(TR_ERROR_REPLY))
				self.output_buffer.append(self.set_16(TR_ERROR_HDR))
				self.output_buffer.append(self.set_16(TR_ERR_EOF))
				self.dft_eof = True

			# Set the length now
			o_len = 0
			for i in self.output_buffer:
				if len(i) == 0:
					o_len += 1
				else:
					o_len += len(i)
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
		byte1 = struct.unpack(">B", value[0])[0]
		byte2 = struct.unpack(">B", value[1])[0]
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

	def abort(self, code):
		self.msg(1,"File Transfer - ABORT ABORT ABORT")
		self.output_buffer = []
		self.output_buffer.insert(AID_SF)
		self.output_buffer.insert(self.set_16(9))
		self.output_buffer.insert(SF_TRANSFER_DATA)
		self.output_buffer.insert(chr(self.HIGH8(code)))
		self.output_buffer.insert(chr(TR_ERROR_REPLY))
		self.output_buffer.insert(chr(TR_ERROR_HDR))
		self.output_buffer.insert(chr(TR_ERR_CMDFAIL))
		self.send_tn3270(self.output_buffer)
		self.output_buffer = []
		self.ft_state = FT_NONE


    # The following four functions allows for the sending and receiving of files
    # using IND$FILE
    #
    # NOTE: YOU MUST BE AT THE TSO 'READY' PROMPT TO USE THESE
    #

	def send_ascii_file(self, dataset,filename):
		""" Sends an ascii file using IND$FILE
		    This will replace NL with CL/RF """

		self.msg(1,"FILE TRANSFER: Writing %s to dataset %s at %s:%d in ASCII format", filename, dataset, self.host, self.port)
		self.ft_state = FT_AWAIT_ACK
		self.ascii_file = True
		self.file = open(filename, "rb")
		self.filename = filename
		self.send_cursor("IND$FILE PUT "+dataset+" ASCII CRLF")
		while self.ft_state != FT_NONE:
			self.get_all_data()
		self.file.close()
		#reset the ascii file flag incase we do a binary transfer next
		self.ascii_file = False

	def send_binary_file(self, dataset,filename):
		""" Sends a file using IND$FILE """
		self.msg(1,"FILE TRANSFER: Writing %s to dataset %s at %s:%d", filename, dataset, self.host, self.port)
		self.ft_state = FT_AWAIT_ACK
		self.ascii_file = False
		self.file = open(filename, "rb")
		self.filename = filename
		self.send_cursor("IND$FILE PUT "+dataset)
		while self.ft_state != FT_NONE:
			self.get_all_data()
		self.file.close()

	def get_ascii_file(self, dataset, filename):
		""" Gets a dataset from the Mainframe using ASCII
		    translation (mainframe does the translation) """ 
		self.msg(1,"FILE TRANSFER: Getting dataset %s from %s:%d writing to %s as ASCII", dataset, self.host, self.port, filename)
		self.ft_state = FT_AWAIT_ACK
		self.ascii_file = True
		self.file = open(filename, 'wb') # file object
		self.filename = filename
		self.send_cursor("IND$FILE GET "+dataset+" ASCII CRLF")
		while self.ft_state != FT_NONE:
			self.get_all_data()
		self.file.close()
		#reset the ascii file flag incase we do a binary transfer next
		self.ascii_file = False


	def get_binary_file(self, dataset, filename):
		""" Gets a dataset from the mainframe without
		    any translation """
		self.msg(1,"FILE TRANSFER: Getting dataset %s from %s:%d writing to %s", dataset, self.host, self.port, filename)
		self.ft_state = FT_AWAIT_ACK
		self.ascii_file = False
		self.file = open(filename, 'wb') # file object
		self.filename = filename
		self.send_cursor("IND$FILE GET "+dataset+" ASCII CRLF")
		while self.ft_state != FT_NONE:
			self.get_all_data()
		self.file.close()

	def send_cursor( self, data ):
		output_addr = 0
		self.output_buffer = []
		self.msg(1,"Generating Output Buffer for send_cursor")
		self.output_buffer.insert(output_addr, ENTER)
		output_addr += 1
		self.msg(1,"Output Address: %r", output_addr)
		self.msg(1,"Cursor Location ("+ str(self.cursor_addr) +"): Row: %r, Column: %r ",
					self.BA_TO_ROW(self.cursor_addr),
					self.BA_TO_COL(self.cursor_addr) )
		self.output_buffer.insert(output_addr, self.ENCODE_BADDR(self.cursor_addr))
		output_addr += 1
		self.output_buffer.append(SBA)
		self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
		for lines in data:
			self.msg( 1,'Adding %r to the output buffer', lines.decode('utf-8').encode('EBCDIC-CP-BE'))
			self.output_buffer.append(lines.decode('utf-8').encode('EBCDIC-CP-BE'))
		#--self.output_buffer[output_addr]  = self:ENCODE_BADDR(self.cursor_addr + i)
		#-- for i = 1,#self.fa_buffer do
		#--   if self.fa_buffer[i] ~= "\0" then
		#--     break
		#--   end
		#--   output_addr = self:INC_BUF_ADDR(output_addr)
		#-- end
		#-- stdnse.debug(3,"At Field Attribute: Row: %s, Column %s",
		#--                 self:BA_TO_ROW(output_addr),
		#--                 self:BA_TO_COL(output_addr) )
		#--stdnse.debug(1, "sending the following: %s", stdnse.tohex(self.output_buffer))
		return self.send_tn3270(self.output_buffer)

	def send_pf( self, pf ):
		""" Sends an F1 through F24 """
	  	if ( pf > 24 ) or ( pf < 0) :
	  		self.msg(1,"PF Value must be between 1 and 24. Recieved %s", pf)
	  		return False
  	
		self.output_buffer = []
		self.msg(1,"Generating Output Buffer for send_pf: %s", "PF"+str(pf))
		self.output_buffer.append(eval("PF"+str(pf)))
		self.msg(1,"Cursor Location ("+ str(self.cursor_addr) +"): Row: %r, Column: %r ",
					self.BA_TO_ROW(self.cursor_addr),
					self.BA_TO_COL(self.cursor_addr) )
		self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))

		return self.send_tn3270(self.output_buffer)

        def send_enter( self ):
                self.output_buffer = []
                self.msg(1,"Generating Output Buffer for send_enter")
                self.output_buffer.append(ENTER)
                self.msg(1,"Cursor Location ("+ str(self.cursor_addr) +"): Row: %r, Column: %r ",
                        self.BA_TO_ROW(self.cursor_addr),
                        self.BA_TO_COL(self.cursor_addr) )
                self.output_buffer.append(self.ENCODE_BADDR(self.cursor_addr))
                return self.send_tn3270(self.output_buffer)

	def hexdump(self, src, length=8):
		""" Used to debug connection issues """
		result = []
		digits = 4 if isinstance(src, unicode) else 2
		for i in xrange(0, len(src), length):
			s = src[i:i+length]
			hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
			text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
			result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
		return b'\n'.join(result)

	def raw_screen_buffer(self):
		""" returns a list containing all the tn3270 data recieved """
		return self.raw_tn

	def writeable(self):
		""" Returns a list with all writeable fields as begining/ending tuples """
		writeable_list = []
		b_loc = 1
		for i in self.fa_buffer:
			if i != chr(0x00) and not (struct.unpack(">B", i)[0] & 0x20): 
				# find next SFA:
				j_loc = 1
				for j in self.fa_buffer[b_loc + 1:]:
					#print j
					if j != chr(0x00) and (struct.unpack(">B", j)[0] & 0x20):
						break
					j_loc += 1
				self.msg(1,"Writeable Area: %d Row: %d Col: %d Length: %d", b_loc, self.BA_TO_ROW(b_loc + 1), 
					                        self.BA_TO_COL(b_loc + 1), j_loc)
				writeable_list.append([b_loc + 1,b_loc + 1 + j_loc])
			b_loc += 1
		return writeable_list

	def is_ssl(self):
		""" returns True if the connection is SSL. False if not. """
		return self.ssl

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
