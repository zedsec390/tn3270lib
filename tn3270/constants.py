"""Telnet, TN3270E and 3270 data stream constants.

Option numbers follow RFC 854 (telnet), RFC 1091 (TTYPE) and
RFC 2355, in which telnet option 40 is TN3270E."""

import logging


# Tunable parameters
DEBUGLEVEL = 0
LOGGER = logging.getLogger("tn3270")
SCREEN_SIZE = 1920  # IBM-3278-2 / 24x80, 0-based

# Telnet protocol commands (single-byte values; compare as ints)
SE   = 240 #End of subnegotiation parameters
SB   = 250 #Sub-option to follow
WILL = 251 #Will; request or confirm option begin
WONT = 252 #Wont; deny option request
DO   = 253 #Do = Request or confirm remote option
DONT = 254 #Don't = Demand or confirm option halt
IAC  = 255 #Interpret as Command
SEND = 0o1 #Sub-process negotiation SEND command
IS   = 0o0 #Sub-process negotiation IS command


#TN3270 Telnet Commands
TN_ASSOCIATE  = 0
TN_CONNECT    = 1
TN_DEVICETYPE = 2
TN_FUNCTIONS  = 3
TN_IS         = 4
TN_REASON     = 5
TN_REJECT     = 6
TN_REQUEST    = 7
TN_SEND       = 8
TN_TN3270     = 40
TN_EOR        = 239 #End of Record

# RFC 854 verbs that are not WILL/WONT/DO/DONT/SB/EOR. IAC + these
# is ignored and the state machine returns to data (do not leave TNS_IAC).
TELNET_NOP = 241
TELNET_DM  = 242
TELNET_BRK = 243
TELNET_IP  = 244
TELNET_AO  = 245
TELNET_AYT = 246
TELNET_EC  = 247
TELNET_EL  = 248
TELNET_GA  = 249

# Supported Telnet Options (IANA / RFC 2355: option 40 is TN3270E).
# options['TN3270'] is kept as an alias for 40 so existing wire lookups still
# send TN3270E. Option 28 is not TN3270E (it is TELNET LOCATION-NUMBER).
options = {
        'BINARY'  : 0,
        'EOR'     : 25,
        'TTYPE'   : 24,
        'TN3270E' : 40,
}
options['TN3270'] = options['TN3270E']

supported_options = {
        0  : 'BINARY',
        25 : 'EOR',
        24 : 'TTYPE',
        40 : 'TN3270E',
}

#TN3270 Stream Commands: TCPIP
EAU   = 15
EW    = 5
EWA   = 13
RB    = 2
RM    = 6
RMA   = 0x6E  # Read Modified All (same numeric value as SNA_RMA)
W     = 1
WSF   = 17
NOP   = 3
SNS   = 4
SNSID = 228
#TN3270 Stream Commands: SNA
SNA_RMA   = 110
SNA_EAU   = 111
SNA_EWA   = 126
SNA_W     = 241
SNA_RB    = 242
SNA_WSF   = 243
SNA_EW    = 245
SNA_NOP   = 0o3
SNA_RM    = 246


#TN3270 Stream Orders
SF  = 29
SFE = 41
SBA = 17
SA  = 40
MF  = 44
IC  = 19
PT  = 5
RA  = 60
EUA = 18
GE  = 8


#TN3270 Format Control Orders
NUL = 0
SUB = 63
DUP = 28
FM  = 30
FF  = 12
CR  = 13
NL  = 21
EM  = 25
EO  = 255

#TN3270 Attention Identification (AIDS)
#####
# SoF ## Left this as hex because i coulnd't
#        be bothered to convert to decimal
#####
NO      = 0x60 #no aid
QREPLY  = 0x61 #reply
ENTER   = 0x7d #enter
PF1     = 0xf1
PF2     = 0xf2
PF3     = 0xf3
PF4     = 0xf4
PF5     = 0xf5
PF6     = 0xf6
PF7     = 0xf7
PF8     = 0xf8
PF9     = 0xf9
PF10    = 0x7a
PF11    = 0x7b
PF12    = 0x7c
PF13    = 0xc1
PF14    = 0xc2
PF15    = 0xc3
PF16    = 0xc4
PF17    = 0xc5
PF18    = 0xc6
PF19    = 0xc7
PF20    = 0xc8
PF21    = 0xc9
PF22    = 0x4a
PF23    = 0x4b
PF24    = 0x4c
OICR    = 0xe6
MSR_MHS = 0xe7
SELECT  = 0x7e
PA1     = 0x6c
PA2     = 0x6e
PA3     = 0x6b
CLEAR   = 0x6d
SYSREQ  = 0xf0

AIDS = {
    'NO': NO,
    'QREPLY': QREPLY,
    'ENTER': ENTER,
    'PF1': PF1,
    'PF2': PF2,
    'PF3': PF3,
    'PF4': PF4,
    'PF5': PF5,
    'PF6': PF6,
    'PF7': PF7,
    'PF8': PF8,
    'PF9': PF9,
    'PF10': PF10,
    'PF11': PF11,
    'PF12': PF12,
    'PF13': PF13,
    'PF14': PF14,
    'PF15': PF15,
    'PF16': PF16,
    'PF17': PF17,
    'PF18': PF18,
    'PF19': PF19,
    'PF20': PF20,
    'PF21': PF21,
    'PF22': PF22,
    'PF23': PF23,
    'PF24': PF24,
    'OICR': OICR,
    'MSR_MHS': MSR_MHS,
    'SELECT': SELECT,
    'PA1': PA1,
    'PA2': PA2,
    'PA3': PA3,
    'CLEAR': CLEAR,
    'SYSREQ': SYSREQ,
}

# used for Structured Fields
AID_SF      = 0x88
SFID_QREPLY     = 0x81

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
# x3270 structured-field reject; same value as BAD_COMMAND
PDS_BAD_CMD    = BAD_COMMAND
NO_AID         = 0x60
FA_MDT         = 0x01  # field modified-data tag
FA_NUMERIC     = 0x10  # numeric-only unprotected field
FA_PROTECTED   = 0x20
WCC_RESET      = 0x40
WCC_RESTORE    = 0x02  # keyboard restore
WCC_RESET_MDT  = 0x01

# Extended attributes: SA uses 0x41/0x42/0x43; SFE/MF use 0xC0/0xC1/0xC2/0xC3.
XA_RESET       = 0x00
XA_HIGHLIGHT   = 0x41
XA_FGCOLOR     = 0x42
XA_CHARSET     = 0x43
SFE_FA         = 0xC0
SFE_HIGHLIGHT  = 0xC1
SFE_COLOR      = 0xC2
SFE_CHARSET    = 0xC3

# 3270 color values (Query Reply / SA / SFE).
COLOR_DEFAULT    = 0x00
COLOR_NEUTRAL    = 0xF0
COLOR_BLUE       = 0xF1
COLOR_RED        = 0xF2
COLOR_PINK       = 0xF3
COLOR_GREEN      = 0xF4
COLOR_TURQUOISE  = 0xF5
COLOR_YELLOW     = 0xF6
COLOR_WHITE      = 0xF7

COLOR_NAMES = {
        COLOR_DEFAULT: 'default',
        COLOR_NEUTRAL: 'neutral',
        COLOR_BLUE: 'blue',
        COLOR_RED: 'red',
        COLOR_PINK: 'pink',
        COLOR_GREEN: 'green',
        COLOR_TURQUOISE: 'turquoise',
        COLOR_YELLOW: 'yellow',
        COLOR_WHITE: 'white',
}

# Extended highlighting.
HL_DEFAULT     = 0x00
HL_NORMAL      = 0xF0
HL_BLINK       = 0xF1
HL_REVERSE     = 0xF2
HL_UNDERSCORE  = 0xF4

HL_NAMES = {
        HL_DEFAULT: 'default',
        HL_NORMAL: 'default',
        HL_BLINK: 'blink',
        HL_REVERSE: 'reverse',
        HL_UNDERSCORE: 'underscore',
}



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
SF_READ_PART      = 0x01   # read partition
SF_RP_QUERY       = 0x02   #query
SF_RP_QLIST       = 0x03   #query list
SF_RPQ_LIST       = 0x00   # QCODE list
SF_RPQ_EQUIV      = 0x40   # equivalent+ QCODE list
SF_RPQ_ALL        = 0x80   # all
SF_ERASE_RESET    = 0x03   # erase/reset
SF_ER_DEFAULT     = 0x00   #default
SF_ER_ALT         = 0x80   #alternate
SF_SET_REPLY_MODE = 0x09   # set reply mode
SF_SRM_FIELD      = 0x00   #field
SF_SRM_XFIELD     = 0x01   #extended field
SF_SRM_CHAR       = 0x02   #character
SF_CREATE_PART    = 0x0c   #create partition
CPFLAG_PROT       = 0x40   #protected flag
CPFLAG_COPY_PS    = 0x20   #local copy to presentation space
CPFLAG_BASE       = 0x07   #base character set index
SF_OUTBOUND_DS    = 0x40   #outbound 3270 DS
SF_TRANSFER_DATA  = 0xd0   #file transfer open request

#Data Transfer
# Host requests.
TR_OPEN_REQ                     = 0x0012        #open request
TR_CLOSE_REQ            = 0x4112                #close request
TR_SET_CUR_REQ          = 0x4511        #set cursor request
TR_GET_REQ                      = 0x4611        #get request
TR_INSERT_REQ           = 0x4711        #insert request
TR_DATA_INSERT          = 0x4704        #data to insert

# PC replies.
TR_GET_REPLY            = 0x4605        #data for get
TR_NORMAL_REPLY         = 0x4705        #insert normal reply
TR_ERROR_REPLY          = 0x08  #error reply (low 8 bits)
TR_CLOSE_REPLY          = 0x4109        #close acknowledgement

# Other headers.
TR_RECNUM_HDR           = 0x6306        #record number header
TR_ERROR_HDR            = 0x6904        #error header
TR_NOT_COMPRESSED       = 0xc080        #data not compressed
TR_BEGIN_DATA           = 0x61  #beginning of data

# Error codes.
TR_ERR_EOF                      = 0x2200        #get past end of file
TR_ERR_CMDFAIL          = 0x0100        #command failed

DFT_BUF             = 4096  # Default buffer size
DFT_MIN_BUF         = 256   # Minimum file send buffer size
DFT_MAX_BUF             = 32768 # Max buffer size

# File Transfer Constants
FT_NONE       = 1   # No transfer in progress
FT_AWAIT_ACK  = 2   # IND$FILE sent, awaiting acknowledgement message



#TN3270E Negotiation Options

TN3270E_ASSOCIATE       = 0x00
TN3270E_CONNECT         = 0x01
TN3270E_DEVICE_TYPE     = 0x02
TN3270E_FUNCTIONS   = 0x03
TN3270E_IS                      = 0x04
TN3270E_REASON          = 0x05
TN3270E_REJECT          = 0x06
TN3270E_REQUEST         = 0x07
TN3270E_SEND            = 0x08

#Global Vars
NEGOTIATING    = 0
CONNECTED      = 1
TN3270_DATA    = 2
TN3270E_DATA   = 3
# IBM-3278-2-E is honest for this 24x80 emulator (model 2). A constructor
# argument can override the telnet TTYPE / TN3270E device-type string.
DEVICE_TYPE    = "IBM-3278-2-E"
COLS           = 80 # default width (IBM-3278-2).
ROWS           = 24 # default rows (IBM-3278-2).
# Primary (default) and alternate sizes by 3270 model. Model 2 is 24x80
# only; models 3/4/5 keep 24x80 primary and a larger alternate.
DEVICE_MODEL_GEOMETRY = {
        '2': ((24, 80), (24, 80)),
        '3': ((24, 80), (32, 80)),
        '4': ((24, 80), (43, 80)),
        '5': ((24, 80), (27, 132)),
}

# Query Reply QCODEs we actually send.
QR_SUMMARY            = 0x80
QR_USABLE_AREA        = 0x81
QR_CHARACTER_SETS     = 0x85
QR_COLOR              = 0x86
QR_HIGHLIGHTING       = 0x87
QR_REPLY_MODES        = 0x88
QR_IMPLICIT_PARTITION = 0xA6
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

# TN3270E function codes (RFC 2355). These are NOT telnet option numbers;
# putting RESPONSES=2 in telnet_options overwrote DEVICE_TYPE in debug prints.
TN3270E_FN_BIND_IMAGE      = 0
TN3270E_FN_DATA_STREAM_CTL = 1
TN3270E_FN_RESPONSES       = 2
TN3270E_FN_SCS_CTL_CODES   = 3
TN3270E_FN_SYSREQ          = 4
# SYSREQ as a 3270 AID (0xf0) remains available; the TN3270E *function*
# is also advertised so z/VM and consoles can switch to SSCP-LU.
TN3270E_SUPPORTED_FUNCTIONS = frozenset({
        TN3270E_FN_RESPONSES,
        TN3270E_FN_SYSREQ,
})
# Back-compat alias; do not add this to telnet_options (collides with DEVICE_TYPE).
TN_RESPONSES = TN3270E_FN_RESPONSES

telnet_options = {
        TN_ASSOCIATE  : 'ASSOCIATE',
        TN_CONNECT    : 'CONNECT',
        TN_DEVICETYPE : 'DEVICE_TYPE',
        TN_FUNCTIONS  : 'FUNCTIONS',
        TN_IS         : 'IS',
        TN_REASON     : 'REASON',
        TN_REJECT     : 'REJECT',
        TN_REQUEST    : 'REQUEST',
        TN_SEND       : 'SEND',
        TN_TN3270     : 'TN3270',
        TN_EOR        : 'EOR'
}

tn3270_options = {
        TN3270E_ASSOCIATE       :'TN3270E_ASSOCIATE',
        TN3270E_CONNECT         :'TN3270E_CONNECT',
        TN3270E_DEVICE_TYPE :'TN3270E_DEVICE_TYPE',
        TN3270E_FUNCTIONS       :'TN3270E_FUNCTIONS',
        TN3270E_IS                      :'TN3270E_IS',
        TN3270E_REASON          :'TN3270E_REASON',
        TN3270E_REJECT          :'TN3270E_REJECT',
        TN3270E_REQUEST         :'TN3270E_REQUEST',
        TN3270E_SEND            :'TN3270E_SEND'
}
