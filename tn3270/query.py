"""Build Read Partition Query Reply structured fields.

Advertises Summary, Usable Area, Color, Highlighting, Character Sets,
Reply Modes (field / extended-field / character), and Implicit Partition.
"""

import struct

from .constants import (
    AID_SF, SFID_QREPLY,
    QR_SUMMARY, QR_USABLE_AREA, QR_CHARACTER_SETS,
    QR_COLOR, QR_HIGHLIGHTING, QR_REPLY_MODES, QR_IMPLICIT_PARTITION,
    COLOR_BLUE, COLOR_RED, COLOR_PINK,
    COLOR_GREEN, COLOR_TURQUOISE, COLOR_YELLOW, COLOR_WHITE,
    HL_NORMAL, HL_BLINK, HL_REVERSE, HL_UNDERSCORE,
)
from .ebcdic import cgcsgid_of


def _sf(body):
    """Two-byte length (including the length bytes) plus body."""
    n = 2 + len(body)
    return struct.pack('>H', n) + body


def _qr(qcode, data=b''):
    return _sf(bytes((SFID_QREPLY, qcode)) + data)


def _u16(n):
    return struct.pack('>H', n)


def qr_summary(qcodes):
    return _qr(QR_SUMMARY, bytes(qcodes))


def qr_usable_area(rows, cols):
    """Usable Area for the advertised (usually alternate / maximum) size.

    Layout follows the z/OS-accepted 3278-2 reply: 14-bit addressing,
    character cells, then a 12x7 cell measurement trailer.
    """
    data = (
        bytes((0x01, 0x00))  # 12/14-bit addressing, cells
        + _u16(cols) + _u16(rows)
        + bytes((0x01, 0x00, 0x0a, 0x02, 0xe5, 0x00, 0x02, 0x00,
                 0x6f, 0x09, 0x0c, 0x07))
    )
    return _qr(QR_USABLE_AREA, data)


def qr_color():
    """Eight standard 3270 colors; default maps to green (x3270-like)."""
    pairs = (
        (0x00, COLOR_GREEN),
        (COLOR_BLUE, COLOR_BLUE),
        (COLOR_RED, COLOR_RED),
        (COLOR_PINK, COLOR_PINK),
        (COLOR_GREEN, COLOR_GREEN),
        (COLOR_TURQUOISE, COLOR_TURQUOISE),
        (COLOR_YELLOW, COLOR_YELLOW),
        (COLOR_WHITE, COLOR_WHITE),
    )
    data = bytearray((0x00, len(pairs)))
    for ident, val in pairs:
        data.append(ident)
        data.append(val)
    return _qr(QR_COLOR, bytes(data))


def qr_highlighting():
    """Default, blink, reverse, underscore."""
    pairs = (
        (0x00, HL_NORMAL),
        (HL_BLINK, HL_BLINK),
        (HL_REVERSE, HL_REVERSE),
        (HL_UNDERSCORE, HL_UNDERSCORE),
    )
    data = bytearray((len(pairs),))
    for ident, val in pairs:
        data.append(ident)
        data.append(val)
    return _qr(QR_HIGHLIGHTING, bytes(data))


def qr_character_sets(codepage):
    """One SBCS character set with CGCSGID matching the session code page."""
    gcsgid, cpgid = cgcsgid_of(codepage)
    data = (
        bytes((0x82, 0x00, 0x09, 0x0c, 0x00, 0x00, 0x00, 0x00,
               0x07, 0x00, 0x10, 0x00))
        + _u16(gcsgid) + _u16(cpgid)
    )
    return _qr(QR_CHARACTER_SETS, data)


def qr_reply_modes():
    """Field, extended-field, and character reply modes."""
    return _qr(QR_REPLY_MODES, bytes((0x00, 0x01, 0x02)))


def qr_implicit_partition(def_rows, def_cols, alt_rows, alt_cols):
    """Default and alternate implicit-partition sizes."""
    sdp = (
        bytes((0x0b, 0x01, 0x00))
        + _u16(def_cols) + _u16(def_rows)
        + _u16(alt_cols) + _u16(alt_rows)
    )
    return _qr(QR_IMPLICIT_PARTITION, bytes((0x00, 0x00)) + sdp)


def build_query_reply(def_rows, def_cols, alt_rows, alt_cols, codepage='cp037'):
    """AID 0x88 followed by length-prefixed Query Reply structured fields."""
    qcodes = (
        QR_SUMMARY,
        QR_USABLE_AREA,
        QR_COLOR,
        QR_HIGHLIGHTING,
        QR_CHARACTER_SETS,
        QR_REPLY_MODES,
        QR_IMPLICIT_PARTITION,
    )
    parts = [
        qr_summary(qcodes),
        qr_usable_area(alt_rows, alt_cols),
        qr_color(),
        qr_highlighting(),
        qr_character_sets(codepage),
        qr_reply_modes(),
        qr_implicit_partition(def_rows, def_cols, alt_rows, alt_cols),
    ]
    return bytes((AID_SF,)) + b''.join(parts)


def parse_query_reply(payload):
    """Yield (qcode, data) for each SF after AID 0x88. Raises on leftover."""
    if not payload or payload[0] != AID_SF:
        raise ValueError('Query Reply must start with AID 0x88')
    i = 1
    fields = []
    while i < len(payload):
        if i + 2 > len(payload):
            raise ValueError('truncated structured-field length')
        flen = (payload[i] << 8) | payload[i + 1]
        if flen < 3 or i + flen > len(payload):
            raise ValueError('bad structured-field length %r at %d' % (flen, i))
        body = payload[i + 2:i + flen]
        if body[0] != SFID_QREPLY:
            raise ValueError('expected SFID 0x81, got 0x%02x' % body[0])
        fields.append((body[1], body[2:]))
        i += flen
    if i != len(payload):
        raise ValueError('leftover bytes after Query Reply')
    return fields
