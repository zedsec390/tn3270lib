"""Best-effort SNA BIND RU parsing for TN3270E BIND_IMAGE.

Short or odd images are kept opaque; parsed fields are hints only.
"""

from .ebcdic import ebcdic_to_str

# IBM SNA Formats: BIND command, then PLU name length at offset 26.
BIND_CMD = 0x31
BIND_OFF_PLU_NAME_LEN = 26
BIND_NAME_MAX = 8


def _ebcdic_name(data):
    try:
        text = ebcdic_to_str(data, 'cp037')
    except Exception:
        text = bytes(data).decode('latin1', 'replace')
    return ''.join(c for c in text if c.isprintable()).strip()


def parse_bind_image(data):
    """Return a dict: raw, plu, slu, rows, cols, logmode.

    Never raises on truncated input.
    """
    raw = bytes(data or b'')
    out = {
        'raw': raw,
        'plu': '',
        'slu': '',
        'rows': None,
        'cols': None,
        'logmode': '',
    }
    if not raw:
        return out
    b = raw
    if b[0] != BIND_CMD and len(b) > BIND_OFF_PLU_NAME_LEN + 1:
        # Some hosts omit the 0x31 command byte.
        pass

    if len(b) > BIND_OFF_PLU_NAME_LEN:
        n = b[BIND_OFF_PLU_NAME_LEN]
        pos = BIND_OFF_PLU_NAME_LEN + 1
        if 1 <= n <= BIND_NAME_MAX and pos + n <= len(b):
            out['plu'] = _ebcdic_name(b[pos:pos + n])
            pos += n
            if pos < len(b):
                n2 = b[pos]
                pos += 1
                if 1 <= n2 <= BIND_NAME_MAX and pos + n2 <= len(b):
                    out['slu'] = _ebcdic_name(b[pos:pos + n2])

    # Presentation-space hints sometimes sit at offsets 20-23.
    if len(b) > 23:
        r1, c1, r2, c2 = b[20], b[21], b[22], b[23]
        for rows, cols in ((r1, c1), (r2, c2)):
            if 12 <= rows <= 93 and 40 <= cols <= 160:
                out['rows'] = rows
                out['cols'] = cols
                break
    return out
