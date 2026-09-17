"""EBCDIC <-> str translation using a session SBCS codec.

Stdlib provides cp037, cp273, cp500, cp1140, and similar. Unusual IBM
code pages can be registered by the optional ``ebcdic`` package
(``pip install tn3270lib[i18n]``). DBCS (CP930/939, SO/SI) is not supported.
"""

import codecs
import re

_I18N_HINT = (
    "Unknown EBCDIC code page %r. Install extra codecs with: "
    "pip install tn3270lib[i18n]"
)

# GCSGID 697 is the Latin character set used with most SBCS code pages.
# Euro pages (1140+) commonly use GCSGID 695.
_GCSGID_EURO = 695
_GCSGID_LATIN = 697


def normalize_codepage(name):
    """Return a codecs name like 'cp037' from 'cp037', '037', or 'IBM037'."""
    if not name:
        return 'cp037'
    s = str(name).strip().lower().replace('_', '').replace('-', '')
    if s.startswith('ibm'):
        s = s[3:]
    if s.startswith('cp'):
        s = s[2:]
    if not s.isdigit():
        # already a codec name such as 'cp037'
        raw = str(name).strip().lower()
        if not raw.startswith('cp'):
            raw = 'cp' + s if s.isdigit() else raw
        return raw
    return 'cp' + s


def cpgid_of(codepage):
    """Numeric CPGID (37, 273, 1140, ...) from a codec name."""
    m = re.search(r'(\d+)$', normalize_codepage(codepage))
    return int(m.group(1)) if m else 37


def cgcsgid_of(codepage):
    """(GCSGID, CPGID) pair advertised in Query Reply Character Sets."""
    cpgid = cpgid_of(codepage)
    gcsgid = _GCSGID_EURO if cpgid >= 1140 else _GCSGID_LATIN
    return gcsgid, cpgid


def resolve_codec(codepage):
    """Look up an SBCS codec, loading the optional ebcdic package if needed."""
    name = normalize_codepage(codepage)
    try:
        return codecs.lookup(name).name
    except LookupError:
        pass
    try:
        import ebcdic  # noqa: F401  — registers cp* codecs
    except ImportError:
        raise LookupError(_I18N_HINT % (codepage,)) from None
    try:
        return codecs.lookup(name).name
    except LookupError:
        raise LookupError(_I18N_HINT % (codepage,)) from None


def ebcdic_to_str(data, codepage='cp037'):
    if isinstance(data, int):
        data = bytes((data,))
    codec = resolve_codec(codepage)
    return codecs.decode(bytes(data), codec, errors='replace')


def str_to_ebcdic(text, codepage='cp037'):
    if isinstance(text, (bytes, bytearray)):
        return bytes(text)
    codec = resolve_codec(codepage)
    return codecs.encode(text, codec)


# Back-compat aliases used by tn3270lib.py and older call sites (always CP037).
def _ebcdic_to_str(data):
    return ebcdic_to_str(data, 'cp037')


def _str_to_ebcdic(text):
    return str_to_ebcdic(text, 'cp037')
