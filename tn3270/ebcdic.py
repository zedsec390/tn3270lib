"""EBCDIC <-> str translation (code page 037)."""

import codecs


def _ebcdic_to_str(data):
    if isinstance(data, int):
        data = bytes((data,))
    return codecs.decode(bytes(data), 'cp037', errors='replace')

def _str_to_ebcdic(text):
    if isinstance(text, (bytes, bytearray)):
        return bytes(text)
    return codecs.encode(text, 'cp037')
