# Changelog

## 0.3.0

First public-facing release after the parser-hardening pass and the test-client
API (phases A–C). Packaging, Sphinx docs, and Read the Docs config land here.

Packaging uses setuptools 64+ with the pre-PEP-639 `license = {file = ...}`
table so `pip install .` still works on Python 3.8 (setuptools 77 dropped 3.8).

### Datastream / parser

- Buffer-address and order handling (including leftover SBA bytes after a
  complete address) no longer drops or mis-applies following orders.
- Query Reply Color (`0x86`) and Highlighting (`0x87`).
- SFE / SA / MF store per-cell foreground, highlighting, and character set.
- Numeric unprotected fields (`FA_NUMERIC`) reject letters.
- EW stays on the default 24×80 buffer; EWA switches to the model alternate
  (32×80 / 43×80 / 27×132). Optional `rows` / `cols` override.
- SBCS `codepage` (`cp037`, `cp273`, …); extra IBM codecs via `tn3270lib[i18n]`.

### Client API

- Wait helpers: `wait_for_text`, `wait_unlock`, `wait_cursor`, `wait_stable`.
  Timeouts raise `TN3270Timeout` with screen, cursor, lock, last AID, and raw
  records attached (optional `on_timeout` dump).
- Field helpers: `fields()`, `field(label)`, `fill`, `type`, `tab`.
- `save_screen` / `save_screen_txt` / `save_screen_html`.
- AID sends lock the keyboard and raise `TN3270KeyboardLocked` while locked.
- TLS: `require_tls`, `allow_plaintext`, `ssl_context`, `certfile` / `keyfile`.
  Default remains AT-TLS-friendly (`CERT_NONE`, old ciphers).
- TN3270E: BIND image parse (`bind` / `bind_image`), UNBIND, SYSREQ,
  SSCP-LU (`get_sscp`), NVT line buffer (`get_nvt`), 16-bit outbound seq
  (IAC-doubled), Set Reply Mode (field / extended-field / character).
- `reconnect()` disconnects, resets 3270E/bind/buffers, and initiates again.

## 0.2.0

Internal snapshot: setuptools `pyproject.toml`, IBM-3278-2 client, IND$FILE
helpers, TLS-first connect with optional plaintext fallback.
