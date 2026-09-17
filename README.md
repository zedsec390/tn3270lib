# tn3270lib

Python TN3270/TN3270E client for **test automation** (IBM-3278 models 2–5).
Not an x3270 clone.

Documentation (intended Read the Docs project):
[https://tn3270lib.readthedocs.io](https://tn3270lib.readthedocs.io)

```python
import tn3270lib
tn = tn3270lib.TN3270(device_type="IBM-3278-3", codepage="cp037")
tn.initiate("host", 23)
tn.wait_for_text("LOGON", timeout=10)
tn.fill("Userid", "IBMUSER")
tn.wait_unlock()
tn.send_enter()
tn.save_screen_html("screen.html")
print(tn.get_screen())
tn.disconnect()
```

Wait helpers: `wait_for_text`, `wait_unlock`, `wait_cursor`, `wait_stable` raise `TN3270Timeout` (screen, cursor, lock, last AID, raw records attached). Field helpers: `fields()`, `field(label)` (case-insensitive substring of the preceding protected text), `fill`, `type`, `tab`. Numeric unprotected fields (`FA_NUMERIC`) reject letters. `codepage="cp273"` etc.; extra IBM codecs: `pip install tn3270lib[i18n]`. EW uses the default 24×80 buffer; EWA switches to the model alternate (32×80 / 43×80 / 27×132). SFE/SA store per-cell color and highlighting; `save_screen` / `save_screen_txt` / `save_screen_html` dump the screen (HTML keeps protected vs unprotected and color spans). `send_enter` / `send_pf` / `send_aid` raise `TN3270KeyboardLocked` while locked and lock again after a successful AID.

TN3270E: `BIND_IMAGE` is parsed (raw + PLU/SLU/size hints on `bind` / `bind_image`); UNBIND clears it. FUNCTIONS advertised are RESPONSES and SYSREQ (not BIND_IMAGE-as-function, not SCS). `sysreq()` / `send_aid('SYSREQ')` send a TN3270E REQUEST and toggle SSCP-LU when SYSREQ was negotiated; otherwise the 3270 SYSREQ AID is used. In SSCP-LU mode, `type` + `send_enter` send `DT_SSCP_LU_DATA` (not Read Modified); `get_sscp()` returns inbound SSCP text. `get_nvt()` is an ASCII line buffer for `DT_NVT` and pre-3270 telnet bytes — not a full NVT terminal. Outbound 3270-DATA headers carry an incrementing 16-bit seq (IAC-doubled). Set Reply Mode is honored: field, extended-field (SFE on RM/RB), character (best-effort SA). `reconnect()` disconnects, resets 3270E/bind/buffers, and `initiate`s again.

TLS defaults to CERT_NONE plus old ciphers for z/OS AT-TLS; `verify=True` is **not** the AT-TLS path. Use `ssl_context=` or `certfile=` / `keyfile=` for mTLS. `require_tls=True` refuses plaintext; `allow_plaintext=True` restores fallback. STARTTLS, SCS/3287 printer sessions, extra partitions, and DBCS are out of scope. Licensed GPL-3.0-or-later.

## Install

From a checkout (the package is not assumed to be on PyPI yet):

```bash
pip install .
pip install '.[i18n]'   # extra IBM SBCS codecs
pip install '.[docs]'   # Sphinx / Read the Docs
```

When published:

```bash
pip install tn3270lib
pip install tn3270lib[i18n]
```

Build artifacts locally (no upload):

```bash
python3 -m pip install build twine
python3 -m build
python3 -m twine check dist/*
```

See [CHANGELOG.md](CHANGELOG.md) for 0.3.0 (parser fixes and phases A–C).
