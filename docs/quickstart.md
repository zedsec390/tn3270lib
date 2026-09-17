# Quickstart

`import tn3270lib` still constructs a `TN3270()` the same way as `tn3270.TN3270`.

```python
import tn3270lib

tn = tn3270lib.TN3270(
    device_type="IBM-3278-2-E",
    codepage="cp037",
    timeout=10,
)
if not tn.initiate("host.example.com", 23):
    raise SystemExit("connect/negotiate failed")

tn.wait_for_text("LOGON", timeout=10)
tn.fill("Userid", "IBMUSER")
tn.wait_unlock()
tn.send_enter()
print(tn.get_screen())
tn.disconnect()
```

## Waits and the keyboard

| Helper | Until |
| --- | --- |
| `wait_for_text(s)` | decoded screen contains `s` |
| `wait_unlock()` | keyboard is not locked |
| `wait_cursor(row, col)` | cursor at 1-based row/col (or `addr=`) |
| `wait_stable(quiet=0.3)` | no new 3270 records for `quiet` seconds |

Expired waits raise `TN3270Timeout` with `screen`, `cursor`, `keyboard_locked`,
`aid`, and `raw` records. Optional `tn.on_timeout` can dump the screen.

`send_enter`, `send_pf`, and `send_aid` raise `TN3270KeyboardLocked` if the
keyboard is locked. Call `wait_unlock()` first.

## Fields

```python
for f in tn.fields():
    print(f.label, f.row, f.col, f.value)
tn.fill("Password", "secret")
tn.type("IBMUSER", field="Userid")
tn.tab()
```

`field(label)` matches a case-insensitive substring of the preceding protected
text. Numeric unprotected fields (`FA_NUMERIC`) reject letters.

## Screen dumps

```python
tn.save_screen("screen.txt")
tn.save_screen_html("screen.html")
```

HTML keeps protected vs unprotected and color/highlight spans.

## TLS

Default is **AT-TLS friendly**: try TLS with `CERT_NONE` and old ciphers.
`verify=True` is **not** that path. Use `ssl_context=` or `certfile=` /
`keyfile=` for mTLS. `require_tls=True` refuses plaintext;
`allow_plaintext=True` restores fallback after a failed handshake.

```python
tn = tn3270lib.TN3270(require_tls=True, certfile="client.pem", keyfile="client.key")
tn.disable_ssl(True)   # skip TLS on the next connect
```

## TN3270E extras

```python
tn.sysreq()                 # REQUEST when SYSREQ negotiated, else 3270 AID
print(tn.get_sscp())        # inbound SSCP-LU text
print(tn.get_nvt())         # ASCII NVT line buffer (not a full NVT terminal)
tn.reconnect()              # disconnect, reset, initiate again
```

In SSCP-LU mode, `type` + `send_enter` send `DT_SSCP_LU_DATA`, not Read Modified.
