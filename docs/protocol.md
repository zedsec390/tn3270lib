# Protocol notes

tn3270lib speaks **TN3270** and **TN3270E** (RFC 2355) as a client for
scripted logon and screen scraping. It is not a full 3270 product.

## Models and geometry

| `device_type` | Default (EW) | Alternate (EWA) |
| --- | --- | --- |
| IBM-3278-2 / `-2-E` | 24×80 | 24×80 |
| IBM-3278-3 | 24×80 | 32×80 |
| IBM-3278-4 | 24×80 | 43×80 |
| IBM-3278-5 | 24×80 | 27×132 |

Erase/Write uses the **default** 24×80 buffer. Erase/Write Alternate switches
to the model alternate. Pass `rows` and `cols` to override (model 2: both
sizes; models 3–5: alternate only).

## TN3270E

FUNCTIONS advertised to the host are **RESPONSES** and **SYSREQ**. BIND_IMAGE
is **not** advertised as a function; when the host still sends `DT_BIND_IMAGE`,
the payload is parsed (raw plus PLU/SLU/size hints on `bind` / `bind_image`).
`DT_UNBIND` clears it.

`sysreq()` / `send_aid('SYSREQ')` send a TN3270E `DT_REQUEST` and toggle
SSCP-LU when SYSREQ was negotiated; otherwise the 3270 SYSREQ AID is used.
In SSCP-LU mode, typed input + ENTER is `DT_SSCP_LU_DATA`. `get_sscp()` returns
inbound SSCP text.

`get_nvt()` is an ASCII line buffer for `DT_NVT` and pre-3270 telnet bytes —
not a full NVT terminal.

Outbound 3270-DATA headers carry an incrementing 16-bit sequence number with
IAC bytes doubled. Set Reply Mode is honored: field, extended-field (SFE on
RM/RB), and a best-effort character (SA) mode.

## TLS versus AT-TLS

z/OS AT-TLS often presents old ciphers and a host certificate that is not in
a public CA store. The default client context uses `CERT_NONE` and a legacy
cipher list, then tries TLS first.

- `verify=True` is **not** the AT-TLS path (it expects a valid chain).
- `require_tls=True` never falls back to plaintext.
- `allow_plaintext=True` restores fallback after handshake failure.
- `disable_ssl(True)` skips TLS on the next connect.

**STARTTLS** (RFC 2941 / 4279-style upgrade after a cleartext banner) is out
of scope. Wrap the port with AT-TLS or a TLS terminator instead.

## Out of scope

- SCS / 3287 printer sessions
- DBCS / double-byte code pages
- Extra partitions
- STARTTLS
- A complete NVT or 3287 emulator
