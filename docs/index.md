# tn3270lib

Python **TN3270/TN3270E** client for **test automation** against IBM 3270 sessions
(z/OS TSO, CICS, VTAM logon screens). Default geometry is IBM-3278-2 (24×80);
models 3/4/5 are selected with `device_type`. This is not an x3270 clone.

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

Always `wait_unlock()` (or wait until the host restores the keyboard) before
`send_enter()` / `send_pf()` — AID sends raise `TN3270KeyboardLocked` while
locked and lock again after a successful AID.

```{toctree}
:maxdepth: 2
:caption: Contents

installation
quickstart
api
protocol
changelog
```
