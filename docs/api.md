# API reference

The public class is {class}`tn3270.TN3270`, also exported as
`tn3270lib.TN3270` so existing `import tn3270lib` callers keep working.

Constructor flags of note: `device_type`, `codepage`, `rows` / `cols`,
`verify`, `ssl_context`, `require_tls`, `allow_plaintext`, `certfile`,
`keyfile`.

```{eval-rst}
.. autoclass:: tn3270.TN3270
   :members: initiate, reconnect, wait_for_text, wait_unlock, wait_cursor, wait_stable, fields, field, fill, type, tab, newline, send_enter, send_pf, send_aid, send_clear, send_cursor, send_location, send_locations, sysreq, get_screen, get_screen_html, save_screen, save_screen_txt, save_screen_html, get_sscp, get_nvt, get_lu, set_lu, disconnect, connect, check_tn3270, disable_ssl, disable_enhanced, find, writeable, print_screen, send_ascii_file, send_binary_file, get_ascii_file, get_binary_file
   :inherited-members:
   :show-inheritance:

.. autoexception:: tn3270.TN3270Timeout
   :members:
   :undoc-members:

.. autoexception:: tn3270.TN3270KeyboardLocked

.. autoclass:: tn3270.Field
   :members:

.. autodata:: tn3270.DEVICE_TYPE
.. autodata:: tn3270.ROWS
.. autodata:: tn3270.COLS
.. autodata:: tn3270.SCREEN_SIZE
```
