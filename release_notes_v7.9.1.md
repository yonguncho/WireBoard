Fix — HAR upload robustness.

**Fixed**
- HAR files with a UTF-8 BOM (added by some tools/proxies/editors) were rejected as
  "unsupported format". Now decoded with utf-8-sig and accepted.
- A single malformed entry no longer fails the whole HAR. Browser HAR exports often
  include aborted requests / WebSocket / entries without a request URL — these are now
  skipped with a warning while the valid entries parse normally.
- Non-list `entries`, non-dict entries, bad time/timings, and out-of-range URL ports
  are handled defensively instead of raising.

**Integrity**
- WireBoard.exe SHA-256: `d61a0b71e4174d342e2c32fdaf560f5f7c372396f7d1fe3f0c488a8f35339dd5`
- 870 tests passed.
