Protocol-detail polish — window scale and L2 vendor identification.

**New**
- TCP window scale: the SYN window-scale option is parsed per direction, so the flow
  view shows the true receive window (raw x factor) instead of the raw 16-bit value,
  and the negotiated scale (e.g. x128/x64) appears in the flow header.
- MAC OUI vendor: the flow header identifies the L2 device vendor from the MAC prefix
  (Cisco -> Dell, VMware, Fortinet, Juniper, ...) using a bundled offline OUI table,
  plus locally-administered / multicast detection.

**Integrity**
- WireBoard.exe SHA-256: `9b187fe3df77f788f6fc8f2cd41ac034a585c35b2d0c7e5060bf0dbf1b61d27b`
- 848 tests passed.
