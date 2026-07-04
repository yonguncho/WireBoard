Wireshark-grade TCP analysis — Expert Info and layer-level packet detail.

**New**
- TCP Expert Info: per-packet flags from a sequence/ack/window state machine —
  retransmission, out-of-order, previous-segment-lost, duplicate ACK, zero-window,
  window-update. Colored tags in the packet table + per-flow summary + an aggregate
  Expert Info card grouped by severity (like Wireshark).
- Layer fields exposed: parser now keeps TCP window, IP TTL, IP ID, Don't-Fragment.
- IP hop badge: estimates hop count from observed TTL vs assumed initial (64/128/255).
- Per-packet delta-time column for latency triage.

**Integrity**
- WireBoard.exe SHA-256: `31f9c8b4f8d7f80cee92060c90e94e77cc03ed609c261eeaf4bb5485a5bbe078`
- 833 tests passed.

**Note**: window-scale option is not yet parsed; zero-window uses the raw advertised window.
