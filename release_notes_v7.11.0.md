Customer-ready reports + headless CLI (automation).

**Richer PDF report**
- The Executive Summary now includes a DIAGNOSTICS section: network-vs-application
  verdict, connection health score, TCP Expert Info counts (retransmit / dup-ack /
  zero-window / lost), DNS response p50/p95 and error/no-response counts, detected
  application protocols (QUIC/HTTP2), and capture-quality caveats.

**Headless CLI (automation / SOC pipelines)**
- `WireBoard.exe analyze <capture> [--json out.json] [--pdf out.pdf] [--target IP]`
  Parses (including streaming for large pcap), runs detection + diagnosis, and emits
  JSON and/or a PDF report — no server or browser. `--version` / `--help` supported.

**Integrity**
- WireBoard.exe SHA-256: `0c397c88dfa8b1fef762704f3e059dd18621e9f50b47e2ef8970090ee247ee09`
- 897 tests passed. Packaged-EXE CLI verified end-to-end.
