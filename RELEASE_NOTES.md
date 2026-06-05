## WireBoard v5.0.0

Zero external-dependency network capture analysis tool.

### What's New
- Pure-Python parser (struct only) — removed dpkt/scapy
- FortiGate verbose 3 + 6 text parser
- HAR (HTTP Archive) parser
- tcpdump text parser
- Modular attack detection: PortScan / Beacon / BruteForce
- UUID session validation
- 50 MB pre-check guard (Content-Length before read)
- 254/254 tests pass (including streaming-limit unit tests)

### Download
- **WireBoard.exe** — Windows x64, 12.16 MB, no install required
- Run and open `http://127.0.0.1:8000`

### Upgrade from v3.x
v5.0.0 is a backend-only API server (no bundled browser UI). Use any HTTP client or integrate with a frontend.
