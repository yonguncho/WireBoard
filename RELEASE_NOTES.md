## WireBoard v7.12.0 (2026-07-09)

Launch prep — licensing infrastructure, onboarding, legal clean-up.

### New
- **Demo capture onboarding** — a "Try a demo capture" button on the upload page
  loads a bundled sample (web flow with a retransmit, a DNS query/response, and a
  120-port scan) so first-time users see the 5-minute triage immediately.
- **License verification infrastructure** (OFF by default — nothing is gated):
  offline Ed25519-signed license files (privacy-preserving, no internet) plus
  optional Lemon Squeezy online validation. Endpoints `GET /api/license/status` and
  `POST /api/license/activate`; owner issues licenses with `tools/sign_license.py`.
  Turn gating on later with `WIREBOARD_LICENSE_ENFORCE=1`.
- Upload hint updated to the real limits (2 GB pcap / 300 MB text).

### Legal / docs
- Confirmed **no MaxMind GeoIP database is bundled** (legally clean); documented the
  licensing model, GeoIP handling, and privacy stance in `docs/LICENSING_AND_LEGAL.md`.

### Tests
- 909 passed (incl. license offline round-trip / tamper / expiry + demo endpoint).

---

## WireBoard v7.11.0 (2026-07-08)

Customer-ready reports + headless CLI (automation).

### New
- **Richer PDF report** — the Executive Summary now includes a full DIAGNOSTICS
  section: network-vs-application verdict, connection health score, TCP Expert
  Info counts (retransmit / dup-ack / zero-window / lost), DNS response p50/p95 and
  error/no-response counts, detected application protocols (QUIC/HTTP2), and
  capture-quality caveats — a report you can hand to a customer.
- **Headless CLI mode** for automation / SOC pipelines:
  `WireBoard.exe analyze <capture> [--json out.json] [--pdf out.pdf] [--target IP]`
  Parses (incl. streaming for large pcap), runs detection + diagnosis, and emits
  JSON and/or a PDF report with no server or browser.

### Tests
- 897 passed (incl. CLI + PDF-diagnostics tests).

---

## WireBoard v7.10.0 (2026-07-08)

Large captures + modern protocols (QUIC / HTTP/2).

### New — large-capture streaming
- **File size limit raised from 50 MB to 2 GB** for pcap/pcapng. Uploads are spooled
  to disk and parsed **streaming from the file handle** (dpkt yields packets lazily),
  so memory stays bounded by the flow/packet caps regardless of file size — real
  captures (hundreds of MB to GB) now open instead of being rejected as a "toy" limit.
- Binary pcap routed by magic bytes to the streaming path; text formats
  (HAR/FortiGate/tcpdump) read within the text cap (300 MB).
- Limits configurable via `WIREBOARD_MAX_PCAP_MB` / `WIREBOARD_MAX_TEXT_MB`.

### New — QUIC & HTTP/2
- **QUIC** long-header identification (version: v1/v2/draft/gQUIC + packet type), and
  **SNI decrypted from the QUIC Initial packet** (RFC 9001 initial keys) — you can see
  which service an encrypted QUIC/UDP-443 connection is going to.
- **HTTP/2** detection via TLS ALPN (`h2`) and cleartext h2c preface.
- Detected application protocols are shown in the Protocol panel and the flow header
  (with QUIC SNI), instead of guessing from the port alone.

### Tests
- 885 passed (streaming, QUIC identification/decrypt round-trip, HTTP/2).

---

## WireBoard v7.9.1 (2026-07-07)

Fix — HAR upload robustness.

### Fixed
- **HAR files with a UTF-8 BOM** (added by some tools/proxies/editors) were rejected
  as "unsupported format". Now decoded with utf-8-sig and accepted.
- **A single malformed entry no longer fails the whole HAR.** Browser HAR exports
  often include aborted requests / WebSocket / entries without a request URL — these
  are now skipped with a warning while the valid entries parse normally.
- Non-list `entries`, non-dict entries, bad `time`/`timings`, and out-of-range URL
  ports are handled defensively instead of raising.

### Tests
- 870 passed (incl. new HAR robustness/upload tests).

---

## WireBoard v7.9.0 (2026-07-05)

Live capture — record packets directly on the PC (optional).

### New
- **Live Capture (beta)**: pick a network interface (shown with its IP), optionally
  enter a source IP / destination IP / port / host filter, and capture packets
  straight into the analysis pipeline — no external tool needed. Capture is 100%
  local (never leaves the PC), auto-stops at a packet or time limit, and the result
  flows into the normal analysis views. The captured file is also downloadable.
- Filters compile to a BPF (e.g. `src host … and dst host … and port …`);
  inputs are validated as IPs/ports.

### Requirements / notes
- Live capture needs the **Npcap** driver (npcap.com) and the app must run as
  **Administrator**. When either is missing, the UI explains it and offline pcap
  analysis is unaffected — the single-EXE, no-install analysis story is unchanged.

### Tests
- 861 passed. (Live sniff path verified manually on a machine with Npcap; capture
  endpoints, BPF builder, and graceful degradation are covered by tests.)

---

## WireBoard v7.8.0 (2026-07-04)

Protocol-detail polish — window scale and L2 vendor identification.

### New
- **TCP window scale**: the SYN window-scale option is parsed per direction, so the
  flow view shows the true receive window (raw × factor) instead of the raw 16-bit
  value, and the negotiated scale (e.g. ×128/×64) appears in the flow header.
- **MAC OUI vendor**: the flow header now identifies the L2 device vendor from the
  MAC prefix (Cisco → Dell, VMware, Fortinet, Juniper, …) using a bundled offline
  OUI table, plus locally-administered / multicast detection.

### Tests
- 848 passed.

---

## WireBoard v7.7.0 (2026-07-04)

TLS failure diagnosis + time-based error overlay.

### New
- **TLS Alert decode + handshake stages**: the flow's TLS tab now shows the
  handshake result (Completed / FAILED on a fatal alert / Incomplete), the stages
  seen (ClientHello → ServerHello → …), and any Alert messages decoded by name
  (handshake_failure, certificate_expired, unknown_ca, protocol_version, …) — the
  classic "TCP connects but TLS drops" pattern is now visible.
- **Timeline error overlay**: the traffic timeline overlays a red per-bucket error
  series (RST + no-reply) on a second axis, answering "when did errors spike?".

### Tests
- 838 passed.

---

## WireBoard v7.6.0 (2026-07-04)

DNS triage — query↔response matching with latency and failure analysis.

### New
- **DNS query↔response matching** by transaction ID with per-query response time.
  The DNS panel now leads with the signals NOC checks first: **no-response count,
  SERVFAIL/NXDOMAIN/REFUSED errors, and response-time p50/p95/max** — plus a table
  of unanswered queries and the slowest lookups (color-coded).
- Works entirely from the existing captured DNS payloads (UDP/53); the DNS header
  (txid/rcode) is always within the captured bytes.

### Tests
- 831 passed (incl. new DNS matcher tests).

---

## WireBoard v7.5.0 (2026-07-04)

Correctness release — IPv6 support and parser hardening.

### Fixed / New
- **IPv6 is now parsed** (dpkt primary + scapy fallback). Dual-stack captures no
  longer silently drop their IPv6 half. TCP/UDP over IPv6 and ICMPv6 are decoded;
  hop-limit maps to the TTL/hop badge.
- **Layer fields in the struct fallback**: TTL / IP ID / DF / TCP window are now
  populated even on the last-resort parser.
- **VLAN stack cap** (QinQ ≤ 4 tags) in the struct parser — guards against a
  crafted/looping tag chain.
- **FortiGate/tcpdump log timezone** is configurable via `WIREBOARD_LOG_TZ_OFFSET`
  (hours, e.g. `9` or `-5`); logs carry no TZ, so this normalizes device-local
  timestamps to UTC instead of silently assuming UTC.

### Tests
- 824 passed (incl. new IPv6 parse tests).

---

## WireBoard v7.4.0 (2026-07-02)

Wireshark-grade TCP analysis — Expert Info and layer-level packet detail.

### New
- **TCP Expert Info**: per-packet flags reproduced from a sequence/ack/window state
  machine — retransmission, out-of-order, previous-segment-lost, duplicate ACK,
  zero-window, window-update. Shown as colored tags in the packet table, a per-flow
  event summary, and an aggregate Expert Info card (grouped by severity like Wireshark).
- **Layer fields exposed**: parser now keeps TCP window, IP TTL, IP ID, and the
  Don't-Fragment flag (previously discarded).
- **IP hop badge**: estimates hop count from the observed TTL vs the assumed initial
  TTL (64/128/255) — a quick "did the path change?" hint.
- **Per-packet delta time** column for latency triage.

### Notes
- 820 tests passed. Window-scale option is not yet parsed, so zero-window is based on
  the raw advertised window.

---

## WireBoard v7.3.0 (2026-07-02)

NOC triage release — trustworthy risk grading and "network vs application" verdicts.

### New
- **Network vs Application verdict**: compares pure network RTT (SYN↔SYN/ACK) against
  server response delay per TCP session and tells you which team to escalate to.
  Shown as a banner in Health Diagnostics and in the summary diagnosis.
- **Evidence-based risk grade**: risk score (0-100) with an explicit factor breakdown
  ("Why this grade") — no more unexplained HIGH/MEDIUM.
- **Failure diagnosis without an attack**: captures full of refused/timed-out
  connections are diagnosed as network problems instead of "normal traffic".
- **Capture-quality warnings**: flags connections that started before the capture,
  summary-only text logs, and flows hitting the per-flow packet cap — so partial
  captures aren't over-trusted.
- **Conversations panel**: RST / no-reply columns + sort by issue rate.
- **Compare verdict**: two-capture diff now classifies each conversation
  (NEW / GONE / SURGE / DROP / DEGRADED / RECOVERED) and rolls them into a single
  DEGRADED / IMPROVED / SIMILAR verdict.
- **English PDF report** with risk grade, evidence factors, and connectivity
  diagnosis; multi-page (no more silent truncation).

### Fixed
- False DEGRADED verdicts on healthy captures (normal RST teardown and one-way UDP
  such as syslog/mDNS/broadcast are no longer counted as failures).
- False MEDIUM/HIGH risk on broadcast-heavy LANs and summary-only text logs.
- Detector crashes no longer surface as attack findings.
- FortiGate verbose-3 logs now explain why .pcap conversion is unavailable
  (and how to re-capture with verbose 6).

### Tests
- 809 passed (pytest), TypeScript build clean.

---

## WireBoard v5.4.0

Zero external-dependency network capture analysis tool.

### What's New (v5.4.0 vs v5.0.0)

**신규 기능**
- Compare UI (T-12): 두 번째 PCAP 업로드 후 `/api/compare` → IP/포트/트래픽 변화 표시
- Annotations UI (T-13): `/api/annotations` 로드 + 타임라인 마커 목록 표시

**보안 수정**
- 업로드 파서 예외 처리 범위 확장: ValueError 외 KeyError/TypeError/JSONDecodeError/ValidationError → 400 응답
- Content-Length 비정상 값(음수, 비숫자) → 400 거부

**기능 수정**
- PortScan 탐지기: severity 기준 최상위 후보 반환 (이전: 첫 번째 결과만 반환)
- Beacon 탐지기: 동일 수정 — 다중 통신 쌍에서 high beacon 누락 방지
- EDR 빌드: `upx=False` 적용 (EDR-safe)

### 테스트 현황
- **415/415 tests PASS** (pytest, py-3.10)
- TypeScript 빌드: `tsc --noEmit` EXIT 0
- EDR: `upx=False`, `console=True`, 외부 네트워크 호출 0건

### Download
- **WireBoard.exe** — Windows x64, no install required
- Run and open `http://127.0.0.1:8000`

### Previous Versions
- v5.0.0 (2026-06-05): 기초 버전, 254 테스트, FortiGate/HAR/tcpdump/PCAP 파서
