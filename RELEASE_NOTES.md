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
