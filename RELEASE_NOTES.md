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
