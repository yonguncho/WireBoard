# WireBoard v5.1.4 — QA Checklist

**날짜**: 2026-06-05  
**QA 라운드**: R5 (v5.1.4 — 업로드 버그·UI 개선·테스트 추가)

---

## 최종 판정: ✅ QA_PASS

| 항목 | 결과 |
|------|------|
| 테스트 스위트 | **259 / 259 PASS** (스킵 0) |
| 코드 리뷰 Critical | 0건 |
| 이전 라운드 이슈 | **전량 해결** |
| 보안 점검 | ✅ PASS |
| 빌드 | WireBoard.exe 38.0 MB (dpkt 포함) |

---

## 1. 테스트 결과

| 항목 | 수치 |
|------|------|
| 수집된 테스트 | 259개 |
| 통과 | **259개** |
| 스킵 | **0개** |
| 실패 | 0개 |
| 실행 시간 | 116.55초 |
| 이전(R4) 대비 | +5개 추가 |

---

## 2. v5.1.4 변경 사항 및 검증

| # | 이슈 | 수정 파일 | 검증 |
|---|------|-----------|------|
| F-1 | 업로드 400 오류 (pcapng struct parser ValueError) | `pcap_parser.py` | ✅ FIXED — pcapng magic 시 ValueError 대신 [] 반환 |
| F-2 | dpkt 번들 누락 (pcapng 파싱 불가) | `WireBoard.spec` | ✅ FIXED — collect_all('dpkt') 추가 |
| F-3 | 에러 메시지 미표시 (generic "400") | `api.ts` | ✅ FIXED — handleError()가 detail.message 파싱 |
| F-4 | Panel1 바차트 x축 string (Plotly 렌더 깨짐) | `Panel1Ip.tsx` | ✅ FIXED — e.bytes (number) + hovertemplate |
| F-5 | 버전 5.1.1 하드코딩 | `launcher.py` | ✅ FIXED — 5.1.4 |
| F-6 | Invalid HTTP request WARNING 노이즈 | `launcher.py` | ✅ FIXED — log filter 추가 |

---

## 3. UI/UX 개선 검증

| 항목 | 상태 |
|------|------|
| 탭 레이아웃 (개요/트래픽/보안/프로토콜) | ✅ |
| 요약 통계바 (세션·IP·공격·RST) | ✅ |
| 헤더 파일명·세션수·소스타입 표시 | ✅ |
| 단계별 로딩 메시지 | ✅ |
| 에러 상세 메시지 표시 | ✅ |
| 새 파일 버튼 | ✅ |

---

## 4. PRD MVP 3대 필수 요건 (이월)

### 요건 A: pcap 업로드 및 분석 파이프라인
- [x] POST /api/upload — Content-Length 사전 체크, 50MB 제한, 스트리밍 청크 제한, 빈 파일 거부
- [x] POST /api/analyze — UUID/IP 검증 400, asyncio.gather 병렬 탐지
- [x] PortScan + Beacon + CommFailure + DDoS + Exfiltration + BruteForce 탐지기 동작
- [x] .pcap + .pcapng 모두 정식 지원 (dpkt 번들)

### 요건 B: 세션 관리 및 TTL
- [x] SessionStore TTL = 900초 (15분)
- [x] TTL eviction 시 annotations_store 연동 정리
- [x] annotations JSON export에 포함

### 요건 C: 보안 기본값
- [x] 0.0.0.0 binding 0 hit
- [x] bare except 0 hit
- [x] 하드코딩 시크릿 0 hit
- [x] LoggingMiddleware requestId/durationMs/ISO8601
- [x] `_read_stream_limited()` chunked upload 50MB 스트리밍 제한
- [x] 로컬 전용 (127.0.0.1) 바인딩 유지

---

## 5. 보안 점검

| 항목 | 결과 | 판정 |
|------|------|------|
| 0.0.0.0 바인딩 | 0 hit | ✅ PASS |
| bare except | 0 hit | ✅ PASS |
| 하드코딩 시크릿 | 0 hit | ✅ PASS |
| UUID 검증 | analyze/filter/compare/annotations | ✅ PASS |

---

## 6. 빌드 정보

| 항목 | 내용 |
|------|------|
| 파일 | `dist/WireBoard.exe` |
| 크기 | 38.0 MB (dpkt 포함) |
| 버전 | 5.1.4 |
| 도구 | PyInstaller 6.20.0 onefile |
| 바인딩 | 127.0.0.1:8765 |
| console | True (EDR-safe) |
| dpkt | ✅ 번들 포함 |

---

## 7. 배포 정보

| 항목 | 내용 |
|------|------|
| GitHub Release | https://github.com/yonguncho/WireBoard/releases/tag/v5.1.4 |
| 다운로드 URL | https://github.com/yonguncho/WireBoard/releases/download/v5.1.4/WireBoard.exe |
