# WireBoard v5.0 — QA Checklist

**날짜**: 2026-06-05  
**작성자**: AI_WORKPLACE_Associate  
**QA 라운드**: R2 (Phase 2 AttackDetector 3종 구현 + 이슈 수정 반영)

---

## 최종 판정: ✅ READY

| 항목 | 결과 |
|------|------|
| 테스트 스위트 | 132 / 132 PASS |
| 코드 리뷰 Critical | 0건 |
| 코드 리뷰 Warning | 3건 (Phase 2 잔여) |
| PRD MVP 필수 3개 | PASS |
| Phase 2 AttackDetector | DDoS / Exfiltration / BruteForce 구현 완료 |
| 빌드 | WireBoard.exe 12.2 MB (2026-06-05) |

---

## 1. 테스트 결과

| 항목 | 수치 |
|------|------|
| 수집된 테스트 | 248개 |
| 통과 | 132개 |
| 스킵 | 116개 (미구현 Phase 2+ 피처) |
| 실패 | 0개 |
| 실행 시간 | 5.72초 |
| allPassed | true |

---

## 2. 이슈 처리 결과 (Elegance Review / Code Review)

| # | 이슈 | 처리 결과 |
|---|------|-----------|
| E-1 | Plotly iterrows + add_trace 루프 | ✅ 이미 None separator 패턴 적용 — `test_no_iterrows_in_services` PASS |
| E-2 | UUID 포맷 미검증 → silent mismatch | ✅ `analyze.py` `_UUID_V4_RE` + `session.py` `validate_uuid_v4` 적용 완료 |
| E-3 | webhook/API body 파싱 (VARIANT_PLAN) | ⚠️ JS 전용 패턴 — Python FastAPI 백엔드에 비적용, Phase 2 FE 구현 시 처리 예정 |

---

## 3. PRD MVP 3대 필수 요건 점검

### 요건 A: pcap 업로드 및 분석 파이프라인
- [x] POST /api/upload — Content-Length 사전 체크, 50MB 제한, 빈 파일 거부
- [x] POST /api/analyze — UUID/IP 검증, 404/400 정상 반환
- [x] PortScan + Beacon + CommFailure + DDoS + Exfiltration + BruteForce 탐지기 동작
- [x] 응답 스키마 완결 (flows / sessions / attacks / plotly_xs / plotly_ys / analysis_duration_ms / target_ip)

### 요건 B: 세션 관리 및 TTL
- [x] SessionStore TTL = 900초 (15분) — integration.md §4 준수
- [x] TTL 0 인스턴스화로 테스트 격리 정상
- [x] `test_session_store_*` 전 케이스 PASS

### 요건 C: 보안 기본값
- [x] `test_no_0000_binding` PASS — 0.0.0.0 바인딩 없음
- [x] `test_no_bare_except` PASS — bare except 없음
- [x] `test_no_any_type_in_models` PASS — Any 타입 사용 없음
- [x] `test_analyze_router_has_gc_collect` PASS — 메모리 해제 확인

---

## 4. Phase 2 AttackDetector 구현 현황

| 탐지기 | MITRE | 임계값 | 상태 |
|--------|-------|--------|------|
| PortScanDetector | T1046 | 포트 ≥ 20/100 | ✅ 기존 구현 |
| BeaconDetector | T1071 | CV ≤ 3%/10%, n ≥ 5 | ✅ 기존 구현 |
| CommFailureDetector | — | RST/Malformed | ✅ 기존 구현 |
| DDoSDetector | T1498 | 1000/300 pps, 50/10 src | ✅ R2 신규 구현 |
| ExfiltrationDetector | T1041 | conn>20/5, bytes>500/100 MB | ✅ R2 신규 구현 |
| BruteForceDetector | T1110 | 시도≥50/10, 실패율≥90% | ✅ R2 신규 구현 |

---

## 5. 빌드 결과

| 항목 | 내용 |
|------|------|
| 파일 | `dist/WireBoard.exe` |
| 크기 | 12.2 MB |
| 빌드 시각 | 2026-06-05 07:07:54 |
| 도구 | PyInstaller onefile |
| 바인딩 | 127.0.0.1:8765 (ADR-005 준수) |

---

## 6. Warning 잔여 현황

| Warning | 파일 | 처리 상태 |
|---------|------|-----------|
| SessionModel IP/port/timestamp 미검증 | `models/session.py` | ⚠️ Phase 2 후반 처리 예정 |
| SessionStore 비동기 미보호 | `store/session_store.py` | ⚠️ Phase 4 asyncio 전환 시 처리 예정 |
| PortScan/Beacon 신뢰도 집계 불일치 | 탐지기 파일 | ⚠️ Phase 2 정밀화 예정 |

---

## 7. 수정 이력 (R2)

| 파일 | 변경 내용 | 사유 |
|------|-----------|------|
| `backend/services/attack_detector/ddos_detector.py` | 신규 생성 | DDoS 탐지기 Phase 2 구현 |
| `backend/services/attack_detector/exfiltration_detector.py` | 신규 생성 | Exfiltration 탐지기 Phase 2 구현 |
| `backend/services/attack_detector/bruteforce_detector.py` | 신규 생성 | BruteForce 탐지기 Phase 2 구현 |
| `backend/routers/analyze.py` | `_DETECTORS` 3개 추가 | 신규 탐지기 엔드포인트 연동 |

---

## 8. 다음 단계 (Phase 2 잔여)

1. **PayloadExtractor** — HTTP/TLS/DNS 페이로드 추출 (test_tls_edge, test_dns_edge, test_http_status_edge)
2. **ConversationAnalyzer** — IP 대화 집계 Top 20 (test_conversation_edge)
3. **ReputationService** — 외부 IP 평판 조회 (로컬 캐시 우선)
4. **W-2 대응**: SessionModel 도메인 검증자 추가
5. **FE 구현**: React/Plotly 10개 패널, PDF 내보내기

**전환 조건**: 본 QA_CHECKLIST R2 READY 판정 → `implementation_phase2_remaining` 착수.
