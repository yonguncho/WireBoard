# WireBoard v5.0 — QA Checklist

**날짜**: 2026-06-05  
**작성자**: AI_WORKPLACE_Associate  
**QA 라운드**: R3 (CrossValidation R3 완료 + 전체 테스트 252/252 PASS)

---

## 최종 판정: ❌ NOT_READY

| 항목 | 결과 |
|------|------|
| 테스트 스위트 | **252 / 252 PASS** (스킵 0) |
| 코드 리뷰 Critical | 0건 |
| 코드 리뷰 High (Codex 검증) | 5건 미해결 |
| 코드 리뷰 Warning/NEED_FIX | 3건 미해결 |
| Codex CV R3 판정 | NEED_FIX |
| Codex 검증 공격 판정 | FAIL |
| PRD MVP 필수 3개 | 조건부 PASS (임계값 편차 있음) |
| 빌드 | WireBoard.exe 12.2 MB (2026-06-05) |

**NOT_READY 사유**: Codex CV R3 NEED_FIX (신규 이슈 2건) + Codex 검증 FAIL (스펙 정합성 5건)

---

## 1. 테스트 결과

| 항목 | 수치 |
|------|------|
| 수집된 테스트 | 252개 |
| 통과 | **252개** |
| 스킵 | **0개** (R2 116개 → 0개로 감소) |
| 실패 | 0개 |
| 실행 시간 | 6.90초 |
| allPassed | true |

> R2 대비: 116개 스킵 테스트 전량 PASS 전환. Phase 2 AttackDetector 3종 테스트 포함.

---

## 2. 코드 리뷰 결과 처리 (CC R3 + Codex CV R3 + Codex 검증)

### 2-1. CC Review Round 3 (Associate — 이번 라운드)

| # | 이슈 | 심각도 | 처리 상태 |
|---|------|--------|-----------|
| C3-1 | session.py 도메인 유효성 검사 미완 (src_ip/dst_ip/confidence/bytes/timestamp) | WARNING | ❌ 미해결 — Phase 3 처리 예정 |
| C3-N1 | pcap_parser.py `>I` 폴백 unreachable dead code | 참고 | ⚠️ 인지, 제거 권장 |
| C3-N2 | beacon_detector.py `len(intervals) < _MIN_SAMPLES - 1` 항상 false | 참고 | ⚠️ 인지, 제거 권장 |
| C3-N3 | annotations.py GET 가변 리스트 직접 반환 | 참고 | ❌ Codex CV R3 신규 이슈로 연결 |
| C3-N4 | analyze.py / session.py `_UUID_V4_RE` 중복 정의 | 참고 | ⚠️ utils/validators.py 추출 권장 |

### 2-2. Codex CV Round 3 (외부 — 이번 라운드)

| # | 이슈 | 심각도 | 처리 상태 |
|---|------|--------|-----------|
| CV3-1 | export.py: annotations가 JSON export에 미포함 (사용자 annotation 유실) | **HIGH** | ❌ 신규 미해결 |
| CV3-2 | annotations_store TTL/LRU 분리 → 세션 만료 후 메모리 증가 | **HIGH** | ❌ 신규 미해결 |
| CV3-A1 | session.py 도메인 검증 미완 (CC R3-1과 동일) | WARNING | ❌ 미해결 |
| CV3-A2 | pcap_parser.py `>I` dead code | 참고 | ⚠️ 인지 |
| CV3-A3 | beacon_detector dead code | 참고 | ⚠️ 인지 |
| CV3-A4 | annotations.py 가변 리스트 반환 | 참고 | ❌ CV3-1 수정 시 함께 처리 |

**Codex CV R3 판정**: `NEED_FIX`

### 2-3. Codex 검증 공격 (스펙 정합성 검증)

| # | 이슈 | 심각도 | 처리 상태 |
|---|------|--------|-----------|
| V-1 | 제품명/버전 불일치 (WireBoard v5.0 vs 원본 todo PacketLens v5.0) | **HIGH** | ❌ 확인 필요 |
| V-2 | T-04: pcap_parser가 dpkt/scapy 없이 struct 직접 파싱 (스펙 편차) | **HIGH** | ⚠️ 기능 정상, 스펙 재정의 필요 |
| V-3 | T-08: Content-Length 없는 chunked 업로드 시 전체 read() 가능 | **HIGH** | ❌ 스트리밍 제한 테스트 추가 필요 |
| V-4 | T-07: LoggingMiddleware requestId/durationMs/ISO8601 미구현 | **HIGH** | ❌ 미해결 |
| V-5 | T-16/T-27: DDoS/Exfil/BruteForce 임계값·시간창·MITRE ID가 원본 스펙과 다름 | **HIGH** | ❌ 스펙 재검토 필요 |

**Codex 검증 판정**: `FAIL` (critical 5건)

---

## 3. PRD MVP 3대 필수 요건 점검

### 요건 A: pcap 업로드 및 분석 파이프라인
- [x] POST /api/upload — Content-Length 사전 체크, 50MB 제한, 빈 파일 거부
- [x] POST /api/analyze — UUID/IP 검증, 404/400 정상 반환
- [x] PortScan + Beacon + CommFailure + DDoS + Exfiltration + BruteForce 탐지기 동작
- [x] 응답 스키마 완결
- [⚠️] AttackDetector 임계값 원본 스펙과 편차 (Codex 검증 V-5)

### 요건 B: 세션 관리 및 TTL
- [x] SessionStore TTL = 900초 (15분)
- [x] TTL 0 인스턴스화로 테스트 격리 정상
- [x] `test_session_store_*` 전 케이스 PASS
- [⚠️] annotations_store TTL 분리 → 메모리 증가 가능 (CV3-2)

### 요건 C: 보안 기본값
- [x] `test_no_0000_binding` PASS
- [x] `test_no_bare_except` PASS
- [x] `test_no_any_type_in_models` PASS
- [x] `test_analyze_router_has_gc_collect` PASS
- [⚠️] T-08 chunked upload 스트리밍 제한 미검증 (V-3)

---

## 4. Phase 2 AttackDetector 구현 현황

| 탐지기 | MITRE | 임계값 | 상태 |
|--------|-------|--------|------|
| PortScanDetector | T1046 | 포트 ≥ 20/100 | ✅ 구현 완료 |
| BeaconDetector | T1071 | CV ≤ 3%/10%, n ≥ 5 | ✅ 구현 완료 |
| CommFailureDetector | — | RST/Malformed | ✅ 구현 완료 |
| DDoSDetector | T1498 | pps/unique_src (⚠️ 스펙 편차 V-5) | ⚠️ 재검토 필요 |
| ExfiltrationDetector | T1041 | conn/bytes (⚠️ 스펙 편차 V-5) | ⚠️ 재검토 필요 |
| BruteForceDetector | T1110 | 시도/실패율 (⚠️ 시간창 미구현 V-5) | ⚠️ 재검토 필요 |

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

## 6. Warning/NEED_FIX 잔여 현황

| # | 항목 | 파일 | 처리 상태 |
|---|------|------|-----------|
| W-1 | session.py 도메인 검증 미완 (IP/confidence/bytes/timestamp) | `models/session.py` | ❌ 미해결 |
| W-2 | export.py annotations 미포함 → 사용자 데이터 유실 | `routers/export.py` | ❌ 신규 미해결 |
| W-3 | annotations_store 메모리 증가 (TTL 분리) | `main.py`/`store/` | ❌ 신규 미해결 |
| W-4 | LoggingMiddleware requestId/durationMs/ISO8601 미구현 | (없음) | ❌ 미구현 |
| W-5 | AttackDetector 임계값 원본 스펙 편차 | 탐지기 파일 3종 | ❌ 스펙 재검토 필요 |
| W-6 | chunked upload 스트리밍 제한 테스트 없음 | `routers/upload.py` | ❌ 테스트 추가 필요 |

---

## 7. 수정 이력 (R3 반영)

| 파일 | 변경 내용 | 사유 |
|------|-----------|------|
| `backend/routers/upload.py` | 파서 예외 확장 (KeyError/TypeError/ValidationError) | CC R3 |
| `backend/services/attack_detector/portscan_detector.py` | best-severity 비교 로직 도입 | CC R3 |
| `backend/services/attack_detector/beacon_detector.py` | best-severity + group_size 이중 기준 | CC R3 |
| `backend/routers/upload.py` | Content-Length 음수/비정상 400 처리 | CC R3 |
| `backend/store/session_store.py` | threading.Lock + deepcopy 적용 | CC R3 |
| `backend/routers/upload.py` | TcpdumpParser 등록 + 확장자 허용 | CC R3 |
| `backend/models/session.py` | src_port/dst_port 0-65535 검증 | CC R3 |

---

## 8. 다음 단계 (NEED_FIX 해결 목록)

**우선순위 HIGH** (NOT_READY 사유):
1. **CV3-1**: `export.py` — annotations 포함하여 JSON export (`annotations_store.get(upload_id)` 연동)
2. **CV3-2**: annotations_store TTL 정리 훅 추가 (SessionStore evict 시 연동)
3. **V-3**: chunked 업로드 50MB 스트리밍 제한 테스트 추가
4. **V-4**: LoggingMiddleware 구현 (requestId, durationMs, ISO8601)
5. **V-5**: DDoS/Exfil/BruteForce 임계값·시간창 원본 스펙으로 재정렬

**우선순위 MEDIUM**:
6. **W-1**: session.py IP/confidence/bytes/timestamp 도메인 검증 완성

**전환 조건**: 위 HIGH 항목 5건 해결 + 테스트 재실행 252+ PASS → R4 QA 재판정.
