# WireBoard v5.2.0 — QA Checklist

**날짜**: 2026-06-05  
**QA 라운드**: R1 (v5.2.0 — 공격/방어 재설계 + 버그픽스)

---

## 최종 판정: ✅ QA_PASS

| 항목 | 결과 |
|------|------|
| 테스트 스위트 | **303 / 303 PASS** (스킵 0) |
| 코드 리뷰 Critical | 0건 |
| 버그픽스 | **7건 전량 수정** |
| 보안 점검 | ✅ PASS |
| 빌드 | WireBoard.exe 38.0 MB |

---

## 1. 수정된 버그

| # | 버그 | 영향 | 수정 파일 |
|---|------|------|-----------|
| B1 | `AttackResult`에 `src_ip` 필드 없음 → attacker_ips 항상 빈 배열 | Critical | `base.py`, 탐지기 6개, `analyze.py`, `summary_builder.py` |
| B2 | Exfiltration MITRE `T1041` vs 방어권고 맵 `T1048` 불일치 | Critical | `summary_builder.py` |
| B3 | CommFailure `T1499` 방어권고 맵 누락 | High | `summary_builder.py` |
| B4 | narrative `" ".join()` → 불릿 포인트 인라인 붙음 | Medium | `summary_builder.py`, `NarrativeSummary.tsx` |
| B5 | sessions 없으면 timeline ts=0.0 → 프론트 1970년 표시 | Medium | `summary_builder.py`, `AttackTimeline.tsx` |
| B6 | 미사용 `Counter` import / `_is_internal` 데드코드 | Low | `summary_builder.py` |
| B7 | `attack-defense-row` margin-bottom + panel-grid gap 이중 간격 | Low | `App.css` |

---

## 2. 테스트 결과

| 항목 | 수치 |
|------|------|
| 수집된 테스트 | 303개 |
| 통과 | **303개** |
| 스킵 | 0개 |
| 실패 | 0개 |
| 실행 시간 | ~119초 |
| v5.1.4(R5) 대비 | +44개 추가 |

---

## 3. 신규 테스트 커버리지 (44개)

| 클래스 | 케이스 | 검증 항목 |
|--------|--------|-----------|
| TestBuildSummaryClean | 2 | CLEAN 판정, narrative 비어있지 않음 |
| TestBuildSummaryRiskLevel | 5 | HIGH/MEDIUM/LOW, 혼합 max, 대소문자 |
| TestAttackerIpExtraction | 6 | B1 fix — src_ip 추출, 중복 제거, None/빈 처리, victim 추론, 상한 5 |
| TestMitreRecommendations | 8 | B2/B3 fix — T1046/1071/1498/1041/1110/1499 권고, 폴백, 중복 제거 |
| TestTimeline | 4 | B5 fix — 길이 일치, ts=0 when no sessions, ts>0 with sessions, src_ip 포함 |
| TestNarrativeFormatting | 2 | B4 fix — 줄바꿈, 불릿 없을 때 |
| TestAttackDetectorSrcIp | 6 | B1 fix — 각 탐지기 src_ip 반환 검증 |
| TestAttackResultDowngrade | 1 | downgrade()가 src_ip 유지 |
| TestAnalyzeEndpointSrcIp | 2 | analyze endpoint dict에 src_ip 포함 |
| TestSummaryEndpoint | 8 | 통합 테스트 — 404/400, schema, CLEAN, attacker_ips, recommendations, narrative |

---

## 4. v5.2.0 신규 기능 (Phase 1)

| 컴포넌트 | 상태 |
|----------|------|
| NarrativeSummary — 자연어 요약 카드 | ✅ |
| AttackTimeline — 공격 타임라인 | ✅ |
| DefensePanel — 방어 권고 패널 | ✅ |
| GET /api/summary/{id} | ✅ |
| 초보자 설명 토글 (? 버튼) | ✅ |
| 공격자/피해자 IP 뱃지 | ✅ (B1 fix로 이제 실제 표시됨) |
| MITRE → 방어권고 6개 매핑 | ✅ (B2/B3 fix로 완전 커버) |

---

## 5. 보안 점검

| 항목 | 결과 |
|------|------|
| 0.0.0.0 바인딩 | 0 hit ✅ |
| bare except | 0 hit ✅ |
| 하드코딩 시크릿 | 0 hit ✅ |
| UUID v4 검증 | summary/analyze/panels ✅ |

---

## 6. 빌드 정보

| 항목 | 내용 |
|------|------|
| 파일 | `dist/WireBoard.exe` |
| 크기 | 38.0 MB |
| 버전 | 5.2.0 |
| 빌드 시각 | 2026-06-05 21:44:27 |
| GitHub Release | https://github.com/yonguncho/WireBoard/releases/tag/v5.2.0 |
