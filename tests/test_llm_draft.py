"""로컬 LLM 초안 — 환각 검사·폴백·기본 OFF 동일성 테스트 (모델 불필요, 가짜 응답 주입).

모델 불필요: 가짜 응답을 caller 로 주입한다.
실행: python -m pytest tests/test_llm_draft.py -q
"""
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from services.narrative import llm_draft  # noqa: E402
from services.narrative.llm_draft import (  # noqa: E402
    LlmConfig, LlmUnavailable, build_facts, draft_for_capture, generate_draft, template_paragraphs,
)
from services.narrative.llm_guard import check_paragraph  # noqa: E402
from services.narrative.summary_builder import build_summary  # noqa: E402
from services.report.pdf_exporter import PdfExporter  # noqa: E402

CASE = json.loads((ROOT / "eval/llm_draft/cases/12_mixed_beacon_exfil_degraded.json").read_text(encoding="utf-8"))
FACTS, TEMPLATES = CASE["facts"], CASE["templates"]
CFG = LlmConfig(True, "ollama", "http://127.0.0.1:11434", "fake", 5)

GOOD_EXEC = ("The capture indicates HIGH risk activity (score 100) across 197 sessions. Host 10.0.0.31 shows "
             "C2 beacon behaviour toward 203.0.113.77 consistent with T1071, and may be sending data out (T1041). "
             "The host should be isolated and reviewed.")
GOOD_NARR = ("Between 2026-10-29 01:02:03 UTC and 01:49:33 UTC, 10.0.0.31 made 96 connections to 203.0.113.77 "
             "with a CV of 2.1%, which is consistent with beaconing. The same host sent 140 MB over 6 external "
             "connections. 9 of 60 connections were refused.")


def fake(exec_text=GOOD_EXEC, exec_ids=("S1", "F1", "F2"), narr_text=GOOD_NARR, narr_ids=("F1", "F2", "H1")):
    payload = {"executive_summary": {"text": exec_text, "finding_ids": list(exec_ids)},
               "incident_narrative": {"text": narr_text, "finding_ids": list(narr_ids)}}
    return lambda cfg, facts: "```json\n" + json.dumps(payload) + "\n```"


def sources(draft):
    return {p["slot"]: p["source"] for p in draft["paragraphs"]}


# ── 정상 문단은 통과 ──────────────────────────────────────────────────────────

def test_grounded_paragraphs_pass():
    d = generate_draft(FACTS, TEMPLATES, CFG, caller=fake())
    assert sources(d) == {"executive_summary": "llm", "incident_narrative": "llm"}, d["paragraphs"]
    assert d["stats"] == {"passed": 2, "replaced": 0, "gen_ms": d["stats"]["gen_ms"]}
    assert d["label"] == "AI-generated draft - review required"


# ── 일부러 틀린 가짜 출력이 걸러지는가 ─────────────────────────────────────────

@pytest.mark.parametrize("bad, reason", [
    (GOOD_NARR.replace("96 connections", "97 connections"), "numbers not in input"),           # 틀린 숫자
    (GOOD_NARR.replace("140 MB", "1.4 GB"), "numbers not in input"),                           # 틀린 크기
    (GOOD_NARR.replace("203.0.113.77", "203.0.113.78"), "IPs not in input"),                   # 없는 IP
    (GOOD_NARR + " It also contacted 2001:db8::99.", "IPs not in input"),                      # 없는 IPv6
    (GOOD_NARR + " Port 4444 was used.", "numbers not in input"),                              # 없는 포트
    (GOOD_NARR.replace("01:49:33", "02:49:33"), "times/dates not in input"),                   # 틀린 시각
    (GOOD_NARR.replace("2026-10-29", "2026-10-28"), "times/dates not in input"),               # 틀린 날짜
    (GOOD_NARR + " This matches T1059.001.", "MITRE IDs not in input"),                        # 없는 기법
    (GOOD_NARR + " The tactic is TA0011.", "MITRE IDs not in input"),                          # 없는 전술
    (GOOD_NARR + " It resolved evil-c2.example.net first.", "domains not in input"),           # 없는 도메인
    (GOOD_NARR + " Payload hash " + "ab" * 32 + ".", "hashes not in input"),                   # 없는 해시
    (GOOD_NARR + " See also F9.", "mentions unknown IDs in text"),                             # 없는 ID 언급
    (GOOD_NARR + " The host is definitely compromised.", "banned assertive wording"),          # 단정
    (GOOD_NARR + " 10.0.0.31 has been compromised.", "banned assertive wording"),
    ("이 호스트는 확실히 침해됨. " + GOOD_NARR, "banned assertive wording"),
    ("Beaconing seen.", "too short"),
    # 독립 리뷰가 찾은 우회 경로 (모두 걸러져야 함)
    (GOOD_NARR.replace("140 MB", "140 GB"), "number/unit not in input"),                      # 단위만 바꿈
    (GOOD_NARR.replace("140 MB", "140TB"), "number/unit not in input"),                        # 공백 없는 단위
    (GOOD_NARR + " It used port4444 as well.", "numbers not in input"),                        # 단어에 붙은 숫자
    (GOOD_NARR + " See port_7777.", "numbers not in input"),
    (GOOD_NARR + " This matches t1059.", "MITRE IDs not in input"),                            # 소문자 MITRE
    (GOOD_NARR + " See also f9.", "mentions unknown IDs in text"),                             # 소문자 ID
    (GOOD_NARR + " It reached ample.com.", "domains not in input"),                            # 부분 문자열 도메인
    (GOOD_NARR + " It contacted forty-two hosts.", "numbers not in input"),                    # 단어 숫자 → 42 로 환산해 검사
    (GOOD_NARR + " It made nine thousand requests.", "numbers written as words"),               # 크기 단위 단어
    (GOOD_NARR + " The host has been breached.", "banned assertive wording"),
    (GOOD_NARR + " The host is infected.", "banned assertive wording"),
])
def test_hallucinated_paragraph_is_replaced_by_template(bad, reason):
    d = generate_draft(FACTS, TEMPLATES, CFG, caller=fake(narr_text=bad))
    p = next(p for p in d["paragraphs"] if p["slot"] == "incident_narrative")
    assert p["source"] == "template"
    assert p["text"] == TEMPLATES["incident_narrative"]
    assert any(v.startswith(reason) for v in p["violations"]), p["violations"]
    # 다른 슬롯은 영향 없음 (문단 단위 대체)
    assert sources(d)["executive_summary"] == "llm"
    assert d["stats"]["replaced"] == 1


def test_unknown_or_missing_finding_ids_rejected():
    d = generate_draft(FACTS, TEMPLATES, CFG, caller=fake(exec_ids=("F1", "F7")))
    assert sources(d)["executive_summary"] == "template"
    d = generate_draft(FACTS, TEMPLATES, CFG, caller=fake(exec_ids=()))
    assert sources(d)["executive_summary"] == "template"


def test_unparseable_output_falls_back_entirely():
    d = generate_draft(FACTS, TEMPLATES, CFG, caller=lambda c, f: "Sure! Here is your report: ...")
    assert sources(d) == {"executive_summary": "template", "incident_narrative": "template"}
    assert d["stats"]["replaced"] == 2


def test_check_paragraph_accepts_values_copied_from_input():
    assert check_paragraph("Host 10.0.0.21 talked to 192.0.2.53 on port 53 in 30 sessions (5.4 KB), see P4.",
                           ["P4"], FACTS) == []


# ── 꺼짐 / 모델 없음 → 기존과 동일 ─────────────────────────────────────────────

class _Cap:
    def __init__(self, attacks, sessions):
        self.attacks, self.sessions, self.target_ip = attacks, sessions, None


def _capture():
    sys.path.insert(0, str(ROOT / "eval/llm_draft"))
    import make_cases
    attacks, sessions, health = make_cases.CASES["04_beacon_single"]
    return _Cap(attacks, sessions), build_summary(attacks, sessions, health=health)


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("WIREBOARD_LLM_ENABLED", raising=False)
    assert LlmConfig.from_env().enabled is False
    cap, nr = _capture()
    assert draft_for_capture(cap, nr) is None


@pytest.mark.parametrize("url", ["http://192.168.0.10:11434", "http://example.com:11434", "file:///etc/passwd"])
def test_non_loopback_url_is_refused(monkeypatch, url):
    monkeypatch.setenv("WIREBOARD_LLM_ENABLED", "1")
    monkeypatch.setenv("WIREBOARD_LLM_URL", url)
    assert LlmConfig.from_env().enabled is False


def test_http_proxy_is_ignored(monkeypatch):
    """HTTP_PROXY 가 있어도 사실 JSON 이 프록시로 가지 않는다 (직접 loopback 접속)."""
    import socket
    import threading
    hits = []
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)
    proxy.settimeout(3)

    def accept():
        try:
            conn, _ = proxy.accept()
            hits.append(conn.recv(200))
            conn.close()
        except OSError:
            pass
    th = threading.Thread(target=accept)
    th.start()
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.getsockname()[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.getsockname()[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    with pytest.raises(LlmUnavailable):
        llm_draft.call_model(LlmConfig(True, "ollama", "http://127.0.0.1:9", "m", 2), FACTS)
    th.join()
    proxy.close()
    assert hits == []


@pytest.mark.parametrize("resp", [5, [1], {"message": {"content": {"a": 1}}}, {"message": None}])
def test_malformed_runtime_response_is_unavailable_not_crash(monkeypatch, resp):
    monkeypatch.setattr(llm_draft, "_OPENER", type("O", (), {"open": lambda self, req, timeout: _Resp(resp)})())
    with pytest.raises(LlmUnavailable):
        llm_draft.call_model(CFG, FACTS)


class _Resp:
    def __init__(self, data):
        self.data = json.dumps(data).encode()

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_model_unreachable_returns_none(monkeypatch):
    cap, nr = _capture()
    cfg = LlmConfig(True, "ollama", "http://127.0.0.1:9", "nope", 2)  # 포트 9: 아무것도 안 떠 있음
    llm_draft._CACHE.clear()
    assert draft_for_capture(cap, nr, cfg) is None


def _pdf_text(analysis):
    path, _ = PdfExporter().generate(analysis)
    try:
        raw = path.read_bytes().decode("latin-1")
    finally:
        path.unlink(missing_ok=True)
    return re.sub(r"\(Generated: [^)]*\)", "", raw)


def test_pdf_identical_without_draft_and_labelled_with_draft():
    cap, nr = _capture()
    base = {"target_ip": "10.0.0.31", "sessions": cap.sessions, "attacks": cap.attacks, "annotations": [],
            "risk": {"risk_level": nr.risk_level, "risk_score": nr.risk_score, "headline": nr.headline,
                     "risk_factors": nr.risk_factors, "diagnosis": nr.diagnosis, "recommendations": nr.recommendations}}
    assert _pdf_text(base) == _pdf_text({**base, "ai_draft": None})

    facts = build_facts(cap.attacks, cap.sessions, nr)
    d = generate_draft(facts, template_paragraphs(nr), CFG, caller=fake(
        exec_text="Host 10.0.0.31 shows C2 beacon activity toward 203.0.113.77 (T1071); risk is HIGH. Review the host.",
        exec_ids=("F1", "S1"),
        narr_text="10.0.0.31 made 48 connections to 203.0.113.77 with CV=3.2%, consistent with beaconing.",
        narr_ids=("F1",)))
    assert d["stats"]["passed"] == 2, d["paragraphs"]
    txt = _pdf_text({**base, "ai_draft": d})
    assert "Summary \\(AI-generated draft - review required; based on F1, S1\\):" in txt
    assert "Incident narrative \\(AI-generated draft - review required; based on F1\\):" in txt
    assert txt.index("Incident narrative") > txt.index("=== THREAT ASSESSMENT ===")

    # 검사 실패 슬롯은 PDF 에 들어가지 않는다 (템플릿 서술이 그 자리를 맡음)
    d_bad = generate_draft(facts, template_paragraphs(nr), CFG, caller=fake(
        exec_text="Host 10.0.0.31 is definitely compromised and talked to 203.0.113.77 (T1071).", exec_ids=("F1",),
        narr_text="10.0.0.31 made 49 connections to 203.0.113.77, consistent with beaconing.", narr_ids=("F1",)))
    assert d_bad["stats"]["replaced"] == 2
    assert _pdf_text({**base, "ai_draft": d_bad}) == _pdf_text(base)


def test_api_endpoint_disabled_and_pdf_unchanged(api_client_factory=None):
    """FastAPI 경로: 기본 OFF 면 ai-draft 는 available=False."""
    from fastapi.testclient import TestClient
    import main
    client = TestClient(main.app)
    r = client.get("/api/summary/00000000-0000-4000-8000-000000000000/ai-draft")
    assert r.status_code == 404  # 없는 업로드 → 기존 summary 와 같은 404 규약


def test_concurrent_requests_run_model_once(monkeypatch):
    """같은 캡처 동시 요청(PDF 연타) → 모델 호출 1회, 모두 같은 결과."""
    import threading
    import time as _t
    calls = []

    def slow(facts, templates, cfg, caller=None):
        calls.append(1)
        _t.sleep(0.3)
        return {"paragraphs": [], "stats": {"passed": 0, "replaced": 0, "gen_ms": 300}}

    monkeypatch.setattr(llm_draft, "generate_draft", slow)
    llm_draft._CACHE.clear()
    cap, nr = _capture()
    out = []
    ths = [threading.Thread(target=lambda: out.append(draft_for_capture(cap, nr, CFG))) for _ in range(5)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    assert len(calls) == 1
    assert len(out) == 5 and all(o is out[0] for o in out)
    assert llm_draft._INFLIGHT == {}


def test_health_reports_bound_port():
    from fastapi.testclient import TestClient
    import main
    r = TestClient(main.app).get("/health")
    assert r.status_code == 200
    assert r.json()["port"] == 80  # TestClient 의 가상 서버 포트 — 하드코딩 8764 가 아님

# ── 실제 모델(llama3.2 3B, eval 2026-10-30)이 낸 환각 — 숫자는 입력에 있지만 의미가 틀린 경우 ──

@pytest.mark.parametrize("bad, reason", [
    # eval 11: '스캔한 포트 수'를 포트 번호로 씀
    (GOOD_NARR + " Traffic went to 203.0.113.77:96.", "IP:port not in input"),
    (GOOD_NARR + " It targeted port 140 on 203.0.113.77.", "IP:port not in input"),
    # eval 04: 입력에 없는 공격 유형을 지어냄
    (GOOD_NARR + " The top talkers indicate potential lateral movement.", "threat claims not in input"),
    (GOOD_NARR + " A port scan preceded this.", "threat claims not in input"),
    (GOOD_NARR + " This may be ransomware staging.", "threat claims not in input"),
    # eval 11: 침해 전제
    (GOOD_NARR + " Further analysis will show the extent of the compromise.", "banned assertive wording"),
    (GOOD_NARR + " This indicates a potential security breach.", "banned assertive wording"),
])
def test_real_model_hallucinations_are_rejected(bad, reason):
    p = check_paragraph(bad, ["F1"], FACTS)
    assert any(v.startswith(reason) for v in p), p


def test_valid_ip_port_and_supported_claims_pass():
    text = ("10.0.0.31 connected to 203.0.113.77:8443 repeatedly, consistent with C2 beaconing; "
            "it also sent 140 MB out, which may indicate exfiltration.")
    assert check_paragraph(text, ["F1", "F2", "P1"], FACTS) == []

def test_spelled_out_date_and_matching_number_word_pass():
    """실모델이 쓴 정상 표현: 풀어 쓴 날짜, 입력과 같은 값의 단어 숫자 (eval 07/05 오탐이었음)."""
    text = ("On October 29, 2026, 10.0.0.31 showed C2 beacon activity toward 203.0.113.77 with six "
            "external connections and 140 MB sent, which may indicate exfiltration.")
    assert check_paragraph(text, ["F1", "F2"], FACTS) == []
    bad = text.replace("October 29, 2026", "October 30, 2026")
    assert any(v.startswith("times/dates not in input") for v in check_paragraph(bad, ["F1"], FACTS))
    assert any(v.startswith("numbers not in input") for v in check_paragraph(text.replace("six", "seventeen"), ["F1"], FACTS))


def test_output_format_leak_rejected():
    p = check_paragraph(GOOD_NARR + " The finding_ids for this narrative are [F1].", ["F1"], FACTS)
    assert "output format leaked into text" in p

# ── hermes3 8B 실측(eval 2026-10-30)에서 검사를 통과했던 의미 오류 ──

@pytest.mark.parametrize("bad, reason", [
    ("Four external hosts (10.0.0.31, 10.0.0.21) communicated with internal hosts (203.0.113.77), "
     "consistent with C2 beaconing.", "internal/external mislabel"),
    ("The beacon from 10.0.0.31 to 203.0.113.77 had a high confidence level of 2.1% over 96 connections.",
     "metric not in input"),
    ("The compromised host 10.0.0.31 beaconed to 203.0.113.77 over 96 connections (CV=2.1%).",
     "unhedged compromise claim"),
])
def test_8b_semantic_errors_rejected(bad, reason):
    p = check_paragraph(bad, ["F1"], FACTS)
    assert any(v.startswith(reason) for v in p), p


def test_correct_labels_scale_and_hedged_compromise_pass():
    text = ("Internal host 10.0.0.31 contacted external address 203.0.113.77 96 times (CV=2.1%), "
            "which may indicate a compromised host; the risk score is 100 out of 100.")
    assert check_paragraph(text, ["F1", "S1"], FACTS) == []

def test_ip_port_is_not_read_as_time():
    assert check_paragraph("Host 10.0.0.21 queried 192.0.2.53:53 in 30 sessions (5.4 KB), see P4.", ["P4"], FACTS) == []

# ── 2차 독립 리뷰 지적 (오탐·미탐) ──

@pytest.mark.parametrize("ok", [
    "The internal host 10.0.0.31 opened 96 connections to 203.0.113.77, consistent with C2 beaconing.",
    "An external server, 203.0.113.77, received 96 connections from 10.0.0.31 (CV=2.1%), consistent with beaconing.",
    "Traffic from 10.0.0.31 to 203.0.113.77 used port 8443; no lateral spread or scanning was observed.",
    "There is no evidence that 10.0.0.31 was compromised, but its 96 connections to 203.0.113.77 suggest beaconing.",
    "Collateral traffic from 10.0.0.31 to 203.0.113.77 over an IPsec tunnel is consistent with C2 beaconing.",
])
def test_review_false_positives_now_pass(ok):
    assert check_paragraph(ok, ["F1"], FACTS) == [], check_paragraph(ok, ["F1"], FACTS)


@pytest.mark.parametrize("bad, reason", [
    ("10.0.0.31 has been hacked and beaconed to 203.0.113.77 96 times.", "threat claims not in input"),
    ("10.0.0.31 was taken over and beaconed to 203.0.113.77 96 times.", "threat claims not in input"),
    ("Host 10.0.0.31 is external and beaconed to 203.0.113.77 96 times.", "internal/external mislabel"),
    ("The beacon may be periodic. 10.0.0.31 compromised the network via 203.0.113.77.", "unhedged compromise claim"),
])
def test_review_false_negatives_now_rejected(bad, reason):
    p = check_paragraph(bad, ["F1"], FACTS)
    assert any(v.startswith(reason) for v in p), p


def test_exact_duration_conversion_allowed():
    facts = json.loads(json.dumps(FACTS))
    facts["stats"]["duration_seconds"] = 120
    assert check_paragraph("The capture lasted 2 minutes and 10.0.0.31 beaconed to 203.0.113.77.", ["S1"], facts) == []