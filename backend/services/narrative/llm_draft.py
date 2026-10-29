"""llm_draft — 로컬 LLM 으로 보고서 문단 초안 생성 (선택 기능, 기본 꺼짐).

원칙
- 외부 API 비용 0: 사용자 PC 에서 이미 돌고 있는 LLM 런타임(Ollama 또는 llama.cpp server 등
  OpenAI 호환 서버)에 **loopback 주소로만** 접속한다. 원격 URL 은 거부.
- 기본값 OFF. 꺼져 있거나 모델이 응답하지 않으면 None → 호출부는 기존 템플릿 보고서를 그대로 낸다.
- 모델에는 원본 패킷을 넣지 않는다. WireBoard 가 계산한 결과를 ID 붙은 사실 JSON 으로 넣는다.
- 출력은 슬롯별 {text, finding_ids}. 각 문단은 llm_guard 로 검사해 하나라도 위반하면 버리고
  템플릿 문장으로 대체한다. 수치 표·IOC 목록은 계속 코드가 만든다 (LLM 은 서술 문단만).

설정 (환경변수, 프로세스 시작 시 읽음)
  WIREBOARD_LLM_ENABLED   1/true/yes/on 이면 켬 (기본 0)
  WIREBOARD_LLM_API       ollama (기본) | openai   — openai = llama.cpp server 등 /v1/chat/completions
  WIREBOARD_LLM_URL       기본 http://127.0.0.1:11434 (ollama) / http://127.0.0.1:8080 (openai)
  WIREBOARD_LLM_MODEL     기본 llama3.2:3b (CPU 실측: 8B 와 검사 통과율 같고 2배 빠름 — eval/llm_draft)
  WIREBOARD_LLM_TIMEOUT   초, 기본 300 (CPU 전용 8B 는 보고서 1건 약 140초)
"""
from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlparse

from services.narrative.llm_guard import FactIndex, check_paragraph
from services.narrative.summary_builder import _ATTACK_KO, _fmt_bytes, _traffic_overview

logger = logging.getLogger(__name__)

DRAFT_LABEL = "AI-generated draft - review required"
SLOTS = ("executive_summary", "incident_narrative")
# v2: 숫자-의미 결합·근거 없는 공격 유형 금지 / v3: findings 없을 때 F1 인용 금지·형식 누설 금지
# v4: 내부/외부 대역 정의·침해 단정 금지·필드명 유지 (8B 실측 오류 대응)
PROMPT_VERSION = "v4"
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_TRUE = ("1", "true", "yes", "on")

_SYSTEM_PROMPT = """You write two short paragraphs for a network incident report.
Rules:
- Use ONLY the facts in the JSON you are given. Do not add knowledge from outside it.
- Copy every IP address, port, number, time, byte size and MITRE technique ID exactly as written in the JSON. If a value is not in the JSON, do not write it.
- Write numbers as digits, never as words. Do not add up, round or convert numbers.
- Keep each number with what it describes: a count of ports scanned or connections is not a port number. Write "IP:port" only for a port that the JSON lists for that IP.
- Addresses in 10.x, 172.16-31.x and 192.168.x are internal; other addresses are external. Do not call a host compromised; describe what it did.
- Use the field names as given (for example "CV" is the timing variation of a beacon, not a confidence level).
- Name only the attack types that appear in "findings". If "findings" is empty, say that no attack pattern was detected and do not speculate about attacks.
- Use cautious wording such as "indicates", "is consistent with", "may". Packet data alone cannot prove a compromise: never say a host is definitely or certainly compromised.
- For each paragraph, list the IDs (like F1, H2, P1, S1) of the facts it relies on in "finding_ids". Use only IDs that exist in the JSON; when "findings" is empty there is no F1, so cite S1, P and H IDs instead. Do not mention "finding_ids" in the text.
- Write in English. Plain sentences, no bullet points, no markdown.
Paragraphs:
- executive_summary: 2-4 sentences for a manager. What was observed, the overall risk level, and the general next step.
- incident_narrative: 3-6 sentences for an analyst. A factual account of which hosts did what to which hosts, based on the findings and top talkers, in time order where the facts allow.
Answer with JSON only:
{"executive_summary": {"text": "...", "finding_ids": ["S1"]}, "incident_narrative": {"text": "...", "finding_ids": ["F1"]}}"""

_SCHEMA = {
    "type": "object",
    "properties": {
        slot: {
            "type": "object",
            "properties": {"text": {"type": "string"}, "finding_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["text", "finding_ids"],
        } for slot in SLOTS
    },
    "required": list(SLOTS),
}


class LlmUnavailable(Exception):
    """런타임 미기동·모델 없음·타임아웃 등 — 템플릿 보고서로 조용히 되돌아간다."""


@dataclass(frozen=True)
class LlmConfig:
    enabled: bool
    api: str
    url: str
    model: str
    timeout: float

    @classmethod
    def from_env(cls) -> "LlmConfig":
        api = os.environ.get("WIREBOARD_LLM_API", "ollama").strip().lower()
        default_url = "http://127.0.0.1:8080" if api == "openai" else "http://127.0.0.1:11434"
        try:
            timeout = float(os.environ.get("WIREBOARD_LLM_TIMEOUT", "300"))
        except ValueError:
            timeout = 300.0
        enabled = os.environ.get("WIREBOARD_LLM_ENABLED", "0").strip().lower() in _TRUE
        url = os.environ.get("WIREBOARD_LLM_URL", default_url).strip().rstrip("/")
        cfg = cls(enabled, api, url, os.environ.get("WIREBOARD_LLM_MODEL", "llama3.2:3b").strip(), timeout)
        if enabled and (api not in ("ollama", "openai") or not is_loopback(url)):
            logger.warning("AI 초안 비활성: WIREBOARD_LLM_URL 은 loopback 주소만, API 는 ollama/openai 만 허용 (api=%s)", api)
            return cls(False, api, url, cfg.model, timeout)
        return cfg


def is_loopback(url: str) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    return p.scheme in ("http", "https") and (p.hostname or "") in _LOOPBACK


# ── 입력: ID 붙은 사실 JSON ──────────────────────────────────────────────────

def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _get(a, key, default=""):
    return a.get(key, default) if isinstance(a, dict) else getattr(a, key, default)


def build_facts(attacks: list, sessions: list, narrative, target_ip: Optional[str] = None) -> dict:
    """WireBoard 분석 결과 → 모델 입력 JSON. 원본 패킷/페이로드는 넣지 않는다."""
    attacks = [a for a in attacks if not _get(a, "detector_error", False) and _get(a, "attack_type") != "ERROR"]
    ov = _traffic_overview(sessions) or {}

    sev = {"high": 0, "medium": 0, "low": 0}
    findings = []
    for i, a in enumerate(attacks[:15], 1):
        s = str(_get(a, "severity", "low")).lower()
        sev[s if s in sev else "low"] += 1
        atype = _get(a, "attack_type", "Unknown")
        findings.append({
            "id": f"F{i}",
            "type": _ATTACK_KO.get(atype, atype),
            "severity": s,
            "mitre_id": _get(a, "mitre_id", "") or None,
            "source_ip": _get(a, "src_ip", "") or None,
            "detail": _get(a, "description", ""),
        })

    stats = {
        "id": "S1",
        "risk_level": narrative.risk_level,
        "risk_score": narrative.risk_score,
        "sessions": ov.get("session_count", len(sessions)),
        "total_traffic": _fmt_bytes(ov.get("total_bytes", 0)),
        "unique_sources": ov.get("unique_src", 0),
        "unique_destinations": ov.get("unique_dst", 0),
        "findings_total": len(attacks),
        "findings_high": sev["high"],
        "findings_medium": sev["medium"],
        "findings_low": sev["low"],
    }
    if ov.get("ts_min") and ov.get("ts_max"):
        stats["capture_start"] = _utc(ov["ts_min"])
        stats["capture_end"] = _utc(ov["ts_max"])
        stats["duration_seconds"] = int(ov["ts_max"] - ov["ts_min"])
    if target_ip:
        stats["target_ip"] = target_ip
    if narrative.victim_ips:
        stats["likely_targets"] = narrative.victim_ips[:5]

    pairs: dict[tuple, list] = {}
    for s in sessions:
        k = (_get(s, "src_ip"), _get(s, "dst_ip"))
        acc = pairs.setdefault(k, [0, 0, set()])
        acc[0] += (_get(s, "bytes_sent", 0) or 0) + (_get(s, "bytes_recv", 0) or 0)
        acc[1] += 1
        acc[2].add(_get(s, "dst_port", 0))
    top = sorted(pairs.items(), key=lambda kv: -kv[1][0])[:5]
    talkers = [{
        "id": f"P{i}", "source": k[0], "destination": k[1], "traffic": _fmt_bytes(v[0]),
        "sessions": v[1], "destination_ports": sorted(v[2])[:5],
    } for i, (k, v) in enumerate(top, 1)]

    return {
        "stats": stats,
        "findings": findings,
        "health": [{"id": f"H{i}", "text": d} for i, d in enumerate(narrative.diagnosis[:8], 1)],
        "top_talkers": talkers,
    }


def template_paragraphs(narrative) -> dict[str, str]:
    """검사에 실패한 슬롯을 대신할 기존 템플릿 문장."""
    lines = [l.strip().lstrip("•").strip() for l in narrative.narrative.splitlines() if l.strip()]
    detail = " ".join(lines[1:]) if len(lines) > 1 else ""
    return {
        "executive_summary": f"{narrative.headline}. {lines[0] if lines else ''}".strip(),
        "incident_narrative": detail or (lines[0] if lines else narrative.headline),
    }


# ── 모델 호출 ────────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # 리다이렉트로 loopback 밖으로 나가는 것 차단
        return None


# 프록시 무시: HTTP_PROXY·Windows 시스템 프록시가 있어도 사실 JSON 이 PC 밖으로 나가지 않게.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # 런타임 쪽 오류 본문(모델 없음·바이너리 누락 등)이 원인 파악의 전부라 로그에 남긴다
        detail = exc.read()[:300].decode("utf-8", "replace")
        raise LlmUnavailable(f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError) as exc:
        raise LlmUnavailable(f"{type(exc).__name__}: {exc}") from exc
    if not isinstance(data, dict):
        raise LlmUnavailable(f"unexpected response: {str(data)[:200]}")
    return data


def _content(value) -> str:
    if not isinstance(value, str):
        raise LlmUnavailable(f"unexpected message content: {str(value)[:200]}")
    return value


def call_model(cfg: LlmConfig, facts: dict) -> str:
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": "Facts JSON:\n" + json.dumps(facts, indent=1, ensure_ascii=False)},
    ]
    if cfg.api == "openai":
        resp = _post(f"{cfg.url}/v1/chat/completions", {
            "model": cfg.model, "messages": messages, "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }, cfg.timeout)
        try:
            return _content(resp["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmUnavailable(f"unexpected response: {str(resp)[:200]}") from exc
    resp = _post(f"{cfg.url}/api/chat", {
        "model": cfg.model, "messages": messages, "stream": False, "format": _SCHEMA,
        "options": {"temperature": 0.2, "num_ctx": 4096},
    }, cfg.timeout)
    if "error" in resp:
        raise LlmUnavailable(str(resp["error"])[:200])
    try:
        return _content(resp["message"]["content"])
    except (KeyError, TypeError) as exc:
        raise LlmUnavailable(f"unexpected response: {str(resp)[:200]}") from exc


def _parse(raw: str) -> dict:
    m = re.search(r"\{.*\}", raw or "", re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def generate_draft(facts: dict, templates: dict[str, str], cfg: LlmConfig,
                   caller: Callable[[LlmConfig, dict], str] = call_model) -> dict:
    """모델 호출 → 슬롯별 검사 → 실패 슬롯은 템플릿 대체. 모델 미가용이면 LlmUnavailable."""
    t0 = time.perf_counter()
    raw = caller(cfg, facts)
    gen_ms = int((time.perf_counter() - t0) * 1000)
    data = _parse(raw)
    idx = FactIndex(facts)

    paragraphs = []
    for slot in SLOTS:
        item = data.get(slot) if isinstance(data.get(slot), dict) else {}
        text = item.get("text", "")
        ids = item.get("finding_ids", [])
        violations = check_paragraph(text, ids, idx) if item else ["missing or unparseable output"]
        if violations:
            paragraphs.append({"slot": slot, "text": templates[slot], "finding_ids": [],
                               "source": "template", "violations": violations})
        else:
            paragraphs.append({"slot": slot, "text": " ".join(text.split()), "finding_ids": [str(i) for i in ids],
                               "source": "llm", "violations": []})

    passed = sum(p["source"] == "llm" for p in paragraphs)
    logger.info("AI 초안 검사: model=%s prompt=%s 통과=%d 대체=%d gen_ms=%d",
                cfg.model, PROMPT_VERSION, passed, len(paragraphs) - passed, gen_ms)
    for p in paragraphs:
        if p["violations"]:
            logger.info("AI 초안 문단 대체: slot=%s 사유=%s", p["slot"], "; ".join(p["violations"]))
    return {
        "label": DRAFT_LABEL,
        "model": cfg.model,
        "prompt_version": PROMPT_VERSION,
        "paragraphs": paragraphs,
        "stats": {"passed": passed, "replaced": len(paragraphs) - passed, "gen_ms": gen_ms},
    }


_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_CACHE_MAX = 32
_CACHE_LOCK = threading.Lock()  # executor 스레드 여러 개가 동시에 접근
_INFLIGHT: dict[str, threading.Lock] = {}


def draft_for_capture(capture, narrative, cfg: Optional[LlmConfig] = None) -> Optional[dict]:
    """캡처 1건의 초안. 꺼져 있거나 모델 미가용이면 None (= 기존 보고서 그대로)."""
    cfg = cfg or LlmConfig.from_env()
    if not cfg.enabled:
        return None
    facts = build_facts(capture.attacks, capture.sessions, narrative, getattr(capture, "target_ip", None))
    key = hashlib.sha256(f"{cfg.model}|{PROMPT_VERSION}|{json.dumps(facts, sort_keys=True)}".encode()).hexdigest()
    with _CACHE_LOCK:
        if key in _CACHE:
            _CACHE.move_to_end(key)
            return _CACHE[key]
        key_lock = _INFLIGHT.setdefault(key, threading.Lock())
    # 같은 캡처를 동시에 요청하면(PDF 연타 등) 모델은 한 번만 돌리고 나머지는 결과를 기다린다
    with key_lock:
        with _CACHE_LOCK:
            if key in _CACHE:
                return _CACHE[key]
        draft = None
        try:
            draft = generate_draft(facts, template_paragraphs(narrative), cfg)
        except LlmUnavailable as exc:
            logger.warning("AI 초안 생략 (로컬 모델 미가용, 템플릿 보고서 유지): model=%s %s", cfg.model, exc)
        finally:
            # 캐시 기록과 in-flight 해제를 한 번에 — 그 사이에 들어온 요청이 모델을 또 돌리지 않게
            with _CACHE_LOCK:
                if draft is not None:
                    _CACHE[key] = draft
                    while len(_CACHE) > _CACHE_MAX:
                        _CACHE.popitem(last=False)
                _INFLIGHT.pop(key, None)
        return draft
