"""llm_guard — LLM 이 쓴 보고서 문단의 환각 검사 (코드 규칙, 모델 판단 없음).

문단이 입력 사실(facts JSON)에 없는 IP·숫자·도메인·해시·MITRE ID 를 쓰거나,
존재하지 않는 finding ID 를 인용하거나, 단정 표현을 쓰면 위반으로 본다.
위반이 하나라도 있으면 호출부(llm_draft)가 그 문단을 버리고 템플릿 문장으로 대체한다.
"""
from __future__ import annotations

import ipaddress
import json
import re

# 단정 표현 금지 목록 — 패킷 분석만으로는 침해를 확정할 수 없다
BANNED_PHRASES = (
    "definitely", "certainly", "undoubtedly", "without a doubt", "without doubt",
    "guaranteed", "proves that", "proof of compromise", "confirmed compromise",
    "confirmed breach", "is compromised", "has been compromised", "was compromised",
    "were compromised", "fully compromised", "100% sure", "100% certain",
    "breach", "extent of the compromise", "the compromise",
    "is infected", "are infected", "was infected", "were infected", "has been infected",
    "confirmed infection", "confirmed attack", "clearly", "no doubt", "beyond doubt",
    "확실히", "틀림없이", "침해됨", "침해되었", "침해가 확인", "감염됨", "감염되었",
)

# 숫자를 단어로 쓰면 대조할 수 없으므로 금지 ("forty-two hosts")
_NUMBER_WORDS_RE = re.compile(
    r"\b(two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|"
    r"sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|"
    r"hundreds?|thousands?|millions?|billions?|dozens?)\b", re.I)

# 공격 유형·행위 주장은 입력(탐지 결과)에 근거가 있을 때만 — 3B 모델이 실제로
# 평범한 웹 트래픽을 "lateral movement" 라고 지어낸 사례가 있었다 (eval 04)
_THREAT_CLAIMS = [
    (re.compile(r"lateral movement|lateral", re.I), ("lateral",)),
    (re.compile(r"exfiltrat|data theft|data leak", re.I), ("exfiltration",)),
    (re.compile(r"\b(c2|command[- ]and[- ]control|beacon\w*)\b", re.I), ("beacon", "c2")),
    (re.compile(r"brute[- ]?forc|password (guess|spray)|credential", re.I), ("brute force",)),
    (re.compile(r"\bscan\w*|reconnaissance|\brecon\b", re.I), ("scan",)),
    (re.compile(r"\bd?dos\b|denial[- ]of[- ]service|\bflood\w*", re.I), ("ddos", "flood", "dos")),
    (re.compile(r"ransomware|malware|trojan|botnet|cryptomin|phishing|rootkit|backdoor|worm\b", re.I), ("malware",)),
    (re.compile(r"privilege escalation|persistence|sql injection|\bxss\b|tunnel\w*", re.I), ("__never__",)),
]
# IP:포트 / "port N on IP" 쌍 — 숫자 자체는 입력에 있어도 엉뚱한 자리에 쓰면 위반
# (eval 11: "스캔한 포트 수 1024" 를 "10.0.0.15:1024" 로 씀)
_IP_PORT_RES = [
    re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b"),
    re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}) (?:on )?port (\d{1,5})\b", re.I),
]
_PORT_ON_IP_RE = re.compile(r"\bport (\d{1,5}) (?:on|of|at) ((?:\d{1,3}\.){3}\d{1,3})(?![\d.]*\d)", re.I)

MIN_CHARS = 40
MAX_CHARS = 1200

_ID_RE = re.compile(r"\b([FHPS]\d{1,3})\b", re.I)
_MITRE_RE = re.compile(r"\bTA?\d{4}(?:\.\d{3})?\b", re.I)
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
_IPV6_CAND_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
# 시각·날짜는 숫자 단위가 아니라 통째로 대조한다 (01:49:33 → 02:49:33 재조합 방지)
_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_TIME_RE = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")
# 숫자 앞 글자는 허용(port4444, x_7777 도 검사 대상) — 앞이 숫자/점이면 이미 다른 숫자의 일부
_NUM_RE = re.compile(r"(?<![\d.])\d+(?:,\d{3})*(?:\.\d+)?")
# 숫자+단위 쌍은 단위까지 맞아야 한다 ("1.4 GB" 가 입력이면 "1.4 TB" 는 위반)
_UNIT_RE = re.compile(
    r"(?<![\d.])(\d+(?:,\d{3})*(?:\.\d+)?)\s*(%|(?:bytes?|[kmgt]i?b|b|pps|ms|secs?|seconds?|s|minutes?|min|hours?|h|days?)\b)", re.I)
_UNIT_CANON = {
    "byte": "b", "bytes": "b", "b": "b", "kb": "kb", "kib": "kb", "mb": "mb", "mib": "mb",
    "gb": "gb", "gib": "gb", "tb": "tb", "tib": "tb", "pps": "pps", "ms": "ms",
    "s": "s", "sec": "s", "secs": "s", "second": "s", "seconds": "s",
    "min": "min", "minute": "min", "minutes": "min", "h": "h", "hour": "h", "hours": "h",
    "day": "d", "days": "d", "%": "%",
}
# 도메인처럼 생긴 흔한 약어 (도메인 오탐 방지)
_NOT_DOMAINS = {"e.g", "i.e", "etc", "vs"}


def _norm_num(tok: str) -> float | None:
    try:
        return float(tok.replace(",", ""))
    except ValueError:
        return None


def _unit_pairs(text: str) -> set[tuple]:
    return {(_norm_num(n), _UNIT_CANON[u.lower()]) for n, u in _UNIT_RE.findall(text)}


class FactIndex:
    """facts JSON 에서 '쓸 수 있는 값' 집합을 미리 뽑아둔다."""

    def __init__(self, facts: dict):
        blob = json.dumps(facts, ensure_ascii=False)
        self.text = blob.lower()
        self.ids = set(collect_ids(facts))
        self.mitre = {m.upper() for m in _MITRE_RE.findall(blob)}
        self.ips: set[str] = set()
        for cand in _IPV4_RE.findall(blob) + _IPV6_CAND_RE.findall(blob):
            ip = _parse_ip(cand)
            if ip:
                self.ips.add(ip)
        self.dates = set(_DATE_RE.findall(blob))
        self.times: set[str] = set()
        for tm in _TIME_RE.findall(blob):
            h, rest = tm.split(":", 1)
            self.times |= {f"{int(h)}:{rest}", f"{int(h)}:{rest[:2]}"}  # 01:49:33 → 1:49:33, 1:49 허용
        stripped = _strip_tokens(blob)
        self.numbers = {n for n in (_norm_num(t) for t in _NUM_RE.findall(stripped)) if n is not None}
        self.units = _unit_pairs(stripped)
        dur = (facts.get("stats") or {}).get("duration_seconds")
        if isinstance(dur, (int, float)):
            self.units.add((float(dur), "s"))
        self.domains = {d.lower() for d in _DOMAIN_RE.findall(_IPV4_RE.sub(" ", blob))}
        self.hashes = {h.lower() for h in _HASH_RE.findall(blob)}
        self.ip_ports = _ip_port_pairs(blob)
        for t in facts.get("top_talkers") or []:
            for p in t.get("destination_ports") or []:
                self.ip_ports.add((str(t.get("destination")), int(p)))


def _ip_port_pairs(text: str) -> set[tuple]:
    pairs = {(ip, int(p)) for r in _IP_PORT_RES for ip, p in r.findall(text)}
    pairs |= {(ip, int(p)) for p, ip in _PORT_ON_IP_RE.findall(text)}
    return pairs


def collect_ids(facts: dict) -> list[str]:
    ids = []
    for section in ("findings", "health", "top_talkers", "stats"):
        items = facts.get(section) or []
        if isinstance(items, dict):
            items = [items]
        ids += [i["id"] for i in items if isinstance(i, dict) and i.get("id")]
    return ids


def _parse_ip(tok: str) -> str | None:
    try:
        return str(ipaddress.ip_address(tok.strip("[]()")))
    except ValueError:
        return None


def _strip_tokens(text: str) -> str:
    """숫자 검사 전에 IP·ID·MITRE·해시처럼 자체 검사되는 토큰을 지운다."""
    text = _DATE_RE.sub(" ", text)
    text = _TIME_RE.sub(" ", text)
    text = _HASH_RE.sub(" ", text)
    text = _MITRE_RE.sub(" ", text)
    text = _IPV4_RE.sub(" ", text)
    text = _IPV6_CAND_RE.sub(lambda m: " " if _parse_ip(m.group(0)) else m.group(0), text)
    text = _ID_RE.sub(" ", text)
    return text


def check_paragraph(text: str, finding_ids: list, facts_or_index) -> list[str]:
    """위반 사유 목록. 빈 목록이면 통과."""
    idx = facts_or_index if isinstance(facts_or_index, FactIndex) else FactIndex(facts_or_index)
    v: list[str] = []
    if not isinstance(text, str) or not text.strip():
        return ["empty paragraph"]
    t = text.strip()
    if len(t) < MIN_CHARS:
        v.append(f"too short ({len(t)} chars)")
    if len(t) > MAX_CHARS:
        v.append(f"too long ({len(t)} chars)")
    non_ascii = sum(1 for c in t if ord(c) > 127 and c not in "–—’‘“”…•·→")
    if non_ascii > len(t) * 0.05:
        v.append("not English (report is ASCII/English)")

    # 인용 ID
    if not isinstance(finding_ids, list) or not finding_ids:
        v.append("no finding IDs cited")
    else:
        bad = [str(i) for i in finding_ids if str(i) not in idx.ids]
        if bad:
            v.append(f"cites unknown finding IDs: {', '.join(bad[:5])}")
    bad_inline = sorted({i.upper() for i in _ID_RE.findall(t) if i.upper() not in idx.ids})
    if bad_inline:
        v.append(f"mentions unknown IDs in text: {', '.join(bad_inline[:5])}")

    # MITRE
    bad_mitre = sorted({m.upper() for m in _MITRE_RE.findall(t)} - idx.mitre)
    if bad_mitre:
        v.append(f"MITRE IDs not in input: {', '.join(bad_mitre[:5])}")

    # 시각·날짜
    bad_dt = [d for d in _DATE_RE.findall(t) if d not in idx.dates]
    for tm in _TIME_RE.findall(t):
        h, rest = tm.split(":", 1)
        if f"{int(h)}:{rest}" not in idx.times:
            bad_dt.append(tm)
    if bad_dt:
        v.append(f"times/dates not in input: {', '.join(sorted(set(bad_dt))[:5])}")

    # 해시
    bad_hash = [h for h in _HASH_RE.findall(t) if h.lower() not in idx.hashes]
    if bad_hash:
        v.append(f"hashes not in input: {', '.join(h[:12] + '…' for h in bad_hash[:3])}")

    # IP
    bad_ips = []
    for cand in _IPV4_RE.findall(t) + _IPV6_CAND_RE.findall(t):
        ip = _parse_ip(cand)
        if cand.count(".") == 3 and ip is None:
            bad_ips.append(cand)          # 999.1.2.3 같은 가짜 IPv4
        elif ip and ip not in idx.ips:
            bad_ips.append(ip)
    if bad_ips:
        v.append(f"IPs not in input: {', '.join(sorted(set(bad_ips))[:5])}")

    # IP:포트 쌍
    bad_pairs = sorted(f"{ip}:{p}" for ip, p in _ip_port_pairs(t) - idx.ip_ports)
    if bad_pairs:
        v.append(f"IP:port not in input: {', '.join(bad_pairs[:5])}")

    # 근거 없는 공격 유형 주장
    claims = sorted({m.group(0).lower() for rx, need in _THREAT_CLAIMS for m in [rx.search(t)]
                     if m and not any(k in idx.text for k in need)})
    if claims:
        v.append(f"threat claims not in input: {', '.join(claims[:5])}")

    # 도메인
    bad_dom = [d for d in _DOMAIN_RE.findall(_IPV4_RE.sub(" ", t))
               if d.lower() not in _NOT_DOMAINS and d.lower() not in idx.domains]
    if bad_dom:
        v.append(f"domains not in input: {', '.join(sorted(set(bad_dom))[:5])}")

    # 숫자 (포트·바이트·횟수 포함) — 시각·IP·ID 등은 위에서 따로 검사하고 지운 뒤
    plain = _strip_tokens(_DOMAIN_RE.sub(" ", t))
    bad_nums = []
    for tok in _NUM_RE.findall(plain):
        n = _norm_num(tok)
        if n is not None and n not in idx.numbers:
            bad_nums.append(tok)
    if bad_nums:
        v.append(f"numbers not in input: {', '.join(sorted(set(bad_nums))[:6])}")
    bad_units = sorted(f"{n:g} {u}" for n, u in _unit_pairs(plain) - idx.units if n in idx.numbers)
    if bad_units:
        v.append(f"number/unit not in input: {', '.join(bad_units[:5])}")
    words = sorted({w.lower() for w in _NUMBER_WORDS_RE.findall(t)})
    if words:
        v.append(f"numbers written as words: {', '.join(words[:5])}")

    # 단정 표현
    low = t.lower()
    hits = [p for p in BANNED_PHRASES if p in low]
    if hits:
        v.append(f"banned assertive wording: {', '.join(hits[:3])}")
    return v
