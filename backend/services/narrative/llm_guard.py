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

# 단어 숫자: 값이 입력에 있으면 허용("two C2 beacons" + findings 2건), 없거나 큰 단위면 위반
_NUMBER_WORDS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen "
    "sixteen seventeen eighteen nineteen twenty".split())}
_NUMBER_WORDS.update({"thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90})
_TENS = "twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety"
_UNITS = "one|two|three|four|five|six|seven|eight|nine"
_COMPOUND_RE = re.compile(rf"\b({_TENS})[- ]({_UNITS})\b", re.I)       # forty-two → 42
_SIMPLE_WORD_RE = re.compile(
    r"\b(two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|"
    rf"sixteen|seventeen|eighteen|nineteen|{_TENS})\b", re.I)
# 크기 단위 단어는 값으로 대조할 수 없으므로 금지 ("nine thousand sessions")
_NUMBER_WORDS_RE = re.compile(r"\b(hundreds?|thousands?|millions?|billions?|dozens?)\b", re.I)
# "October 29, 2026" / "29 October 2026" → ISO 로 바꿔 날짜 검사 (풀어 쓴 날짜는 정상 표현)
_MONTHS = {m: i for i, m in enumerate(
    "january february march april may june july august september october november december".split(), 1)}
_MONTH_DATE_RES = [
    re.compile(r"\b(january|february|march|april|may|june|july|august|september|october|november|december)"
               r"\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b", re.I),
    re.compile(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+(january|february|march|april|may|june|july|august|september|"
               r"october|november|december),?\s+(\d{4})\b", re.I),
]
# 내부/외부 라벨과 IP 대역 대조 (eval 05: 8B 가 사설 IP 를 external, 공인 IP 를 internal 로 뒤집음)
# (대역을 "10/8" 처럼 쓰면 ADR-005 보안 grep(전체 바인딩 문자열 금지)과 충돌하므로 호스트 비트를 둔 표기 + strict=False)
_INTERNAL_NETS = [ipaddress.ip_network(n, strict=False) for n in (
    "10.255.255.255/8", "172.16.255.255/12", "192.168.255.255/16", "100.64.255.255/10", "127.255.255.255/8",
    "169.254.255.255/16", "fc00::/7", "fe80::/10", "::1/128")]
_LABEL = r"(internal|private|local|external|public|remote|internet-facing)"
_IP_TOK = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})"
# 라벨이 직접 수식하는 IP 만 본다: "external hosts (10.0.0.31, 10.0.0.44)", "internal host 10.0.0.15"
_LABEL_THEN_IPS_RE = re.compile(
    rf"\b{_LABEL}\s+(?:[A-Za-z-]+\s+){{0,2}}\(?\s*({_IP_TOK}(?:\s*(?:,|and|,\s*and)\s*{_IP_TOK})*)", re.I)
# "10.0.0.15 is external", "203.0.113.9 as an internal host"
_IP_IS_LABEL_RE = re.compile(rf"({_IP_TOK})\s+(?:is|was|as)\s+(?:an?\s+|the\s+)?{_LABEL}\b", re.I)
# 입력에 없는 지표 이름 (eval 04: CV 3.2% 를 'confidence level of 3.2%' 로 바꿔 부름)
_UNSUPPORTED_METRICS_RE = re.compile(r"\b(confidence|probability|accuracy|certainty)\b", re.I)
# 침해 언급은 완곡 표현(may/possible/consistent with …)이 앞에 있을 때만 허용 (eval 12: "The compromised host …")
_COMPROMISE_RE = re.compile(r"\bcompromis\w*", re.I)
_HEDGE_RE = re.compile(r"\b(may|might|could|possibl\w*|potential\w*|suspect\w*|consistent with|suggest\w*|"
                       r"indicat\w*|whether|check\w* for|signs? of|risk of|no|not|without)\b", re.I)
_NEGATION_RE = re.compile(r"\b(no|not|without|nor)\b", re.I)
# "70 out of 100", "70/100" 의 100 은 척도라 숫자 검사에서 뺀다
_SCALE_RE = re.compile(r"\s*(?:out of|/)\s*100\b", re.I)
# 출력 형식이 본문에 새어 나온 경우 ("The finding_ids for this narrative are [F1]")
_FORMAT_LEAK_RE = re.compile(r"finding_ids?|\"text\"|executive_summary|incident_narrative|[{}]", re.I)

# 공격 유형·행위 주장은 입력(탐지 결과)에 근거가 있을 때만 — 3B 모델이 실제로
# 평범한 웹 트래픽을 "lateral movement" 라고 지어낸 사례가 있었다 (eval 04)
_THREAT_CLAIMS = [
    (re.compile(r"\blateral\b", re.I), ("lateral",)),
    (re.compile(r"exfiltrat|data theft|data leak", re.I), ("exfiltration",)),
    (re.compile(r"\b(c2|command[- ]and[- ]control|beacon\w*)\b", re.I), ("beacon", "c2")),
    (re.compile(r"brute[- ]?forc|password (guess|spray)|credential", re.I), ("brute force",)),
    (re.compile(r"\bscan\w*|reconnaissance|\brecon\b", re.I), ("scan",)),
    (re.compile(r"\bd?dos\b|denial[- ]of[- ]service|\bflood\w*", re.I), ("ddos", "flood", "dos")),
    (re.compile(r"ransomware|malware|trojan|botnet|cryptomin|phishing|rootkit|backdoor|worm\b", re.I), ("malware",)),
    # WireBoard 가 탐지하지 않는 유형 — 입력에 근거가 생길 수 없다 (tunnel 은 IPsec 등 일반 용어라 제외)
    (re.compile(r"privilege escalation|\bpersistence\b|sql injection|\bxss\b", re.I), ("__never__",)),
    # 장악 단정 표현 (eval 리뷰: "taken over by an attacker", "has been hacked")
    (re.compile(r"taken over|\bhacked\b|attacker[- ]controlled|under (?:the )?(?:attacker'?s? )?control", re.I), ("__never__",)),
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
# ID 처럼 생겼지만 흔한 제품·프로토콜 이름 (F5 로드밸런서, AWS S3, HTTP/2 ALPN h2, h3)
_ID_LOOKALIKES = {"F5", "S3", "H2", "H3"}
_MITRE_RE = re.compile(r"\bTA?\d{4}(?:\.\d{3})?\b", re.I)
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
_IPV6_CAND_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
# 시각·날짜는 숫자 단위가 아니라 통째로 대조한다 (01:49:33 → 02:49:33 재조합 방지)
_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_TIME_RE = re.compile(r"(?<![\d.])\d{1,2}:\d{2}(?::\d{2})?\b")  # IP:포트(192.0.2.53:53)의 53:53 은 시각 아님
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
        stats = facts.get("stats") if isinstance(facts.get("stats"), dict) else {}
        dur = stats.get("duration_seconds")
        if isinstance(dur, (int, float)):
            self.units.add((float(dur), "s"))
            # 정확히 나누어떨어지는 환산만 허용 (120초 → "2 minutes")
            for div, unit in ((60, "min"), (3600, "h")):
                if dur and dur % div == 0:
                    self.units.add((float(dur // div), unit))
                    self.numbers.add(float(dur // div))
        self.domains = {d.lower() for d in _DOMAIN_RE.findall(_IPV4_RE.sub(" ", blob))}
        self.hashes = {h.lower() for h in _HASH_RE.findall(blob)}
        self.ip_ports = _ip_port_pairs(blob)
        for t in facts.get("top_talkers") or []:
            if not isinstance(t, dict):
                continue
            for p in t.get("destination_ports") or []:
                if isinstance(p, int):
                    self.ip_ports.add((str(t.get("destination")), p))


def _same_sentence_before(text: str, pos: int, width: int) -> str:
    """pos 앞 width 글자 중 같은 문장 부분만 (완곡·부정 표현이 앞 문장에서 넘어오지 않게)."""
    window = text[max(0, pos - width):pos]
    cut = max(window.rfind(". "), window.rfind("; "), window.rfind("! "), window.rfind("? "))
    return window[cut + 2:] if cut >= 0 else window


def _is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr.version == n.version and addr in n for n in _INTERNAL_NETS)


def _iso_dates(text: str) -> str:
    def md(m):
        return f"{m.group(3)}-{_MONTHS[m.group(1).lower()]:02d}-{int(m.group(2)):02d}"

    def dm(m):
        return f"{m.group(3)}-{_MONTHS[m.group(2).lower()]:02d}-{int(m.group(1)):02d}"
    text = _MONTH_DATE_RES[0].sub(md, text)
    text = _MONTH_DATE_RES[1].sub(dm, text)
    # 단어 숫자 → 숫자: 이후 숫자·단위 검사를 그대로 받게 한다 ("two beacons" → "2 beacons")
    text = _COMPOUND_RE.sub(lambda m: str(_NUMBER_WORDS[m.group(1).lower()] + _NUMBER_WORDS[m.group(2).lower()]), text)
    return _SIMPLE_WORD_RE.sub(lambda m: str(_NUMBER_WORDS[m.group(1).lower()]), text)


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
    t = _iso_dates(text.strip())
    if _FORMAT_LEAK_RE.search(t):
        v.append("output format leaked into text")
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
    bad_inline = sorted({i.upper() for i in _ID_RE.findall(t)
                         if i.upper() not in idx.ids and i.upper() not in _ID_LOOKALIKES})
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

    # 내부/외부 라벨 ↔ IP 대역: 라벨 뒤 같은 절(마침표·세미콜론·다음 라벨 전)의 IP 들을 대조
    mislabeled = []
    pairs = [(m.group(1), ips) for m in _LABEL_THEN_IPS_RE.finditer(t)
             for ips in [re.findall(_IP_TOK, m.group(2))]]
    pairs += [(m.group(2), [m.group(1)]) for m in _IP_IS_LABEL_RE.finditer(t)]
    for label, ips in pairs:
        want_internal = label.lower() in ("internal", "private", "local")
        for cand in ips:
            ip = _parse_ip(cand)
            if ip and _is_internal(ip) != want_internal:
                mislabeled.append(f"{ip} as {label.lower()}")
    if mislabeled:
        v.append(f"internal/external mislabel: {', '.join(sorted(set(mislabeled))[:4])}")

    metrics = sorted({w.lower() for w in _UNSUPPORTED_METRICS_RE.findall(t) if w.lower() not in idx.text})
    if metrics:
        v.append(f"metric not in input: {', '.join(metrics)}")

    unhedged = [m.group(0) for m in _COMPROMISE_RE.finditer(t)
                if not _HEDGE_RE.search(_same_sentence_before(t, m.start(), 80))]
    if unhedged:
        v.append(f"unhedged compromise claim: {', '.join(unhedged[:3])}")

    # 근거 없는 공격 유형 주장
    claims = sorted({m.group(0).lower() for rx, need in _THREAT_CLAIMS for m in rx.finditer(t)
                     if not any(k in idx.text for k in need)
                     and not _NEGATION_RE.search(_same_sentence_before(t, m.start(), 25))})
    if claims:
        v.append(f"threat claims not in input: {', '.join(claims[:5])}")

    # 도메인
    bad_dom = [d for d in _DOMAIN_RE.findall(_IPV4_RE.sub(" ", t))
               if d.lower() not in _NOT_DOMAINS and d.lower() not in idx.domains]
    if bad_dom:
        v.append(f"domains not in input: {', '.join(sorted(set(bad_dom))[:5])}")

    # 숫자 (포트·바이트·횟수 포함) — 시각·IP·ID 등은 위에서 따로 검사하고 지운 뒤
    plain = _strip_tokens(_DOMAIN_RE.sub(" ", _SCALE_RE.sub(" ", t)))
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
    # 같은 문장 앞쪽에 부정어가 있으면 제외 ("no evidence that X was compromised")
    hits = [p for p in BANNED_PHRASES
            if any(not _NEGATION_RE.search(_same_sentence_before(low, i, 50))
                   for i in (m.start() for m in re.finditer(re.escape(p), low)))]
    if hits:
        v.append(f"banned assertive wording: {', '.join(hits[:3])}")
    return v
