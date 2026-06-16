"""자연어 요약 생성 — 규칙 기반 (API 비용 없음)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple

# ── MITRE ID → 방어 권고 매핑 ───────────────────────────────────────────────
_MITRE_DEFENSE: dict[str, list[str]] = {
    "T1046": [
        "Block the port-scan source IP at the firewall immediately",
        "Enable SYN scan detection rules on your IDS/IPS",
        "Close unnecessary service ports",
    ],
    "T1071": [
        "Block detected C2 domains/IPs via DNS sinkhole or firewall",
        "Review outbound traffic on non-standard ports (other than 80/443)",
        "Run an EDR agent check on suspect hosts",
    ],
    "T1498": [
        "Consider requesting DDoS mitigation from your upstream ISP",
        "Review enabling a scrubbing service (CloudFlare, AWS Shield, etc.)",
        "Apply rate-limiting rules",
    ],
    "T1041": [  # ExfiltrationDetector가 사용하는 MITRE ID
        "Isolate the source of large outbound traffic",
        "Use a DLP solution to check for sensitive data exfiltration",
        "Analyze for DNS exfiltration patterns",
    ],
    "T1110": [
        "Enable an account lockout policy on the targeted service",
        "Enforce MFA (multi-factor authentication)",
        "Set up fail2ban or similar to auto-block repeatedly failing IPs",
    ],
    "T1499": [  # CommFailureDetector
        "Investigate the source IPs during the RST spike window",
        "Review firewall ACLs and service port configuration",
        "Monitor for abnormal connection-close patterns on your IDS/IPS",
    ],
}

_ATTACK_KO: dict[str, str] = {
    "PortScan":    "Port scan",
    "Beacon":      "C2 beacon",
    "CommFailure": "Communication failure spike",
    "DDoS":        "DDoS attack",
    "Exfiltration":"Data exfiltration",
    "BruteForce":  "Brute force",
}

_ATTACK_EXPLAIN: dict[str, str] = {
    "PortScan": (
        "A port scan is reconnaissance in which an attacker sends connection "
        "attempts to many ports to identify which ports (services) are open on "
        "the target server. This lets the attacker find out which services are vulnerable."
    ),
    "Beacon": (
        "A beacon is a pattern where an already-compromised host periodically "
        "communicates with the attacker's C2 (Command & Control) server. "
        "Regularly spaced connections should raise suspicion of malware infection."
    ),
    "DDoS": (
        "A DDoS (Distributed Denial of Service) attack overwhelms a server or "
        "network with massive traffic. Its goal is service disruption."
    ),
    "Exfiltration": (
        "Exfiltration is when an attacker covertly transfers sensitive internal "
        "data to the outside. It is characterized by large outbound traffic."
    ),
    "BruteForce": (
        "Brute force is an attack that automatically tries large numbers of "
        "passwords against SSH, RDP, web logins, etc. Its goal is account takeover."
    ),
    "CommFailure": (
        "A communication failure spike can appear as a side effect of network "
        "outages, misconfiguration, or connection-based attacks. Many RST/ICMP "
        "unreachable packets occur."
    ),
}

_SEVERITY_WEIGHT: dict[str, int] = {"high": 3, "medium": 2, "low": 1}

# 공용 DNS 리졸버 — 누구나 통신하는 정상 목적지이므로 공격 대상 목록에서 제외
_PUBLIC_RESOLVERS: set[str] = {
    "8.8.8.8", "8.8.4.4",            # Google
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}

# severity → confidence 변환 (0.0~1.0)
_SEVERITY_CONFIDENCE: dict[str, float] = {"high": 0.9, "medium": 0.7, "low": 0.4}
_CONFIDENCE_THRESHOLD = 0.7  # 이 미만이면 "의심 탐지" 표현 사용


def _confidence_label(severity: str) -> str:
    """severity 기반 탐지 강도 레이블 반환."""
    conf = _SEVERITY_CONFIDENCE.get(severity.lower(), 0.5)
    if conf >= 0.8:
        return "Detected"
    elif conf >= _CONFIDENCE_THRESHOLD:
        return "Suspected"
    else:
        return "Low confidence"


def _confidence_pct(severity: str) -> int:
    """severity 기반 확신도 퍼센트 반환."""
    return int(_SEVERITY_CONFIDENCE.get(severity.lower(), 0.5) * 100)


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def _fmt_bytes(b: int) -> str:
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    if b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b} B"


class NarrativeResult(NamedTuple):
    headline: str
    narrative: str
    risk_level: str       # HIGH / MEDIUM / LOW / CLEAN
    attacker_ips: list[str]
    victim_ips: list[str]
    recommendations: list[str]
    attack_timeline: list[dict]
    attack_explanations: dict[str, str]  # attack_type → 초보자 설명 (영문)


def build_summary(attacks: list, sessions: list) -> NarrativeResult:
    """attacks: list of AttackEntry dicts (from analyze endpoint, includes src_ip)
    sessions: list of SessionModel objects or dicts"""

    if not attacks:
        return NarrativeResult(
            headline="Normal traffic — no anomalous events",
            narrative=(
                "No known anomaly patterns were detected in the analyzed capture file. "
                "It appears to be ordinary network traffic."
            ),
            risk_level="CLEAN",
            attacker_ips=[],
            victim_ips=[],
            recommendations=["Keep up regular pcap capture and monitoring"],
            attack_timeline=[],
            attack_explanations={},
        )

    # ── 위험도 계산 ──────────────────────────────────────────────────────
    max_weight = max(_SEVERITY_WEIGHT.get(str(a.get("severity", "low")).lower(), 1) for a in attacks)
    risk = "HIGH" if max_weight >= 3 else "MEDIUM" if max_weight >= 2 else "LOW"

    # ── 공격자 IP 추출 (B1 fix: src_ip 필드 사용) ─────────────────────────
    attacker_ips: list[str] = []
    for a in attacks:
        ip = a.get("src_ip") or ""
        if ip and ip not in attacker_ips:
            attacker_ips.append(ip)

    # ── 피해자 IP 추론 — 공격자→피해자 방향 세션에서 추출 ────────────────
    victim_ips: list[str] = []
    if attacker_ips and sessions:
        for s in sessions:
            if isinstance(s, dict):
                src, dst = s.get("src_ip", ""), s.get("dst_ip", "")
            else:
                src, dst = getattr(s, "src_ip", ""), getattr(s, "dst_ip", "")
            if dst in _PUBLIC_RESOLVERS:
                continue
            if src in attacker_ips and dst and dst not in victim_ips and dst not in attacker_ips:
                victim_ips.append(dst)
    victim_ips = victim_ips[:5]

    # ── 공격 유형 집계 (confidence >= 0.7 기준 분류) ──────────────────────
    attack_type_set = sorted({a.get("attack_type", "Unknown") for a in attacks})

    # 공격별 확신도 레이블 계산
    confirmed_types = [t for a in attacks
                       if _SEVERITY_CONFIDENCE.get(str(a.get("severity", "low")).lower(), 0.5) >= _CONFIDENCE_THRESHOLD
                       for t in [a.get("attack_type", "Unknown")]]
    suspected_types = [a.get("attack_type", "Unknown") for a in attacks
                       if _SEVERITY_CONFIDENCE.get(str(a.get("severity", "low")).lower(), 0.5) < _CONFIDENCE_THRESHOLD]

    def _attack_label(a: dict) -> str:
        ko = _ATTACK_KO.get(a.get("attack_type", "Unknown"), a.get("attack_type", "Unknown"))
        conf = _confidence_pct(str(a.get("severity", "low")))
        label = _confidence_label(str(a.get("severity", "low")))
        return f"{ko} {label} (confidence: {conf}%)"

    attack_ko = " + ".join(_ATTACK_KO.get(t, t) for t in attack_type_set)

    # ── 타임라인 (세션 시작/종료 기준으로 이벤트 시각 배치) ──────────────
    min_ts = 0.0
    max_ts = 0.0
    if sessions:
        ts_vals = []
        for s in sessions:
            if isinstance(s, dict):
                ts_vals.append(s.get("start_ts", 0.0))
                ts_vals.append(s.get("end_ts", 0.0))
            else:
                ts_vals.append(getattr(s, "start_ts", 0.0))
                ts_vals.append(getattr(s, "end_ts", 0.0))
        valid = [t for t in ts_vals if t > 0]
        if valid:
            min_ts = min(valid)
            max_ts = max(valid)

    n = max(len(attacks), 1)
    attack_timeline = []
    for i, a in enumerate(attacks):
        if min_ts > 0:
            ts = min_ts + (max_ts - min_ts) * i / n
        else:
            ts = 0.0  # 세션 타임스탬프 없음 — 프론트에서 "—" 표시
        attack_timeline.append({
            "ts": ts,
            "attack_type": a.get("attack_type", "Unknown"),
            "severity": a.get("severity", "low"),
            "mitre_id": a.get("mitre_id", ""),
            "description": a.get("description", ""),
            "src_ip": a.get("src_ip", ""),
        })

    # ── 내러티브 생성 ──────────────────────────────────────────────────────
    time_range = ""
    if min_ts > 0 and max_ts > 0:
        time_range = f"Between {_fmt_ts(min_ts)} and {_fmt_ts(max_ts)}, "

    attacker_str = ", ".join(attacker_ips[:3]) if attacker_ips else "an unknown host"
    victim_str   = ", ".join(victim_ips[:3])   if victim_ips   else "internal servers"

    total_bytes = sum(
        (s.get("bytes_sent", 0) + s.get("bytes_recv", 0)) if isinstance(s, dict)
        else (getattr(s, "bytes_sent", 0) + getattr(s, "bytes_recv", 0))
        for s in sessions
    ) if sessions else 0

    # 메인 문장
    main_sentence = (
        f"{time_range}{attacker_str} carried out {attack_ko} activity "
        f"against {victim_str}."
    )
    stat_sentence = (
        f"Analyzed {_fmt_bytes(total_bytes)} of traffic across {len(sessions)} sessions."
        if sessions else ""
    )
    # 탐지 상세 줄 (각 공격별 — 확신도 포함)
    detail_lines = [
        f"• {_attack_label(a)}: {a.get('description', '')}"
        for a in attacks if a.get("description")
    ]

    parts = [main_sentence]
    if stat_sentence:
        parts.append(stat_sentence)
    if detail_lines:
        parts.extend(detail_lines)
    narrative = "\n".join(parts)

    # ── 방어 권고 생성 ─────────────────────────────────────────────────────
    recommendations: list[str] = []
    seen: set[str] = set()
    for a in attacks:
        for rec in _MITRE_DEFENSE.get(a.get("mitre_id", ""), []):
            if rec not in seen:
                recommendations.append(rec)
                seen.add(rec)
    if not recommendations:
        recommendations.append("Block the detected attacker IPs at the firewall")

    # ── 초보자 설명 ────────────────────────────────────────────────────────
    attack_explanations = {
        t: _ATTACK_EXPLAIN.get(t, f"A {t} attack was detected.")
        for t in attack_type_set
    }

    # 헤드라인: 확신도 낮은 공격이 섞여 있으면 "의심 포함" 표시
    has_suspected = bool(suspected_types)
    headline_suffix = " (incl. suspected)" if has_suspected and confirmed_types else (" suspected" if has_suspected else "")
    return NarrativeResult(
        headline=f"{attack_ko} detected{headline_suffix} — {risk} risk",
        narrative=narrative,
        risk_level=risk,
        attacker_ips=attacker_ips,
        victim_ips=victim_ips,
        recommendations=recommendations,
        attack_timeline=attack_timeline,
        attack_explanations=attack_explanations,
    )
