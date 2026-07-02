"""Rule-based narrative + risk scoring (no API cost).

Produces a defensible risk grade backed by an explicit factor breakdown, and an
evidence-based auto-diagnosis that describes what happened in the capture even
when NO attack was detected (connectivity failures, latency, retransmissions).

`build_summary` optionally consumes a network-health analysis dict (from
services.analytics.network_health.analyze) so that a capture full of failed
connections is never mislabeled as "normal traffic".
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple, Optional

# ── MITRE ID → defense recommendations ──────────────────────────────────────
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
    "T1041": [  # ExfiltrationDetector
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

# Public DNS resolvers — legitimate destinations, excluded from victim lists.
_PUBLIC_RESOLVERS: set[str] = {
    "8.8.8.8", "8.8.4.4",            # Google
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}

# severity → confidence (0.0~1.0)
_SEVERITY_CONFIDENCE: dict[str, float] = {"high": 0.9, "medium": 0.7, "low": 0.4}
_CONFIDENCE_THRESHOLD = 0.7  # below this → "suspected" phrasing

# risk grade ladder (order matters for _max_level)
_LEVEL_ORDER = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

# Minimum session count before network-health signals may raise the risk grade.
# Guards against tiny/synthetic captures (a single SYN-only session) tripping the
# grade on incomplete evidence.
_HEALTH_MIN_SESSIONS = 8

# Points contributed to the 0-100 risk score.
_ATTACK_BASE_POINTS = {"high": 45, "medium": 25, "low": 10}
_HEALTH_LEVEL_POINTS = {"HIGH": 40, "MEDIUM": 22, "LOW": 10, "CLEAN": 0}


def _confidence_label(severity: str) -> str:
    conf = _SEVERITY_CONFIDENCE.get(severity.lower(), 0.5)
    if conf >= 0.8:
        return "Detected"
    elif conf >= _CONFIDENCE_THRESHOLD:
        return "Suspected"
    else:
        return "Low confidence"


def _confidence_pct(severity: str) -> int:
    return int(_SEVERITY_CONFIDENCE.get(severity.lower(), 0.5) * 100)


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def _fmt_bytes(b: int) -> str:
    if b >= 1_000_000_000:
        return f"{b / 1_000_000_000:.1f} GB"
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    if b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b} B"


def _severity_to_level(severity: str) -> str:
    w = _SEVERITY_WEIGHT.get(str(severity).lower(), 1)
    return "HIGH" if w >= 3 else "MEDIUM" if w >= 2 else "LOW"


def _max_level(a: str, b: str) -> str:
    return a if _LEVEL_ORDER.get(a, 0) >= _LEVEL_ORDER.get(b, 0) else b


def _sget(s, key, default=0):
    """Read a field from a session that may be a dict or a SessionModel."""
    if isinstance(s, dict):
        return s.get(key, default)
    return getattr(s, key, default)


# ── network-health interpretation ───────────────────────────────────────────

def _health_level(health: Optional[dict]) -> str:
    """Map a network_health.analyze() dict to a risk grade contribution.

    Conservative: only elevates when there is a meaningful volume of sessions
    AND a real failure/critical ratio, so normal or tiny captures stay CLEAN.

    Critical-ratio is the primary signal (it already encodes multiple
    corroborating symptoms per session). failure_summary counts are used as a
    secondary signal ONLY when the capture has real packet data — for
    packet-less text logs (FortiGate verbose 3 / plain tcpdump lines) an RST
    flag cannot distinguish "refused" from a normal RST teardown, so counting
    them as hard failures would mislabel healthy traffic.
    """
    if not health:
        return "CLEAN"
    total = health.get("total_sessions", 0)
    if total < _HEALTH_MIN_SESSIONS:
        return "CLEAN"
    critical = health.get("critical", 0)
    warning = health.get("warning", 0)
    crit_ratio = critical / total
    warn_ratio = warning / total

    # failure counts are trustworthy only when most sessions carry packet data
    packetless = health.get("packetless_sessions", 0)
    fail_ratio = 0.0
    if packetless / total < 0.5:
        fs = health.get("failure_summary", {}) or {}
        hard_fail = (
            fs.get("connection_refused", 0)
            + fs.get("no_response", 0)
            + fs.get("path_issue", 0)
        )
        fail_ratio = hard_fail / total

    if crit_ratio >= 0.5 or fail_ratio >= 0.6:
        return "HIGH"
    if crit_ratio >= 0.25 or fail_ratio >= 0.3:
        return "MEDIUM"
    if crit_ratio >= 0.10 or fail_ratio >= 0.1 or warn_ratio >= 0.5:
        return "LOW"
    return "CLEAN"


_FAILURE_PHRASE = {
    "connection_refused": "connection(s) were refused (server sent RST)",
    "no_response":        "connection(s) got no response (SYN timeout / half-open)",
    "path_issue":         "connection(s) hit a path problem (ICMP unreachable / TTL exceeded)",
    "slow_response":      "connection(s) were slow (RTT over 1s)",
}


def _health_findings(health: Optional[dict]) -> list[str]:
    """Human-readable diagnosis lines from the network-health summary."""
    if not health or health.get("total_sessions", 0) == 0:
        return []
    findings: list[str] = []
    total = health["total_sessions"]
    # "network vs application" verdict leads the diagnosis — it decides who to page
    v = health.get("verdict") or {}
    if v.get("side") and v["side"] != "none":
        findings.append(v.get("headline", ""))
    fs = health.get("failure_summary", {}) or {}
    for ftype, phrase in _FAILURE_PHRASE.items():
        n = fs.get(ftype, 0)
        if n:
            pct = round(n / total * 100)
            findings.append(f"{n} of {total} {phrase} ({pct}%).")
    # retransmission / latency issues surfaced by network_health top_issues
    # ("retransmi" matches both "retransmit rate" and "Retransmissions detected")
    for item in (health.get("top_issues") or []):
        issue = item.get("issue", "")
        low = issue.lower()
        if "retransmi" in low or "rtt" in low or "latency" in low:
            findings.append(f"{item.get('count', 0)} session(s): {issue}")
    # capture-quality caveats last — they qualify how much to trust the above
    for w in (health.get("capture_quality", {}) or {}).get("warnings", [])[:2]:
        findings.append(f"[capture quality] {w}")
    return findings


class NarrativeResult(NamedTuple):
    headline: str
    narrative: str
    risk_level: str       # HIGH / MEDIUM / LOW / CLEAN
    attacker_ips: list[str]
    victim_ips: list[str]
    recommendations: list[str]
    attack_timeline: list[dict]
    attack_explanations: dict[str, str]
    # ── added: defensible scoring + evidence-based diagnosis ────────────────
    risk_score: int = 0                     # 0-100 severity indicator
    risk_factors: list[dict] = []           # [{factor, detail, points}]
    diagnosis: list[str] = []               # network-health findings (plain English)
    key_findings: list[str] = []            # top bullets (attacks + health + traffic)
    health_overview: dict = {}              # compact health snapshot for the report


def _traffic_overview(sessions: list) -> dict:
    """Aggregate top-level traffic stats used across the narrative and report."""
    if not sessions:
        return {}
    total_bytes = 0
    proto_counts: dict[str, int] = {}
    pair_bytes: dict[tuple, int] = {}
    src_ips: set = set()
    dst_ips: set = set()
    ts_min = None
    ts_max = None
    for s in sessions:
        bs = _sget(s, "bytes_sent", 0) or 0
        br = _sget(s, "bytes_recv", 0) or 0
        total_bytes += bs + br
        proto = str(_sget(s, "protocol", "?")).upper()
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
        src = _sget(s, "src_ip", "?")
        dst = _sget(s, "dst_ip", "?")
        src_ips.add(src)
        dst_ips.add(dst)
        pair_bytes[(src, dst)] = pair_bytes.get((src, dst), 0) + bs + br
        # pool BOTH timestamps for min and max — a session with end_ts=0 must
        # not drag ts_max below ts_min (pre-existing behavior at HEAD)
        for t in (_sget(s, "start_ts", 0.0) or 0.0, _sget(s, "end_ts", 0.0) or 0.0):
            if t > 0:
                ts_min = t if ts_min is None else min(ts_min, t)
                ts_max = t if ts_max is None else max(ts_max, t)
    top_pair = max(pair_bytes, key=lambda k: pair_bytes[k]) if pair_bytes else None
    return {
        "total_bytes": total_bytes,
        "session_count": len(sessions),
        "protocol_counts": proto_counts,
        "unique_src": len(src_ips),
        "unique_dst": len(dst_ips),
        "top_pair": top_pair,
        "top_pair_bytes": pair_bytes.get(top_pair, 0) if top_pair else 0,
        "ts_min": ts_min or 0.0,
        "ts_max": ts_max or 0.0,
    }


def _compute_risk_score(attacks: list, health_lvl: str, malicious_ip_count: int
                        ) -> tuple[int, list[dict]]:
    """0-100 risk score with an explicit factor breakdown (defensibility)."""
    factors: list[dict] = []
    score = 0

    sev_counts = {"high": 0, "medium": 0, "low": 0}
    for a in attacks:
        sev = str(a.get("severity", "low")).lower()
        if sev not in sev_counts:
            sev = "low"
        sev_counts[sev] += 1
    for sev in ("high", "medium", "low"):
        c = sev_counts[sev]
        if not c:
            continue
        # first detection full weight; extras with diminishing returns
        pts = _ATTACK_BASE_POINTS[sev] + min(c - 1, 3) * 5
        score += pts
        factors.append({
            "factor": f"{c}x {sev}-severity detection",
            "detail": f"{c} {sev}-severity attack finding(s)",
            "points": pts,
        })

    hp = _HEALTH_LEVEL_POINTS.get(health_lvl, 0)
    if hp:
        score += hp
        factors.append({
            "factor": f"Network health: {health_lvl}",
            "detail": "Connectivity failures / degradation observed in the capture",
            "points": hp,
        })

    if malicious_ip_count:
        pts = min(malicious_ip_count, 3) * 10
        score += pts
        factors.append({
            "factor": "Threat-intel hit",
            "detail": f"{malicious_ip_count} IP(s) flagged by reputation sources",
            "points": pts,
        })

    return min(100, score), factors


def build_summary(
    attacks: list,
    sessions: list,
    health: Optional[dict] = None,
    reputation: Optional[dict] = None,
) -> NarrativeResult:
    """Build the analysis narrative + risk grade.

    attacks:   list of attack dicts (include src_ip, severity, mitre_id, description)
    sessions:  list of SessionModel objects or dicts
    health:    optional network_health.analyze() dict (enables failure diagnosis)
    reputation: optional {"is_malicious": bool, "sources": [...]} for the target IP
    """
    # Detector crashes are stored as {"attack_type": "ERROR", "detector_error": True}
    # pseudo-entries by /api/analyze — internal software errors, NOT attack evidence.
    attacks = [a for a in attacks
               if not a.get("detector_error") and a.get("attack_type") != "ERROR"]

    overview = _traffic_overview(sessions)
    health_lvl = _health_level(health)
    health_findings = _health_findings(health)
    malicious_ips = 1 if (reputation and reputation.get("is_malicious")) else 0

    # compact health snapshot for the PDF/report layer
    health_overview = {}
    if health and health.get("total_sessions", 0):
        health_overview = {
            "overall_score": health.get("overall_score"),
            "healthy": health.get("healthy", 0),
            "warning": health.get("warning", 0),
            "critical": health.get("critical", 0),
            "failure_summary": health.get("failure_summary", {}),
        }

    # ── no attacks ──────────────────────────────────────────────────────────
    if not attacks:
        risk_score, risk_factors = _compute_risk_score([], health_lvl, malicious_ips)
        # Network problems present even without an "attack"?
        if health_lvl != "CLEAN":
            diag = health_findings or ["Connectivity degradation detected."]
            traffic_line = _traffic_sentence(overview)
            narrative = "\n".join(
                [f"No attack signature matched, but the capture shows network problems ({health_lvl} concern)."]
                + ([traffic_line] if traffic_line else [])
                + [f"• {d}" for d in diag]
            )
            key_findings = [f"Network health: {health_lvl}"] + diag[:4]
            recommendations = _health_recommendations(health)
            return NarrativeResult(
                headline=f"Network issues detected — {health_lvl} risk (no attack signature)",
                narrative=narrative,
                risk_level=health_lvl,
                attacker_ips=[],
                victim_ips=[],
                recommendations=recommendations,
                attack_timeline=[],
                attack_explanations={},
                risk_score=risk_score,
                risk_factors=risk_factors,
                diagnosis=diag,
                key_findings=key_findings,
                health_overview=health_overview,
            )
        # grade is CLEAN, but a tiny capture (< _HEALTH_MIN_SESSIONS) can still be
        # failure-heavy — never call that "normal traffic" while showing 100%
        # failure diagnosis in the same card. Grade stays CLEAN (sample too
        # small to grade), the wording tells the truth.
        small_sample_issue = False
        if health_findings and health:
            total = health.get("total_sessions", 0)
            fs = health.get("failure_summary", {}) or {}
            hard_fail = sum(fs.get(k, 0) for k in
                            ("connection_refused", "no_response", "path_issue"))
            if 0 < total < _HEALTH_MIN_SESSIONS and hard_fail / total >= 0.5:
                small_sample_issue = True

        traffic_line = _traffic_sentence(overview)
        if small_sample_issue:
            narrative = "\n".join(
                ["No attack signature matched. Connectivity problems were observed, "
                 f"but the capture is too small ({health.get('total_sessions', 0)} sessions) "
                 "to grade reliably — capture more traffic to confirm."]
                + ([traffic_line] if traffic_line else [])
                + [f"• {d}" for d in health_findings]
            )
            return NarrativeResult(
                headline="Connectivity issues observed — sample too small to grade",
                narrative=narrative,
                risk_level="CLEAN",
                attacker_ips=[],
                victim_ips=[],
                recommendations=_health_recommendations(health),
                attack_timeline=[],
                attack_explanations={},
                risk_score=risk_score,
                risk_factors=risk_factors,
                diagnosis=health_findings,
                key_findings=health_findings[:4],
                health_overview=health_overview,
            )

        # genuinely clean
        narrative = (
            "No known anomaly patterns were detected in the analyzed capture file. "
            "It appears to be ordinary network traffic."
        )
        if traffic_line:
            narrative += "\n" + traffic_line
        return NarrativeResult(
            headline="Normal traffic — no anomalous events",
            narrative=narrative,
            risk_level="CLEAN",
            attacker_ips=[],
            victim_ips=[],
            recommendations=["Keep up regular pcap capture and monitoring"],
            attack_timeline=[],
            attack_explanations={},
            risk_score=risk_score,
            risk_factors=risk_factors,
            diagnosis=health_findings,
            key_findings=[traffic_line] if traffic_line else [],
            health_overview=health_overview,
        )

    # ── attacks present ─────────────────────────────────────────────────────
    attack_level = "CLEAN"
    for a in attacks:
        attack_level = _max_level(attack_level, _severity_to_level(a.get("severity", "low")))
    risk = _max_level(attack_level, health_lvl)
    risk_score, risk_factors = _compute_risk_score(attacks, health_lvl, malicious_ips)

    # attacker IPs (src_ip field)
    attacker_ips: list[str] = []
    for a in attacks:
        ip = a.get("src_ip") or ""
        if ip and ip not in attacker_ips:
            attacker_ips.append(ip)

    # victim IPs — attacker→victim direction sessions
    victim_ips: list[str] = []
    if attacker_ips and sessions:
        for s in sessions:
            src, dst = _sget(s, "src_ip", ""), _sget(s, "dst_ip", "")
            if dst in _PUBLIC_RESOLVERS:
                continue
            if src in attacker_ips and dst and dst not in victim_ips and dst not in attacker_ips:
                victim_ips.append(dst)
    victim_ips = victim_ips[:5]

    attack_type_set = sorted({a.get("attack_type", "Unknown") for a in attacks})

    suspected_types = [a.get("attack_type", "Unknown") for a in attacks
                       if _SEVERITY_CONFIDENCE.get(str(a.get("severity", "low")).lower(), 0.5) < _CONFIDENCE_THRESHOLD]
    confirmed_types = [a.get("attack_type", "Unknown") for a in attacks
                       if _SEVERITY_CONFIDENCE.get(str(a.get("severity", "low")).lower(), 0.5) >= _CONFIDENCE_THRESHOLD]

    def _attack_label(a: dict) -> str:
        ko = _ATTACK_KO.get(a.get("attack_type", "Unknown"), a.get("attack_type", "Unknown"))
        conf = _confidence_pct(str(a.get("severity", "low")))
        label = _confidence_label(str(a.get("severity", "low")))
        return f"{ko} {label} (confidence: {conf}%)"

    attack_ko = " + ".join(_ATTACK_KO.get(t, t) for t in attack_type_set)

    # timeline
    min_ts = overview.get("ts_min", 0.0)
    max_ts = overview.get("ts_max", 0.0)
    n = max(len(attacks), 1)
    attack_timeline = []
    for i, a in enumerate(attacks):
        ts = min_ts + (max_ts - min_ts) * i / n if min_ts > 0 else 0.0
        attack_timeline.append({
            "ts": ts,
            "attack_type": a.get("attack_type", "Unknown"),
            "severity": a.get("severity", "low"),
            "mitre_id": a.get("mitre_id", ""),
            "description": a.get("description", ""),
            "src_ip": a.get("src_ip", ""),
        })

    # narrative
    time_range = f"Between {_fmt_ts(min_ts)} and {_fmt_ts(max_ts)}, " if (min_ts > 0 and max_ts > 0) else ""
    attacker_str = ", ".join(attacker_ips[:3]) if attacker_ips else "an unknown host"
    victim_str   = ", ".join(victim_ips[:3])   if victim_ips   else "internal servers"
    total_bytes = overview.get("total_bytes", 0)

    main_sentence = f"{time_range}{attacker_str} carried out {attack_ko} activity against {victim_str}."
    stat_sentence = (
        f"Analyzed {_fmt_bytes(total_bytes)} of traffic across {len(sessions)} sessions."
        if sessions else ""
    )
    detail_lines = [
        f"• {_attack_label(a)}: {a.get('description', '')}"
        for a in attacks if a.get("description")
    ]

    parts = [main_sentence]
    if stat_sentence:
        parts.append(stat_sentence)
    if detail_lines:
        parts.extend(detail_lines)
    # append network-health corroboration (only when health data present)
    if health_findings:
        parts.append("Connectivity diagnosis:")
        parts.extend(f"• {d}" for d in health_findings)
    narrative = "\n".join(parts)

    # recommendations
    recommendations: list[str] = []
    seen: set[str] = set()
    for a in attacks:
        for rec in _MITRE_DEFENSE.get(a.get("mitre_id", ""), []):
            if rec not in seen:
                recommendations.append(rec)
                seen.add(rec)
    if not recommendations:
        recommendations.append("Block the detected attacker IPs at the firewall")

    attack_explanations = {
        t: _ATTACK_EXPLAIN.get(t, f"A {t} attack was detected.")
        for t in attack_type_set
    }

    has_suspected = bool(suspected_types)
    headline_suffix = " (incl. suspected)" if has_suspected and confirmed_types else (" suspected" if has_suspected else "")

    key_findings = [f"{_ATTACK_KO.get(t, t)}" for t in attack_type_set]
    if health_findings:
        key_findings += health_findings[:2]

    return NarrativeResult(
        headline=f"{attack_ko} detected{headline_suffix} — {risk} risk",
        narrative=narrative,
        risk_level=risk,
        attacker_ips=attacker_ips,
        victim_ips=victim_ips,
        recommendations=recommendations,
        attack_timeline=attack_timeline,
        attack_explanations=attack_explanations,
        risk_score=risk_score,
        risk_factors=risk_factors,
        diagnosis=health_findings,
        key_findings=key_findings,
        health_overview=health_overview,
    )


def _traffic_sentence(overview: dict) -> str:
    if not overview or not overview.get("session_count"):
        return ""
    parts = [
        f"Analyzed {_fmt_bytes(overview['total_bytes'])} across "
        f"{overview['session_count']} sessions "
        f"({overview['unique_src']} sources, {overview['unique_dst']} destinations)."
    ]
    tp = overview.get("top_pair")
    if tp:
        parts.append(f"Top talker: {tp[0]} -> {tp[1]} ({_fmt_bytes(overview['top_pair_bytes'])}).")
    return " ".join(parts)


def _health_recommendations(health: Optional[dict]) -> list[str]:
    """Operational recommendations for a network-problem (non-attack) verdict."""
    recs: list[str] = []
    fs = (health or {}).get("failure_summary", {}) or {}
    if fs.get("connection_refused"):
        recs.append("Verify the target service is listening and review firewall/ACL policy (many refused connections)")
    if fs.get("no_response"):
        recs.append("Check server availability and the network path (SYN timeouts / half-open connections)")
    if fs.get("path_issue"):
        recs.append("Inspect routing/TTL and intermediate firewalls (ICMP unreachable observed)")
    if fs.get("slow_response"):
        recs.append("Investigate latency: path congestion, MTU, or server overload")
    if not recs:
        recs.append("Review the sessions flagged Critical/Warning in the Network Health panel")
    return recs
