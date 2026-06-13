"""자연어 요약 생성 — 규칙 기반 (API 비용 없음)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple

# ── MITRE ID → 방어 권고 매핑 ───────────────────────────────────────────────
_MITRE_DEFENSE: dict[str, list[str]] = {
    "T1046": [
        "포트스캔 출발지 IP를 방화벽에서 즉시 차단하세요",
        "IDS/IPS에서 SYN 스캔 탐지 룰을 활성화하세요",
        "불필요한 서비스 포트를 닫으세요",
    ],
    "T1071": [
        "탐지된 C2 도메인·IP를 DNS 싱크홀 또는 방화벽으로 차단하세요",
        "아웃바운드 비표준 포트(80/443 외) 트래픽을 검토하세요",
        "의심 호스트에서 EDR 에이전트 점검을 실행하세요",
    ],
    "T1498": [
        "업스트림 ISP에 DDoS 완화 요청을 고려하세요",
        "스크러빙 서비스(CloudFlare, AWS Shield 등) 활성화를 검토하세요",
        "Rate-limiting 룰을 적용하세요",
    ],
    "T1041": [  # ExfiltrationDetector가 사용하는 MITRE ID
        "대용량 아웃바운드 트래픽 출발지를 격리하세요",
        "DLP 솔루션으로 민감 데이터 유출 여부를 확인하세요",
        "DNS exfiltration 패턴을 분석하세요",
    ],
    "T1110": [
        "브루트포스 대상 서비스에서 계정 잠금 정책을 활성화하세요",
        "MFA(다중 인증)를 적용하세요",
        "반복 실패 IP를 자동 차단하는 fail2ban 등을 설정하세요",
    ],
    "T1499": [  # CommFailureDetector
        "RST 급증 구간의 출발지 IP를 조사하세요",
        "방화벽 ACL과 서비스 포트 설정을 점검하세요",
        "IDS/IPS에서 비정상 연결 종료 패턴을 모니터링하세요",
    ],
}

_ATTACK_KO: dict[str, str] = {
    "PortScan":    "포트스캔",
    "Beacon":      "C2 비콘",
    "CommFailure": "통신 실패 급증",
    "DDoS":        "DDoS 공격",
    "Exfiltration":"데이터 유출",
    "BruteForce":  "브루트포스",
}

_ATTACK_EXPLAIN: dict[str, str] = {
    "PortScan": (
        "포트스캔은 공격자가 목표 서버의 열린 포트(서비스)를 파악하기 위해 "
        "다수의 포트에 연결 시도를 보내는 정찰 행위입니다. "
        "이를 통해 공격자는 어떤 서비스가 취약한지 파악합니다."
    ),
    "Beacon": (
        "비콘(Beacon)은 이미 감염된 호스트가 공격자의 C2(Command & Control) 서버와 "
        "주기적으로 통신하는 패턴입니다. 정기적인 간격으로 연결이 발생한다면 "
        "악성코드 감염을 의심해야 합니다."
    ),
    "DDoS": (
        "DDoS(분산 서비스 거부) 공격은 대량의 트래픽으로 서버나 네트워크를 "
        "마비시키는 공격입니다. 서비스 중단이 목적입니다."
    ),
    "Exfiltration": (
        "데이터 유출(Exfiltration)은 공격자가 내부 민감 데이터를 외부로 "
        "몰래 전송하는 행위입니다. 대용량 아웃바운드 트래픽이 특징입니다."
    ),
    "BruteForce": (
        "브루트포스는 SSH, RDP, 웹 로그인 등에 수많은 비밀번호를 자동으로 "
        "시도하는 공격입니다. 계정 탈취가 목적입니다."
    ),
    "CommFailure": (
        "통신 실패 급증은 네트워크 장애, 잘못된 설정, 또는 연결 기반 공격의 "
        "부작용으로 나타날 수 있습니다. RST/ICMP unreachable 패킷이 다수 발생합니다."
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
        return "탐지"
    elif conf >= _CONFIDENCE_THRESHOLD:
        return "의심 탐지"
    else:
        return "낮은 확신"


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
    attack_explanations: dict[str, str]  # attack_type → 초보자 설명


def build_summary(attacks: list, sessions: list) -> NarrativeResult:
    """attacks: list of AttackEntry dicts (from analyze endpoint, includes src_ip)
    sessions: list of SessionModel objects or dicts"""

    if not attacks:
        return NarrativeResult(
            headline="정상 트래픽 — 이상 이벤트 없음",
            narrative=(
                "분석된 캡처 파일에서 알려진 이상 패턴이 탐지되지 않았습니다. "
                "일반적인 네트워크 트래픽으로 판단됩니다."
            ),
            risk_level="CLEAN",
            attacker_ips=[],
            victim_ips=[],
            recommendations=["정기적인 pcap 캡처와 모니터링을 유지하세요"],
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
        return f"{ko} {label} (확신도: {conf}%)"

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
        time_range = f"{_fmt_ts(min_ts)}~{_fmt_ts(max_ts)} 사이에 "

    attacker_str = ", ".join(attacker_ips[:3]) if attacker_ips else "불상의 호스트"
    victim_str   = ", ".join(victim_ips[:3])   if victim_ips   else "내부 서버"

    total_bytes = sum(
        (s.get("bytes_sent", 0) + s.get("bytes_recv", 0)) if isinstance(s, dict)
        else (getattr(s, "bytes_sent", 0) + getattr(s, "bytes_recv", 0))
        for s in sessions
    ) if sessions else 0

    # 메인 문장
    main_sentence = (
        f"{time_range}{attacker_str}이(가) {victim_str}을(를) 대상으로 "
        f"{attack_ko} 활동을 수행했습니다."
    )
    stat_sentence = (
        f"총 {len(sessions)}개 세션에서 {_fmt_bytes(total_bytes)} 트래픽이 분석되었습니다."
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
        recommendations.append("탐지된 공격 IP를 방화벽에서 차단하세요")

    # ── 초보자 설명 ────────────────────────────────────────────────────────
    attack_explanations = {
        t: _ATTACK_EXPLAIN.get(t, f"{t} 공격이 탐지되었습니다.")
        for t in attack_type_set
    }

    # 헤드라인: 확신도 낮은 공격이 섞여 있으면 "의심 포함" 표시
    has_suspected = bool(suspected_types)
    headline_suffix = " (의심 포함)" if has_suspected and confirmed_types else (" 의심" if has_suspected else "")
    return NarrativeResult(
        headline=f"{attack_ko} 탐지{headline_suffix} — {risk} 위험",
        narrative=narrative,
        risk_level=risk,
        attacker_ips=attacker_ips,
        victim_ips=victim_ips,
        recommendations=recommendations,
        attack_timeline=attack_timeline,
        attack_explanations=attack_explanations,
    )
