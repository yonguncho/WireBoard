"""통신 상태 진단 — RTT, 재전송, 핸드셰이크, 원인 분석."""
from __future__ import annotations

import dataclasses
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

_ICMP_LABEL_KR: dict[str, str] = {
    "ttl_expired":       "TTL 만료",
    "fragment_timeout":  "단편화 재조립 타임아웃",
    "net_unreachable":   "네트워크 도달 불가",
    "host_unreachable":  "호스트 도달 불가",
    "port_unreachable":  "포트 도달 불가",
    "admin_prohibited":  "관리자 차단",
    "unreachable":       "도달 불가",
}


# ── 플래그 헬퍼 ───────────────────────────────────────────────────────────────

def _f(flags: str) -> str:
    return (flags or "").upper()


def _is_syn_only(flags: str) -> bool:
    f = _f(flags)
    return "SYN" in f and "ACK" not in f and "RST" not in f


def _is_syn_ack(flags: str) -> bool:
    f = _f(flags)
    return "SYN" in f and "ACK" in f


def _is_rst(flags: str) -> bool:
    return "RST" in _f(flags)


def _is_fin(flags: str) -> bool:
    return "FIN" in _f(flags)


# ── 세션 진단 결과 ──────────────────────────────────────────────────────────

@dataclass
class SessionHealth:
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration_s: float
    packet_count: int
    bytes_sent: int
    bytes_recv: int

    handshake: str           # COMPLETE | REFUSED | TIMEOUT | HALF_OPEN | N/A
    rtt_ms: Optional[float]  # SYN→SYN-ACK RTT
    retransmit_count: int
    retransmit_rate: float   # 0.0~1.0
    rst_type: str            # NONE | EARLY | LATE
    close_type: str          # NORMAL | RESET | TIMEOUT | N/A

    score: int               # 0-100
    status: str              # 정상 | 주의 | 이상
    issues: list
    root_cause: str
    recommendations: list
    failure_type: str = "none"  # none | connection_refused | no_response | path_issue | slow_response
    icmp_label: str = ""    # path_issue 시 ICMP 레이블 (예: ttl_expired)
    icmp_src_ip: str = ""   # path_issue 시 ICMP 응답 라우터 IP


# ── TCP 분석 ─────────────────────────────────────────────────────────────────

def _analyze_tcp(session, packets: list) -> SessionHealth:
    fwd = [p for p in packets if p.direction == "fwd"]
    rev = [p for p in packets if p.direction == "rev"]

    syn_pkt    = next((p for p in fwd if _is_syn_only(p.flags)), None)
    synack_pkt = next((p for p in rev if _is_syn_ack(p.flags)), None)
    rst_pkts   = [p for p in packets if _is_rst(p.flags)]
    fin_pkts   = [p for p in packets if _is_fin(p.flags)]

    # RTT
    rtt_ms: Optional[float] = None
    if syn_pkt and synack_pkt and synack_pkt.ts > syn_pkt.ts:
        rtt_ms = round((synack_pkt.ts - syn_pkt.ts) * 1000, 2)

    # 핸드셰이크 판정
    if syn_pkt is None:
        handshake = "N/A"
    elif synack_pkt is not None:
        handshake = "COMPLETE"
    elif rst_pkts and any(p.direction == "rev" for p in rst_pkts):
        handshake = "REFUSED"
    elif not rev:
        handshake = "TIMEOUT"
    else:
        handshake = "HALF_OPEN"

    # 재전송 감지 (동일 seq + direction 재출현)
    seen: set = set()
    retransmit_count = 0
    data_pkts = 0
    for p in packets:
        if p.payload_len > 0 and p.proto == "TCP":
            key = (p.direction, p.seq)
            data_pkts += 1
            if key in seen:
                retransmit_count += 1
            else:
                seen.add(key)
    retransmit_rate = retransmit_count / max(1, data_pkts)

    # RST 분류
    if not rst_pkts:
        rst_type  = "NONE"
        close_type = "NORMAL" if fin_pkts else "TIMEOUT"
    else:
        data_before_rst = any(
            p.payload_len > 0 and p.ts < rst_pkts[0].ts
            for p in packets
        )
        rst_type  = "LATE" if data_before_rst else "EARLY"
        close_type = "RESET"

    # ── 점수 계산 ────────────────────────────────────────────────────────────
    score = 100
    issues: list = []
    recommendations: list = []

    if handshake == "REFUSED":
        score -= 40
        issues.append("연결 거부됨 (서버 RST 응답)")
        recommendations.append("대상 포트 개방 여부 및 방화벽 정책을 확인하세요")
    elif handshake == "TIMEOUT":
        score -= 35
        issues.append("연결 응답 없음 (SYN 타임아웃)")
        recommendations.append("서버 가용성 및 네트워크 경로를 점검하세요")
    elif handshake == "HALF_OPEN":
        score -= 25
        issues.append("불완전한 핸드셰이크 (SYN-ACK 미수신)")
        recommendations.append("패킷 손실 또는 방화벽 차단 가능성을 확인하세요")

    if rtt_ms is not None:
        if rtt_ms > 500:
            score -= 20
            issues.append(f"RTT 심각 ({rtt_ms:.0f} ms) — 매우 높은 지연")
            recommendations.append("네트워크 경로 병목 또는 서버 과부하를 확인하세요")
        elif rtt_ms > 150:
            score -= 10
            issues.append(f"RTT 높음 ({rtt_ms:.0f} ms)")
            recommendations.append("네트워크 지연 원인을 조사하세요")

    if retransmit_rate > 0.20:
        score -= 30
        issues.append(f"재전송률 매우 높음 ({retransmit_rate:.0%}) — 패킷 손실 의심")
        recommendations.append("링크 품질, MTU 설정, 혼잡 제어를 점검하세요")
    elif retransmit_rate > 0.05:
        score -= 15
        issues.append(f"재전송 발생 ({retransmit_rate:.0%})")
        recommendations.append("간헐적 패킷 손실 가능성이 있습니다")

    if rst_type == "LATE":
        score -= 20
        issues.append("데이터 전송 중 RST 강제 종료")
        recommendations.append("서버 크래시, 방화벽 세션 타임아웃 등을 확인하세요")

    if session.bytes_sent == 0 and session.bytes_recv == 0:
        score -= 15
        issues.append("데이터 교환 없음")

    if session.bytes_sent > 0 and session.bytes_recv == 0 and handshake == "COMPLETE":
        score -= 15
        issues.append("서버 응답 없음 (요청은 전송됨)")
        recommendations.append("서버 로그와 애플리케이션 상태를 확인하세요")

    score = max(0, min(100, score))
    status = "정상" if score >= 80 else ("주의" if score >= 50 else "이상")
    root_cause = issues[0] if issues else "이상 없음 — 정상 통신"

    # failure_type 분류
    if handshake == "REFUSED":
        failure_type = "connection_refused"
    elif handshake in ("TIMEOUT", "HALF_OPEN"):
        failure_type = "no_response"
    elif rtt_ms is not None and rtt_ms > 1000:
        failure_type = "slow_response"
    else:
        failure_type = "none"

    return SessionHealth(
        session_id=session.session_id,
        src_ip=session.src_ip, dst_ip=session.dst_ip,
        src_port=session.src_port, dst_port=session.dst_port,
        protocol=session.protocol,
        duration_s=round(session.end_ts - session.start_ts, 3),
        packet_count=session.packet_count,
        bytes_sent=session.bytes_sent, bytes_recv=session.bytes_recv,
        handshake=handshake, rtt_ms=rtt_ms,
        retransmit_count=retransmit_count,
        retransmit_rate=round(retransmit_rate, 4),
        rst_type=rst_type, close_type=close_type,
        score=score, status=status,
        issues=issues, root_cause=root_cause,
        recommendations=recommendations,
        failure_type=failure_type,
    )


# ── UDP / 기타 분석 ───────────────────────────────────────────────────────────

def _analyze_udp(session, packets: list) -> SessionHealth:
    has_response = any(p.direction == "rev" for p in packets)
    score = 100
    issues: list = []
    recommendations: list = []

    if packets and not has_response:
        score -= 30
        issues.append("UDP 응답 없음")
        recommendations.append("대상 포트가 열려 있는지 확인하세요")
    if session.bytes_sent == 0 and session.bytes_recv == 0:
        score -= 20
        issues.append("데이터 교환 없음")

    score = max(0, min(100, score))
    status = "정상" if score >= 80 else ("주의" if score >= 50 else "이상")
    failure_type = "no_response" if (packets and not has_response) else "none"

    return SessionHealth(
        session_id=session.session_id,
        src_ip=session.src_ip, dst_ip=session.dst_ip,
        src_port=session.src_port, dst_port=session.dst_port,
        protocol=session.protocol,
        duration_s=round(session.end_ts - session.start_ts, 3),
        packet_count=session.packet_count,
        bytes_sent=session.bytes_sent, bytes_recv=session.bytes_recv,
        handshake="N/A", rtt_ms=None,
        retransmit_count=0, retransmit_rate=0.0,
        rst_type="NONE", close_type="N/A",
        score=score, status=status,
        issues=issues,
        root_cause=issues[0] if issues else "이상 없음",
        recommendations=recommendations,
        failure_type=failure_type,
    )


# ── 세션 미검증(패킷 없음) 처리 ───────────────────────────────────────────────

def _analyze_no_packets(session) -> SessionHealth:
    """HAR/FortiGate 등 패킷 데이터가 없는 세션 — 메타 기반 분석."""
    score = 100
    issues: list = []
    recommendations: list = []

    if session.rst:
        score -= 25
        issues.append("RST 플래그 감지 (연결 비정상 종료)")

    if session.bytes_sent == 0 and session.bytes_recv == 0:
        score -= 20
        issues.append("데이터 교환 없음")
    elif session.bytes_sent > 0 and session.bytes_recv == 0:
        score -= 15
        issues.append("서버 응답 없음")
        recommendations.append("서버 애플리케이션 상태를 확인하세요")

    score = max(0, min(100, score))
    status = "정상" if score >= 80 else ("주의" if score >= 50 else "이상")

    return SessionHealth(
        session_id=session.session_id,
        src_ip=session.src_ip, dst_ip=session.dst_ip,
        src_port=session.src_port, dst_port=session.dst_port,
        protocol=session.protocol,
        duration_s=round(session.end_ts - session.start_ts, 3),
        packet_count=session.packet_count,
        bytes_sent=session.bytes_sent, bytes_recv=session.bytes_recv,
        handshake="N/A", rtt_ms=None,
        retransmit_count=0, retransmit_rate=0.0,
        rst_type="NONE" if not session.rst else "EARLY",
        close_type="N/A",
        score=score, status=status,
        issues=issues,
        root_cause=issues[0] if issues else "이상 없음",
        recommendations=recommendations,
        failure_type="connection_refused" if session.rst else "none",
    )


# ── 전체 분석 진입점 ─────────────────────────────────────────────────────────

def analyze(
    sessions: list,
    packet_map: dict,
    icmp_events: list | None = None,
) -> dict:
    """전체 세션 통신 상태 분석. /api/health 에서 호출."""
    healths: list[SessionHealth] = []

    for s in sessions:
        pkts = packet_map.get(s.session_id, [])
        proto = (s.protocol or "").upper()
        if not pkts:
            sh = _analyze_no_packets(s)
        elif proto == "TCP":
            sh = _analyze_tcp(s, pkts)
        else:
            sh = _analyze_udp(s, pkts)
        healths.append(sh)

    # ICMP 에러 이벤트로 path_issue 상관 분석
    if icmp_events:
        # (orig_dst_ip, orig_dst_port) → 첫 번째 ICMP 이벤트
        icmp_lookup: dict[tuple[str, int], dict] = {}
        for ev in icmp_events:
            key = (ev.get("orig_dst", ""), ev.get("orig_dst_port", 0))
            if key[0] and key not in icmp_lookup:
                icmp_lookup[key] = ev

        for sh in healths:
            ev = icmp_lookup.get((sh.dst_ip, sh.dst_port))
            if ev and sh.failure_type in ("none", "no_response"):
                label_kr = _ICMP_LABEL_KR.get(ev.get("label", ""), ev.get("label", ""))
                msg = f"경로 문제 — {ev['src_ip']}에서 {label_kr}"
                sh.failure_type = "path_issue"
                sh.icmp_label   = ev.get("label", "")
                sh.icmp_src_ip  = ev.get("src_ip", "")
                sh.issues.append(msg)
                sh.root_cause = msg
                sh.recommendations.append(
                    "네트워크 경로상 라우터 TTL 설정 및 방화벽 정책을 점검하세요"
                )
                sh.score  = max(0, sh.score - 30)
                sh.status = "정상" if sh.score >= 80 else ("주의" if sh.score >= 50 else "이상")

    total    = len(healths)
    healthy  = sum(1 for h in healths if h.score >= 80)
    warning  = sum(1 for h in healths if 50 <= h.score < 80)
    critical = sum(1 for h in healths if h.score < 50)
    overall  = (sum(h.score for h in healths) // total) if total else 100

    # 이슈 집계 (숫자값 제거해 동일 유형으로 묶음)
    issue_counter: dict = defaultdict(int)
    for h in healths:
        for issue in h.issues:
            key = re.sub(r"[\d.]+\s*m?s|[\d.]+%", "N", issue)
            issue_counter[key] += 1

    top_issues = sorted(
        [{"issue": k, "count": v} for k, v in issue_counter.items()],
        key=lambda x: -x["count"],
    )[:10]

    # failure_type 요약 집계
    failure_summary: dict = defaultdict(int)
    for h in healths:
        if h.failure_type != "none":
            failure_summary[h.failure_type] += 1

    return {
        "total_sessions": total,
        "healthy":        healthy,
        "warning":        warning,
        "critical":       critical,
        "overall_score":  overall,
        "top_issues":     top_issues,
        "failure_summary": dict(failure_summary),
        "sessions":       [dataclasses.asdict(h) for h in healths],
    }
