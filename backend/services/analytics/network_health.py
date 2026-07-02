"""통신 상태 진단 — RTT, 재전송, 핸드셰이크, 원인 분석."""
from __future__ import annotations

import dataclasses
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

_ICMP_LABEL_KR: dict[str, str] = {
    "ttl_expired":       "TTL exceeded",
    "fragment_timeout":  "Fragment reassembly timeout",
    "net_unreachable":   "Network unreachable",
    "host_unreachable":  "Host unreachable",
    "port_unreachable":  "Port unreachable",
    "admin_prohibited":  "Administratively prohibited",
    "unreachable":       "Unreachable",
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
    status: str              # Healthy | Warning | Critical
    issues: list
    root_cause: str
    recommendations: list
    failure_type: str = "none"  # none | connection_refused | no_response | path_issue | slow_response
    icmp_label: str = ""    # path_issue 시 ICMP 레이블 (예: ttl_expired)
    icmp_src_ip: str = ""   # path_issue 시 ICMP 응답 라우터 IP
    # ── NOC 트리아지: "네트워크 문제인가, 앱 문제인가" ────────────────────
    server_delay_ms: Optional[float] = None  # 요청 페이로드 → 응답 페이로드 지연
    bottleneck: str = "none"  # none | network | server | application | indeterminate


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

    # ── 서버 응답 지연: 첫 요청 페이로드(fwd) → 그 이후 첫 응답 페이로드(rev) ──
    # iRTT(순수 네트워크 지연)와 비교해 "네트워크 vs 앱" 병목을 판정하는 근거.
    server_delay_ms: Optional[float] = None
    first_req = next((p for p in packets if p.direction == "fwd" and p.payload_len > 0), None)
    if first_req is not None:
        first_resp = next(
            (p for p in packets
             if p.direction == "rev" and p.payload_len > 0 and p.ts >= first_req.ts),
            None,
        )
        if first_resp is not None:
            server_delay_ms = round((first_resp.ts - first_req.ts) * 1000, 2)

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
        issues.append("Connection refused (server RST)")
        recommendations.append("Check whether the target port is open and review firewall policy")
    elif handshake == "TIMEOUT":
        score -= 35
        issues.append("No connection response (SYN timeout)")
        recommendations.append("Check server availability and the network path")
    elif handshake == "HALF_OPEN":
        score -= 25
        issues.append("Incomplete handshake (no SYN-ACK)")
        recommendations.append("Check for packet loss or firewall blocking")

    if rtt_ms is not None:
        if rtt_ms > 500:
            score -= 20
            issues.append(f"Critical RTT ({rtt_ms:.0f} ms) — very high latency")
            recommendations.append("Check for network path bottlenecks or server overload")
        elif rtt_ms > 150:
            score -= 10
            issues.append(f"High RTT ({rtt_ms:.0f} ms)")
            recommendations.append("Investigate the cause of network latency")

    if retransmit_rate > 0.20:
        score -= 30
        issues.append(f"Very high retransmit rate ({retransmit_rate:.0%}) — suspected packet loss")
        recommendations.append("Check link quality, MTU settings, and congestion control")
    elif retransmit_rate > 0.05:
        score -= 15
        issues.append(f"Retransmissions detected ({retransmit_rate:.0%})")
        recommendations.append("Intermittent packet loss is possible")

    if rst_type == "LATE":
        score -= 20
        issues.append("RST during data transfer (forced close)")
        recommendations.append("Check for server crash, firewall session timeout, etc.")

    if session.bytes_sent == 0 and session.bytes_recv == 0:
        score -= 15
        issues.append("No data exchanged")

    if session.bytes_sent > 0 and session.bytes_recv == 0 and handshake == "COMPLETE":
        score -= 15
        issues.append("No server response (request was sent)")
        recommendations.append("Check server logs and application status")

    score = max(0, min(100, score))
    status = "Healthy" if score >= 80 else ("Warning" if score >= 50 else "Critical")
    root_cause = issues[0] if issues else "No issues — normal communication"

    # failure_type 분류
    if handshake == "REFUSED":
        failure_type = "connection_refused"
    elif handshake in ("TIMEOUT", "HALF_OPEN"):
        failure_type = "no_response"
    elif rtt_ms is not None and rtt_ms > 1000:
        failure_type = "slow_response"
    else:
        failure_type = "none"

    # ── 병목 판정: NOC의 "네트워크팀? 개발팀?" 에스컬레이션 방향 ──────────
    # 근거 우선순위: 손실(재전송) > 연결 거부 > 지연 비교(iRTT vs 서버 delta)
    if retransmit_rate > 0.05 or handshake in ("TIMEOUT", "HALF_OPEN"):
        bottleneck = "network"          # 패킷 손실/무응답 → 경로 문제
    elif handshake == "REFUSED":
        bottleneck = "server"           # 서비스가 안 떠 있음/포트 차단
    elif rtt_ms is not None and rtt_ms > 500:
        bottleneck = "network"          # 순수 왕복 지연 자체가 큼
    elif (server_delay_ms is not None and rtt_ms is not None
          and rtt_ms <= 150 and server_delay_ms > max(500.0, rtt_ms * 10)):
        bottleneck = "application"      # 네트워크는 빠른데 응답 생성이 느림
    elif issues:
        bottleneck = "indeterminate"
    else:
        bottleneck = "none"

    if bottleneck == "application":
        issues.append(
            f"Server response delay {server_delay_ms:.0f} ms vs network RTT "
            f"{rtt_ms:.0f} ms — application/server-side bottleneck"
        )
        recommendations.append(
            "Network path is healthy — escalate to the application/server team "
            "(check server logs, DB queries, thread pools)"
        )
        # 앱 지연도 세션 건강 점수에 반영 (점수는 이미 산정된 뒤이므로 여기서 보정)
        score = max(0, min(100, score - 15))
        status = "Healthy" if score >= 80 else ("Warning" if score >= 50 else "Critical")
        root_cause = issues[0]

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
        server_delay_ms=server_delay_ms,
        bottleneck=bottleneck,
    )


# ── UDP / 기타 분석 ───────────────────────────────────────────────────────────

# 응답이 원래 없는 단방향 UDP 서비스 포트 (syslog, SNMP trap, NetFlow/IPFIX 등)
_ONE_WAY_UDP_PORTS = {514, 162, 2055, 2056, 4739, 6343, 9995, 9996}


def _is_one_way_by_design(session) -> bool:
    """멀티캐스트/브로드캐스트/단방향 프로토콜 — 무응답이 정상인 UDP."""
    try:
        dst = ipaddress.ip_address(session.dst_ip)
        if dst.is_multicast:
            return True
        if str(dst) == "255.255.255.255" or str(dst).endswith(".255"):
            return True  # limited/directed broadcast (mDNS, SSDP, NetBIOS-NS 등)
    except ValueError:
        pass
    return session.dst_port in _ONE_WAY_UDP_PORTS


def _analyze_udp(session, packets: list) -> SessionHealth:
    has_response = any(p.direction == "rev" for p in packets)
    one_way_ok = _is_one_way_by_design(session)
    score = 100
    issues: list = []
    recommendations: list = []

    # 무응답 UDP는 unicast 요청/응답형에서만 문제 (브로드캐스트·syslog 등은 정상)
    if packets and not has_response and not one_way_ok:
        score -= 30
        issues.append("No UDP response")
        recommendations.append("Check whether the target port is open")
    if session.bytes_sent == 0 and session.bytes_recv == 0:
        score -= 20
        issues.append("No data exchanged")

    score = max(0, min(100, score))
    status = "Healthy" if score >= 80 else ("Warning" if score >= 50 else "Critical")
    failure_type = "no_response" if (packets and not has_response and not one_way_ok) else "none"

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
        root_cause=issues[0] if issues else "No issues",
        recommendations=recommendations,
        failure_type=failure_type,
    )


# ── 세션 미검증(패킷 없음) 처리 ───────────────────────────────────────────────

def _analyze_no_packets(session) -> SessionHealth:
    """HAR/FortiGate 등 패킷 데이터가 없는 세션 — 메타 기반 분석.

    패킷이 없으면 RST가 '거부'인지 '정상 종료(teardown)'인지 구분할 수 없다.
    실제 connection refused는 핸드셰이크 초반(패킷 수 소수)에 끝나므로,
    패킷 수가 많은 RST 세션을 refused로 단정하지 않는다 (오탐 방지).
    """
    score = 100
    issues: list = []
    recommendations: list = []
    likely_refused = session.rst and session.packet_count <= 3

    if session.rst:
        score -= 25
        issues.append("RST flag detected (abnormal connection close)")

    if session.bytes_sent == 0 and session.bytes_recv == 0:
        score -= 20
        issues.append("No data exchanged")
    elif session.bytes_sent > 0 and session.bytes_recv == 0:
        score -= 15
        issues.append("No server response")
        recommendations.append("Check the server application status")

    score = max(0, min(100, score))
    status = "Healthy" if score >= 80 else ("Warning" if score >= 50 else "Critical")

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
        root_cause=issues[0] if issues else "No issues",
        recommendations=recommendations,
        failure_type="connection_refused" if likely_refused else "none",
    )


# ── 전체 분석 진입점 ─────────────────────────────────────────────────────────

def analyze(
    sessions: list,
    packet_map: dict,
    icmp_events: list | None = None,
) -> dict:
    """전체 세션 통신 상태 분석. /api/health 에서 호출."""
    healths: list[SessionHealth] = []
    packetless = 0

    for s in sessions:
        pkts = packet_map.get(s.session_id, [])
        proto = (s.protocol or "").upper()
        if not pkts:
            sh = _analyze_no_packets(s)
            packetless += 1
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
                msg = f"Path issue — {label_kr} from {ev['src_ip']}"
                sh.failure_type = "path_issue"
                sh.icmp_label   = ev.get("label", "")
                sh.icmp_src_ip  = ev.get("src_ip", "")
                sh.issues.append(msg)
                sh.root_cause = msg
                sh.recommendations.append(
                    "Check router TTL settings and firewall policy along the network path"
                )
                sh.score  = max(0, sh.score - 30)
                sh.status = "Healthy" if sh.score >= 80 else ("Warning" if sh.score >= 50 else "Critical")

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

    # ── "네트워크 vs 앱" 전체 판정 (NOC 에스컬레이션 방향) ─────────────────
    bottleneck_counts: dict = defaultdict(int)
    for h in healths:
        if h.bottleneck not in ("none", "indeterminate"):
            bottleneck_counts[h.bottleneck] += 1
    net_n = bottleneck_counts.get("network", 0)
    app_n = bottleneck_counts.get("application", 0)
    srv_n = bottleneck_counts.get("server", 0)
    if net_n == 0 and app_n == 0 and srv_n == 0:
        verdict_side, verdict_headline = "none", "No dominant bottleneck — sessions look healthy."
    elif net_n >= app_n and net_n >= srv_n:
        verdict_side = "network"
        verdict_headline = (f"Evidence points to a NETWORK problem — {net_n} session(s) "
                            f"show loss, no-response, or high path latency.")
    elif app_n >= srv_n:
        verdict_side = "application"
        verdict_headline = (f"Evidence points to an APPLICATION/SERVER slowdown — {app_n} "
                            f"session(s) respond slowly despite a healthy network path.")
    else:
        verdict_side = "server"
        verdict_headline = (f"Evidence points to a SERVER-side issue — {srv_n} "
                            f"connection(s) actively refused.")
    verdict = {
        "side": verdict_side,          # network | application | server | none
        "headline": verdict_headline,
        "counts": dict(bottleneck_counts),
    }

    # ── 캡처 품질 진단: 오판 방지용 경고 ──────────────────────────────────
    tcp_with_pkts = 0
    no_handshake = 0
    truncated_flows = 0
    for s in sessions:
        pkts = packet_map.get(s.session_id, [])
        if pkts and (s.protocol or "").upper() == "TCP":
            tcp_with_pkts += 1
            if not any(_is_syn_only(p.flags) or _is_syn_ack(p.flags) for p in pkts):
                no_handshake += 1  # 캡처 시작 전에 연결됨 → RTT/핸드셰이크 진단 불가
        if len(pkts) >= 200:  # pcap_parser._MAX_PKTS_PER_FLOW 상한 도달
            truncated_flows += 1
    quality_warnings: list[str] = []
    if tcp_with_pkts and no_handshake / tcp_with_pkts >= 0.5:
        quality_warnings.append(
            f"{no_handshake} of {tcp_with_pkts} TCP sessions began before the capture "
            f"started — handshake/RTT diagnostics are limited for them."
        )
    if total and packetless / total >= 0.5:
        quality_warnings.append(
            "Most sessions have no packet data (summary-only text log) — "
            "flag-level diagnostics only; retransmission/RTT unavailable."
        )
    if truncated_flows:
        quality_warnings.append(
            f"{truncated_flows} flow(s) hit the 200-packets-per-flow storage cap — "
            f"per-flow stats for them are partial."
        )
    capture_quality = {
        "tcp_sessions_with_packets": tcp_with_pkts,
        "handshake_not_captured": no_handshake,
        "packetless_sessions": packetless,
        "truncated_flows": truncated_flows,
        "warnings": quality_warnings,
    }

    return {
        "total_sessions": total,
        "healthy":        healthy,
        "warning":        warning,
        "critical":       critical,
        "overall_score":  overall,
        "top_issues":     top_issues,
        "failure_summary": dict(failure_summary),
        # 데이터 품질 신호: 패킷 없는(텍스트 로그 등) 세션 수 — 등급 판정 신뢰도에 사용
        "packetless_sessions": packetless,
        "verdict":         verdict,          # 네트워크 vs 앱 판정
        "capture_quality": capture_quality,  # 오판 방지용 캡처 품질 경고
        "sessions":       [dataclasses.asdict(h) for h in healths],
    }
