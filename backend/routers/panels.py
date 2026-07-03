"""GET /api/panels/{upload_id} — 패널 통합 분석 결과."""
import logging
from collections import defaultdict

from fastapi import APIRouter, Header, HTTPException, Request

logger = logging.getLogger(__name__)

from services.analytics.ip_analyzer import IpAnalyzer
from services.analytics.protocol_stats import ProtocolStats
from services.analytics.flow_timeline import FlowTimeline
from services.analytics.http_status_analyzer import HttpStatusAnalyzer
from services.analytics.rst_analyzer import RstAnalyzer
from services.analytics.tls_analyzer import TlsAnalyzer
from services.analytics.dns_analyzer import DnsAnalyzer
from services.analytics import tcp_expert
from utils.constants import UUID_RE
from utils.capture_auth import check_capture_token
from utils.net_utils import is_private as _is_private

router = APIRouter()

_ip_analyzer = IpAnalyzer()
_proto_stats = ProtocolStats()
_flow_timeline = FlowTimeline(window_seconds=60)
_http_analyzer = HttpStatusAnalyzer()
_rst_analyzer = RstAnalyzer()
_tls_analyzer = TlsAnalyzer()
_dns_analyzer = DnsAnalyzer()


@router.get("/api/panels/{upload_id}")
async def get_panels(
    upload_id: str,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_RE.match(upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be a valid UUID"})
    logger.info("패널 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "Upload not found"})

    check_capture_token(capture, x_upload_token)
    sessions = capture.sessions

    ip_result = _ip_analyzer.analyze(sessions)
    proto_result = _proto_stats.compute(sessions)
    timeline_result = _flow_timeline.compute(sessions)
    http_result = _http_analyzer.analyze(sessions)
    rst_result = _rst_analyzer.analyze(sessions)
    tls_result = _tls_analyzer.analyze(sessions)
    dns_result = _dns_analyzer.analyze(sessions)

    # panel5_anomalies: rst_count, malformed_count, retransmit_count
    rst_count = sum(rst_result.rst_by_src.values())
    panel5_anomalies = {
        "rst_count": rst_count,
        "malformed_count": rst_result.malformed_count,
        "retransmit_count": rst_result.retransmit_count,
    }

    # panel6_ip_ranking: IpRankEntry[] — bytes per IP (src+dst combined)
    ip_bytes: dict[str, int] = defaultdict(int)
    for s in sessions:
        ip_bytes[s.src_ip] += s.bytes_sent
        ip_bytes[s.dst_ip] += s.bytes_recv
    panel6_ip_ranking = [
        {"ip": ip, "bytes": b, "is_internal": _is_private(ip)}
        for ip, b in sorted(ip_bytes.items(), key=lambda x: -x[1])[:20]
    ]

    # panel9_conversations: ConvEntry[] — top pairs by bytes with packets + duration
    # + NOC 트리아지용 오류 지표(rst/no-reply 세션 수) — 오류율 정렬을 지원한다
    pair_data: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"bytes": 0, "packets": 0, "start": float("inf"), "end": float("-inf"),
                 "sessions": 0, "rst": 0, "no_reply": 0}
    )
    for s in sessions:
        key = (s.src_ip, s.dst_ip)
        pair_data[key]["bytes"] += s.bytes_sent + s.bytes_recv
        pair_data[key]["packets"] += s.packet_count
        pair_data[key]["start"] = min(pair_data[key]["start"], s.start_ts)
        pair_data[key]["end"] = max(pair_data[key]["end"], s.end_ts)
        pair_data[key]["sessions"] += 1
        if s.rst:
            pair_data[key]["rst"] += 1
        # 요청은 보냈는데 응답 0바이트 — TCP에서만 의미(단방향 UDP는 정상)
        if (s.protocol or "").upper() == "TCP" and s.bytes_sent > 0 and s.bytes_recv == 0:
            pair_data[key]["no_reply"] += 1
    panel9_conversations = [
        {
            "src": k[0],
            "dst": k[1],
            "packets": v["packets"],
            "bytes": v["bytes"],
            "duration_s": max(0.0, v["end"] - v["start"]) if v["start"] != float("inf") else 0.0,
            "sessions": v["sessions"],
            "rst": v["rst"],
            "no_reply": v["no_reply"],
            "issue_rate": round((v["rst"] + v["no_reply"]) / v["sessions"], 4) if v["sessions"] else 0.0,
        }
        for k, v in sorted(pair_data.items(), key=lambda x: -x[1]["bytes"])[:20]
    ]

    # panel10_attacks: AttackEntry[] — populated by analyze endpoint
    panel10_attacks = capture.attacks

    # TCP Expert Info — Wireshark식 흐름 이상 집계 (재전송·dup-ack·zero-window)
    expert_info = tcp_expert.aggregate(getattr(capture, "packet_map", {}) or {})

    return {
        "panel1_ip": {"top_src": ip_result.top_src, "top_dst": ip_result.top_dst},
        "panel2_protocol": {
            "distribution": proto_result.distribution,
            "top_ports": proto_result.top_ports,
        },
        "panel3_timeline": {"buckets": timeline_result.buckets},
        "panel4_http": {
            "counts": http_result.counts,
            "groups": http_result.groups,
            "top_errors": http_result.top_errors,
        },
        "panel5_anomalies": panel5_anomalies,
        "panel6_ip_ranking": panel6_ip_ranking,
        "panel7_tls": {"entries": tls_result.entries, "no_meta_count": tls_result.port443_no_meta},
        "panel8_dns": dns_result.entries,
        "panel9_conversations": panel9_conversations,
        "panel10_attacks": panel10_attacks,
        "expert_info": expert_info,
    }
