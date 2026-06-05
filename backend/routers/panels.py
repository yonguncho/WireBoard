"""GET /api/panels/{upload_id} — 패널 통합 분석 결과."""
import logging

from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger(__name__)

from services.analytics.ip_analyzer import IpAnalyzer
from services.analytics.protocol_stats import ProtocolStats
from services.analytics.flow_timeline import FlowTimeline
from services.analytics.http_status_analyzer import HttpStatusAnalyzer
from services.analytics.rst_analyzer import RstAnalyzer
from services.analytics.conversation_analyzer import ConversationAnalyzer
from services.analytics.tls_analyzer import TlsAnalyzer
from services.analytics.dns_analyzer import DnsAnalyzer

router = APIRouter()

_ip_analyzer = IpAnalyzer()
_proto_stats = ProtocolStats()
_flow_timeline = FlowTimeline(window_seconds=60)
_http_analyzer = HttpStatusAnalyzer()
_rst_analyzer = RstAnalyzer()
_conv_analyzer = ConversationAnalyzer()
_tls_analyzer = TlsAnalyzer()
_dns_analyzer = DnsAnalyzer()


@router.get("/api/panels/{upload_id}")
async def get_panels(upload_id: str, request: Request):
    logger.info("패널 요청: upload_id=%s", upload_id)
    store = request.app.state.session_store
    try:
        capture = store.get(upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", upload_id)
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    sessions = capture.sessions

    ip_result = _ip_analyzer.analyze(sessions)
    proto_result = _proto_stats.compute(sessions)
    timeline_result = _flow_timeline.compute(sessions)
    http_result = _http_analyzer.analyze(sessions)
    rst_result = _rst_analyzer.analyze(sessions)
    conv_result = _conv_analyzer.analyze(sessions)
    tls_result = _tls_analyzer.analyze(sessions)
    dns_result = _dns_analyzer.analyze(sessions)

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
        "panel5_rst": {
            "rst_by_src": rst_result.rst_by_src,
            "high_rst_ips": rst_result.high_rst_ips,
            "malformed_count": rst_result.malformed_count,
        },
        "panel9_conversation": {
            "top_conversations": conv_result.top_conversations,
        },
        "panel7_tls": {
            "sni_counts": tls_result.sni_counts,
            "tls_versions": tls_result.tls_versions,
        },
        "panel8_dns": {
            "query_counts": dns_result.query_counts,
            "nxdomain_count": dns_result.nxdomain_count,
        },
    }
