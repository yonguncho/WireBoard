"""POST /api/analyze — 세션 분석 + 공격 탐지."""
import asyncio
import ipaddress
import logging
import time
from collections import Counter
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.flow_extractor import FlowExtractor
from services.attack_detector.portscan_detector import PortScanDetector
from services.attack_detector.beacon_detector import BeaconDetector
from services.attack_detector.comm_failure_detector import CommFailureDetector
from services.attack_detector.dos_detector import DoSDetector
from services.attack_detector.ddos_detector import DDoSDetector
from services.attack_detector.exfiltration_detector import ExfiltrationDetector
from services.attack_detector.bruteforce_detector import BruteForceDetector
from services.reputation_service import ReputationService
from utils.constants import UUID_V4_RE
from utils.capture_auth import check_capture_token

_reputation_svc = ReputationService()

router = APIRouter()

_DETECTORS = [
    PortScanDetector(),
    BeaconDetector(),
    CommFailureDetector(),
    DoSDetector(),
    DDoSDetector(),
    ExfiltrationDetector(),
    BruteForceDetector(),
]


class AnalyzeRequest(BaseModel):
    upload_id: str
    target_ip: Optional[str] = None


def _auto_detect_target_ip(sessions) -> Optional[str]:
    """세션에서 가장 많이 등장하는 IP를 target_ip로 자동 감지."""
    counter: Counter = Counter()
    for s in sessions:
        counter[s.src_ip] += 1
        counter[s.dst_ip] += 1
    if not counter:
        return None
    return counter.most_common(1)[0][0]


@router.post("/api/analyze")
async def analyze(
    req_body: AnalyzeRequest,
    request: Request,
    x_upload_token: str | None = Header(None, alias="X-Upload-Token"),
):
    if not UUID_V4_RE.match(req_body.upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be UUID v4"})

    if req_body.target_ip is not None:
        try:
            ipaddress.ip_address(req_body.target_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": "target_ip must be a valid IP address"})

    logger.info("분석 요청: upload_id=%s target_ip=%s", req_body.upload_id, req_body.target_ip)
    store = request.app.state.session_store
    try:
        capture = store.get(req_body.upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", req_body.upload_id)
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    check_capture_token(capture, x_upload_token)
    start_time = time.perf_counter()

    sessions = capture.sessions
    # target_ip가 None이면 자동 감지
    effective_target_ip = req_body.target_ip if req_body.target_ip else _auto_detect_target_ip(sessions)

    target_sessions = [
        s for s in sessions
        if s.src_ip == effective_target_ip or s.dst_ip == effective_target_ip
    ]
    if not target_sessions:
        try:
            rep = await asyncio.wait_for(_reputation_svc.lookup_all(effective_target_ip), timeout=2.0)
            rep_dict = rep.model_dump()
        except Exception:
            rep_dict = {"ip": effective_target_ip, "is_malicious": False, "sources": []}
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return JSONResponse(content={
            "flows": [], "sessions": [], "attacks": [],
            "plotly_xs": [], "plotly_ys": [],
            "analysis_duration_ms": duration_ms,
            "target_ip": effective_target_ip,
            "partial_failure": False,
            "reputation": rep_dict,
        }, status_code=200)

    extractor = FlowExtractor()
    flows = extractor.extract(target_sessions)

    loop = asyncio.get_running_loop()

    async def _run_one(det):
        try:
            res = await loop.run_in_executor(None, det.detect, target_sessions)
        except Exception as exc:
            logger.error("detector 예외: detector=%s error=%s", type(det).__name__, exc)
            return {
                "attack_type": "ERROR",
                "severity": "unknown",
                "mitre_id": "",
                "description": f"{type(det).__name__} failed: {exc}",
                "detector_error": True,
            }
        if res is None:
            return None
        return {
            "attack_type": res.attack_type,
            "severity": res.severity,
            "mitre_id": res.mitre_id,
            "description": res.description,
            "src_ip": res.src_ip,
        }

    raw_results = await asyncio.gather(*[_run_one(d) for d in _DETECTORS])
    attacks = [r for r in raw_results if r is not None]

    flow_dicts = [
        {
            "flow_id": f.flow_id,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol,
            "start_ts": f.start_ts,
            "end_ts": f.end_ts,
            "bytes_total": f.bytes_total,
        }
        for f in flows
    ]

    session_dicts = [s.model_dump() for s in target_sessions]

    plotly_xs, plotly_ys = extractor.build_plotly_data(flows)

    duration_ms = (time.perf_counter() - start_time) * 1000.0
    logger.info("분석 완료: upload_id=%s attacks=%d duration_ms=%.1f",
                req_body.upload_id, len(attacks), duration_ms)

    try:
        store.update_analysis(req_body.upload_id, effective_target_ip, attacks)
    except KeyError:
        logger.warning("분석 결과 저장 실패 (세션 만료): upload_id=%s", req_body.upload_id)

    try:
        rep = await asyncio.wait_for(_reputation_svc.lookup_all(effective_target_ip), timeout=2.0)
        rep_dict = rep.model_dump()
    except Exception:
        rep_dict = {"ip": effective_target_ip, "is_malicious": False, "sources": []}

    del sessions, target_sessions, flows, capture

    partial_failure = any(a.get("detector_error") for a in attacks)
    response_body = {
        "flows": flow_dicts,
        "sessions": session_dicts,
        "attacks": attacks,
        "plotly_xs": plotly_xs,
        "plotly_ys": plotly_ys,
        "analysis_duration_ms": duration_ms,
        "target_ip": effective_target_ip,
        "partial_failure": partial_failure,
        "reputation": rep_dict,
    }
    return JSONResponse(content=response_body, status_code=207 if partial_failure else 200)
