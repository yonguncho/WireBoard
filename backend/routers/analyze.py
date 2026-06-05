"""POST /api/analyze — 세션 분석 + 공격 탐지."""
import asyncio
import gc
import logging
import re
import time
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.flow_extractor import FlowExtractor
from services.attack_detector.portscan_detector import PortScanDetector
from services.attack_detector.beacon_detector import BeaconDetector
from services.attack_detector.comm_failure_detector import CommFailureDetector
from services.attack_detector.ddos_detector import DDoSDetector
from services.attack_detector.exfiltration_detector import ExfiltrationDetector
from services.attack_detector.bruteforce_detector import BruteForceDetector

router = APIRouter()

_UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_IP_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_DETECTORS = [
    PortScanDetector(),
    BeaconDetector(),
    CommFailureDetector(),
    DDoSDetector(),
    ExfiltrationDetector(),
    BruteForceDetector(),
]


class AnalyzeRequest(BaseModel):
    upload_id: str
    target_ip: str | None = None


@router.post("/api/analyze")
async def analyze(req_body: AnalyzeRequest, request: Request):
    if not _UUID_V4_RE.match(req_body.upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be UUID v4"})

    if req_body.target_ip is not None and not _IP_RE.match(req_body.target_ip):
        raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": "target_ip must be a valid IPv4 address"})

    logger.info("분석 요청: upload_id=%s target_ip=%s", req_body.upload_id, req_body.target_ip)
    store = request.app.state.session_store
    try:
        capture = store.get(req_body.upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", req_body.upload_id)
        raise HTTPException(status_code=404, detail="upload_id를 찾을 수 없습니다")

    start_time = time.perf_counter()

    sessions = capture.sessions

    if req_body.target_ip is not None:
        effective_target_ip = req_body.target_ip
    else:
        src_counts = Counter(s.src_ip for s in sessions)
        effective_target_ip = src_counts.most_common(1)[0][0] if src_counts else ""
        logger.info("target_ip 자동 감지: %s", effective_target_ip)

    target_sessions = [
        s for s in sessions
        if s.src_ip == effective_target_ip or s.dst_ip == effective_target_ip
    ]
    extractor = FlowExtractor()
    flows = extractor.extract(target_sessions)

    attacks = []
    for detector in _DETECTORS:
        try:
            result = detector.detect(target_sessions)
        except Exception as exc:
            logger.error("detector 예외: detector=%s error=%s", type(detector).__name__, exc)
            attacks.append({
                "attack_type": "ERROR",
                "severity": "unknown",
                "mitre_id": "",
                "description": f"{type(detector).__name__} failed: {exc}",
                "detector_error": True,
            })
            continue
        if result is not None:
            attacks.append({
                "attack_type": result.attack_type,
                "severity": result.severity,
                "mitre_id": result.mitre_id,
                "description": result.description,
            })

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

    del sessions, target_sessions, flows, capture
    await asyncio.get_running_loop().run_in_executor(None, gc.collect)

    return {
        "flows": flow_dicts,
        "sessions": session_dicts,
        "attacks": attacks,
        "plotly_xs": plotly_xs,
        "plotly_ys": plotly_ys,
        "analysis_duration_ms": duration_ms,
        "target_ip": effective_target_ip,
    }
