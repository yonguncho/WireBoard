"""POST /api/analyze — 세션 분석 + 공격 탐지."""
import asyncio
import gc
import logging
import time
from collections import Counter
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from services.flow_extractor import FlowExtractor
from services.attack_detector.portscan_detector import PortScanDetector
from services.attack_detector.beacon_detector import BeaconDetector
from services.attack_detector.comm_failure_detector import CommFailureDetector
from services.attack_detector.ddos_detector import DDoSDetector
from services.attack_detector.exfiltration_detector import ExfiltrationDetector
from services.attack_detector.bruteforce_detector import BruteForceDetector
from services.reputation_service import ReputationService
from utils.constants import UUID_V4_RE, IPv4_RE

_reputation_svc = ReputationService()

router = APIRouter()

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
    if not UUID_V4_RE.match(req_body.upload_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_uuid", "msg": "upload_id must be UUID v4"})

    if req_body.target_ip is not None and not IPv4_RE.match(req_body.target_ip):
        raise HTTPException(status_code=400, detail={"code": "invalid_ip", "msg": "target_ip must be a valid IPv4 address"})

    logger.info("분석 요청: upload_id=%s target_ip=%s", req_body.upload_id, req_body.target_ip)
    store = request.app.state.session_store
    try:
        capture = store.get(req_body.upload_id)
    except KeyError:
        logger.warning("upload_id 없음: %s", req_body.upload_id)
        raise HTTPException(status_code=404, detail={"code": "upload_not_found", "message": "업로드 파일 없음"})

    start_time = time.perf_counter()

    sessions = capture.sessions

    if req_body.target_ip is not None:
        effective_target_ip = req_body.target_ip
    else:
        if not sessions:
            raise HTTPException(
                status_code=422,
                detail={"code": "no_sessions", "msg": "캡처 파일에 분석 가능한 세션이 없습니다"},
            )
        # src+dst 양방향으로 등장 횟수 집계 → 가장 중심적인 호스트 선택
        ip_counts: Counter = Counter()
        for s in sessions:
            ip_counts[s.src_ip] += 1
            ip_counts[s.dst_ip] += 1
        effective_target_ip = ip_counts.most_common(1)[0][0]
        logger.info("target_ip 자동 감지: %s", effective_target_ip)

    target_sessions = [
        s for s in sessions
        if s.src_ip == effective_target_ip or s.dst_ip == effective_target_ip
    ]
    if not target_sessions:
        raise HTTPException(
            status_code=422,
            detail={"code": "no_matching_sessions", "msg": f"target_ip {effective_target_ip!r}에 해당하는 세션이 없습니다"},
        )
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
    await asyncio.get_running_loop().run_in_executor(None, gc.collect)

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
