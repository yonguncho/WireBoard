"""Capture → 위험 요약 오케스트레이션 — summary/export 라우터 공용 헬퍼.

network_health.analyze(순수 CPU 작업)와 build_summary를 한 곳에서 묶는다.
라우터에서는 이벤트 루프를 막지 않도록 run_in_executor로 호출할 것.
"""
import logging

from services.analytics import network_health
from services.narrative.summary_builder import NarrativeResult, build_summary

logger = logging.getLogger(__name__)


def summarize_capture(capture) -> NarrativeResult:
    """세션+패킷맵으로 health 진단을 수행한 뒤 위험 요약을 생성한다.

    health 분석 실패는 치명적이지 않다(요약은 진단 없이 계속).
    """
    health = None
    try:
        health = network_health.analyze(
            capture.sessions,
            getattr(capture, "packet_map", {}) or {},
            getattr(capture, "icmp_events", []) or [],
        )
    except Exception as exc:  # 진단은 best-effort — 요약 자체를 깨지 않는다
        logger.warning("network_health 분석 실패 (요약은 계속): %s", exc)
    return build_summary(capture.attacks, capture.sessions, health=health)
