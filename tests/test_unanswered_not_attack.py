"""응답 없는 연결(방화벽 차단·서버 다운)은 공격 탐지 대상이 아니다.

2026-10-30 실사례(제안서용 장애 시나리오): 방화벽에 막힌 MES→DB(1433) 연결 재시도 15회가
'C2 beacon HIGH' + 'Brute force MEDIUM' 으로 오탐돼 PDF 보고서 위험도가 HIGH 로 나왔다.
"""
import uuid

from models.session import SessionModel
from services.attack_detector.beacon_detector import BeaconDetector
from services.attack_detector.bruteforce_detector import BruteForceDetector


def _s(i, *, recv=0, rst=False, meta=None):
    return SessionModel(session_id=str(uuid.uuid4()), src_ip="10.10.20.15", dst_ip="10.10.20.30",
                        src_port=60000 + i, dst_port=1433, protocol="TCP",
                        start_ts=1_793_000_000.0 + i * 4.0, end_ts=1_793_000_003.0 + i * 4.0,
                        bytes_sent=180, bytes_recv=recv, packet_count=3, payload_length=0, rst=rst, meta=meta)


def test_syn_timeouts_are_neither_beacon_nor_bruteforce():
    sessions = [_s(i) for i in range(15)]  # 4초 간격 SYN 재시도, 응답 없음
    assert BeaconDetector().detect(sessions) is None
    assert BruteForceDetector().detect(sessions) is None


def test_answered_periodic_connections_still_detected_as_beacon():
    sessions = [_s(i, recv=900) for i in range(15)]
    r = BeaconDetector().detect(sessions)
    assert r is not None and r.attack_type == "Beacon"


def test_server_rst_still_counts_as_failed_attempt():
    sessions = [_s(i, recv=60, rst=True) for i in range(15)]
    r = BruteForceDetector().detect(sessions)
    assert r is not None and r.attack_type == "BruteForce"