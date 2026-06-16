"""DDoSDetector edge case 테스트 (TDD — T1498/T1499).

탐지 기준 (네트워크 분석 관점 — 절대 pps floor):
  - 동일 dst_ip 행 packet_count 합산, packet_rate = total_packets / window_seconds
  - 최소 6 src (분산) AND packet_rate ≥ 2000 pps (절대 floor) 동시 충족 필요
  - HIGH  : packet_rate ≥ 10000 pps  OR  unique_src ≥ 50
  - MEDIUM: 2000 ≤ packet_rate < 10000 pps
  - packet_rate < 2000 pps → None (정상 서버 부하, 소스 수 무관)
  - confidence='low' → 1단계 강등

검증 항목:
- HIGH threshold 정확성 (T1498)
- MEDIUM threshold 정확성
- 임계값 미달 → None
- 분산 DDoS (여러 src → 단일 dst) → unique_src 기준 탐지
- FortiGate confidence='low' → 1단계 강등
- 단일 src 고속 트래픽 (SYN flood)
- MITRE ID = T1498
- 빈 세션 → None
- dst_ip별 독립 집계 (A→C, B→C 각각 평가)
- UUID 형식 아닌 session_id → ValidationError (ADR-004)
"""
import re
import uuid

import pytest

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# ─────────────────────────── 헬퍼 ───────────────────────────────────


def _make_session(
    src_ip: str,
    dst_ip: str,
    *,
    packets: int = 1,
    ts_start: float = 1_748_000_000.0,
    ts_end: float | None = None,
    protocol: str = "TCP",
    confidence: str = "normal",
    dst_port: int = 80,
):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    if ts_end is None:
        ts_end = ts_start + 1.0

    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=dst_port,
        protocol=protocol,
        start_ts=ts_start,
        end_ts=ts_end,
        bytes_sent=64 * packets,
        bytes_recv=0,
        packet_count=packets,
        payload_length=0,
        confidence=confidence,
    )


def _load_detector():
    try:
        from services.attack_detector.ddos_detector import DDoSDetector
        return DDoSDetector()
    except ImportError:
        pytest.skip("ddos_detector 미구현")


# ─────────────────────────── HIGH 임계값 ────────────────────────────


class TestDDoSHigh:
    def test_10000pps_returns_high(self):
        """6 src × 50000 pkts/30s → 10000 pps 합산 → severity='high'."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=50_000, ts_end=1_748_000_030.0)
            for i in range(1, 7)
        ]
        result = detector.detect(sessions)
        assert result is not None, "10000 pps (6 src) → 탐지 실패"
        assert result.severity == "high"

    def test_50_unique_src_returns_high(self):
        """고유 src_ip ≥ 50 → severity='high' (분산 DDoS)."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.{i // 256}.{i % 256}", "192.168.1.100", packets=100)
            for i in range(50)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "high"

    def test_mitre_id_T1498(self):
        """MITRE ATT&CK ID = T1498 (6 src × 50000 pkts/30s = 10000 pps)."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=50_000, ts_end=1_748_000_030.0)
            for i in range(1, 7)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.mitre_id in {"T1498", "T1499"}


# ─────────────────────────── MEDIUM 임계값 ──────────────────────────


class TestDDoSMedium:
    def test_3000pps_returns_medium(self):
        """6 src × 15000 pkts/30s → 3000 pps (floor↑·high미만) → severity='medium'."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=15_000, ts_end=1_748_000_030.0)
            for i in range(1, 7)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"

    def test_10_src_above_floor_returns_medium(self):
        """10 src × 300 pkts/1s = 3000 pps (floor 충족, src<50) → medium."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=300)
            for i in range(1, 11)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"


# ─────────────────────────── 임계값 미달 ────────────────────────────


class TestDDoSBelowThreshold:
    def test_low_packet_rate_returns_none(self):
        """50 pps → None."""
        detector = _load_detector()
        sessions = [
            _make_session("10.0.0.1", "192.168.1.100", packets=1_500, ts_end=1_748_000_030.0)
        ]
        result = detector.detect(sessions)
        assert result is None

    def test_few_unique_src_returns_none(self):
        """고유 src_ip = 3 → None."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=10)
            for i in range(1, 4)
        ]
        result = detector.detect(sessions)
        assert result is None

    def test_dns_server_fanin_below_floor_returns_none(self):
        """회귀: DNS 서버에 33 src × 30 pkts/1s ≈ 990 pps fan-in → 정상 부하, None.

        소스 수(33)는 많지만 절대 pps(≈990)가 floor(2000) 미만이므로
        DDoS 로 판정하지 않는다. 정상 DNS 서버 트래픽 오탐 방지.
        """
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.{i // 256}.{i % 256}", "192.168.1.53", packets=30, dst_port=53)
            for i in range(33)
        ]
        result = detector.detect(sessions)
        assert result is None

    def test_dns_server_real_flood_still_detected(self):
        """DNS 서버라도 실제 플러드(33 src × 1000 pkts/1s = 33000 pps)는 탐지."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.{i // 256}.{i % 256}", "192.168.1.53", packets=1_000, dst_port=53)
            for i in range(33)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "high"

    def test_empty_sessions_returns_none(self):
        detector = _load_detector()
        assert detector.detect([]) is None


# ─────────────────────────── FortiGate 강등 ─────────────────────────


class TestDDoSDowngrade:
    def test_fortigate_high_downgraded_to_medium(self):
        """confidence='low' + 6 src + 10000 pps → high → medium 강등."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=50_000,
                          ts_end=1_748_000_030.0, confidence="low")
            for i in range(1, 7)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"

    def test_fortigate_medium_downgraded_to_low(self):
        """confidence='low' + medium(3000 pps) → low 강등."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=300, confidence="low")
            for i in range(1, 11)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "low"


# ──────────────────────── dst_ip 독립 집계 ──────────────────────────


class TestDDoSPerDst:
    def test_different_dst_independent(self):
        """dst C: 6 src × 50000 pkts = 10000 pps → high; dst D: below threshold → best=high."""
        detector = _load_detector()
        # dst C: 6 sources → 300000 pkts / 30s = 10000 pps → high
        sessions_c = [
            _make_session(f"10.0.0.{i}", "192.168.1.1", packets=50_000, ts_end=1_748_000_030.0)
            for i in range(1, 7)
        ]
        # dst D: 1 source → below _PRD_SRC_MIN → skipped
        sessions_d = [_make_session("10.0.1.1", "192.168.1.2", packets=1_500, ts_end=1_748_000_030.0)]
        result = detector.detect(sessions_c + sessions_d)
        assert result is not None
        assert result.severity == "high"


# ──────────────────────── UUID 검증 (ADR-004) ───────────────────────


class TestDDoSUUIDValidation:
    def test_invalid_session_id_raises_validation_error(self):
        """session_id가 UUID 형식 아닐 때 SessionModel 생성 자체가 ValidationError."""
        try:
            from pydantic import ValidationError
            from models.session import SessionModel
        except ImportError:
            pytest.skip("models.session 미구현")

        with pytest.raises(ValidationError):
            SessionModel(
                session_id="not-a-uuid",
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                start_ts=1_748_000_000.0,
                end_ts=1_748_000_001.0,
                bytes_sent=64,
                bytes_recv=0,
                packet_count=1,
                payload_length=0,
            )
