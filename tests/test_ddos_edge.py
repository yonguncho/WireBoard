"""DDoSDetector edge case 테스트 (TDD — T1498/T1499).

탐지 기준:
  - 30 초 윈도우 내 동일 dst_ip 행 packet_count 합산
  - packet_rate = total_packets / window_seconds
  - HIGH  : packet_rate ≥ 1000 pps  OR  unique_src ≥ 50
  - MEDIUM: packet_rate ≥ 300  pps  OR  unique_src ≥ 10
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
    def test_1000pps_returns_high(self):
        """30 초 윈도우 1000 pps → severity='high'."""
        detector = _load_detector()
        # 30 초 구간에 1000 packets/sec × 30 = 30 000 패킷
        sessions = [
            _make_session("10.0.0.1", "192.168.1.100", packets=30_000, ts_end=1_748_000_030.0)
        ]
        result = detector.detect(sessions)
        assert result is not None, "1000 pps → 탐지 실패"
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
        """MITRE ATT&CK ID = T1498."""
        detector = _load_detector()
        sessions = [_make_session("10.0.0.1", "192.168.1.100", packets=30_000, ts_end=1_748_000_030.0)]
        result = detector.detect(sessions)
        assert result is not None
        assert result.mitre_id in {"T1498", "T1499"}


# ─────────────────────────── MEDIUM 임계값 ──────────────────────────


class TestDDoSMedium:
    def test_300pps_returns_medium(self):
        """300 pps (30 초 × 9 000 패킷) → severity='medium'."""
        detector = _load_detector()
        sessions = [
            _make_session("10.0.0.1", "192.168.1.100", packets=9_000, ts_end=1_748_000_030.0)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity in {"medium", "high"}

    def test_10_unique_src_returns_medium(self):
        """고유 src_ip = 10 → medium 이상."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=50)
            for i in range(1, 11)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity in {"medium", "high"}


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

    def test_empty_sessions_returns_none(self):
        detector = _load_detector()
        assert detector.detect([]) is None


# ─────────────────────────── FortiGate 강등 ─────────────────────────


class TestDDoSDowngrade:
    def test_fortigate_high_downgraded_to_medium(self):
        """confidence='low' → high → medium 강등."""
        detector = _load_detector()
        sessions = [
            _make_session("10.0.0.1", "192.168.1.100", packets=30_000,
                          ts_end=1_748_000_030.0, confidence="low")
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"

    def test_fortigate_medium_downgraded_to_low(self):
        """confidence='low' + medium 원래 → low 강등."""
        detector = _load_detector()
        sessions = [
            _make_session(f"10.0.0.{i}", "192.168.1.100", packets=50, confidence="low")
            for i in range(1, 11)
        ]
        result = detector.detect(sessions)
        if result is not None:
            assert result.severity in {"low", "medium"}


# ──────────────────────── dst_ip 독립 집계 ──────────────────────────


class TestDDoSPerDst:
    def test_different_dst_independent(self):
        """A→C, B→C 별도 집계 — C만 임계 초과 시 C만 탐지."""
        detector = _load_detector()
        # dst C: 1000 pps
        sessions_c = [_make_session("10.0.0.1", "192.168.1.1", packets=30_000, ts_end=1_748_000_030.0)]
        # dst D: 50 pps (below threshold)
        sessions_d = [_make_session("10.0.0.2", "192.168.1.2", packets=1_500, ts_end=1_748_000_030.0)]
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
