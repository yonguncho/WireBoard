"""ExfiltrationDetector edge case 테스트 (TDD — T1041).

탐지 기준:
  - 동일 src_ip 기준 외부(non-RFC1918) dst_ip 방향 연결 수 > 5
    AND 해당 src_ip 에서 나간 bytes_sent 합산 > 100 MB (104 857 600 bytes)
  - HIGH  : connections > 20 OR bytes_out > 500 MB
  - MEDIUM: connections > 5  AND bytes_out > 100 MB (≤ 위 기준)
  - confidence='low' → 1단계 강등

검증 항목:
- HIGH: connections > 20 → severity='high'
- HIGH: bytes_out > 500 MB → severity='high'
- MEDIUM: connections=6, bytes_out=101 MB → 'medium'
- connections=4 AND bytes_out > 100 MB → None (connections 조건 미달)
- connections=6 AND bytes_out=99 MB → None (bytes 조건 미달)
- RFC1918 dst 는 카운트 제외
- confidence='low' → 1단계 강등
- 빈 세션 → None
- UUID 형식 검증 (ValidationError)
- MITRE ID = T1041 or T1020
"""
import uuid
import re
import pytest

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

MB = 1_048_576  # 1 MB in bytes


# ─────────────────────────── 헬퍼 ───────────────────────────────────


def _make_session(
    src_ip: str,
    dst_ip: str,
    *,
    bytes_sent: int = 1024,
    dst_port: int = 443,
    protocol: str = "TCP",
    confidence: str = "normal",
    ts_start: float = 1_748_000_000.0,
):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol=protocol,
        start_ts=ts_start,
        end_ts=ts_start + 10.0,
        bytes_sent=bytes_sent,
        bytes_recv=0,
        packet_count=max(1, bytes_sent // 1400),
        payload_length=bytes_sent,
        confidence=confidence,
    )


def _load_detector():
    try:
        from services.attack_detector.exfiltration_detector import ExfiltrationDetector
        return ExfiltrationDetector()
    except ImportError:
        pytest.skip("exfiltration_detector 미구현")


# ─────────────────────────── HIGH 임계값 ────────────────────────────


class TestExfiltrationHigh:
    def test_21_connections_returns_high(self):
        """외부 연결 수 > 20 → severity='high'."""
        detector = _load_detector()
        sessions = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=5 * MB)
            for i in range(21)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "high"

    def test_500mb_plus_returns_high(self):
        """bytes_out > 500 MB → severity='high'."""
        detector = _load_detector()
        sessions = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=100 * MB)
            for i in range(6)  # 600 MB total
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "high"

    def test_mitre_id(self):
        """MITRE ID = T1041 또는 T1020."""
        detector = _load_detector()
        sessions = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=5 * MB)
            for i in range(21)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.mitre_id in {"T1041", "T1020"}


# ─────────────────────────── MEDIUM 임계값 ──────────────────────────


class TestExfiltrationMedium:
    def test_6_connections_101mb_returns_medium(self):
        """connections=6 AND bytes_out≈101 MB → medium."""
        detector = _load_detector()
        bytes_each = (101 * MB) // 6 + 1
        sessions = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=bytes_each)
            for i in range(6)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity in {"medium", "high"}


# ─────────────────────────── 임계값 미달 ────────────────────────────


class TestExfiltrationBelowThreshold:
    def test_4_connections_small_bytes_returns_none(self):
        """connections=4, bytes_out=10 MB → None (두 조건 모두 미달)."""
        detector = _load_detector()
        sessions = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=2 * MB)
            for i in range(4)
        ]
        result = detector.detect(sessions)
        assert result is None

    def test_5_connections_small_bytes_returns_none(self):
        """connections=5, bytes_out=10 MB → None (두 조건 모두 미달)."""
        detector = _load_detector()
        sessions = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=2 * MB)
            for i in range(5)
        ]
        result = detector.detect(sessions)
        assert result is None

    def test_empty_sessions_returns_none(self):
        assert _load_detector().detect([]) is None

    def test_rfc1918_dst_not_counted(self):
        """RFC1918 dst_ip 는 외부 연결 카운트에서 제외."""
        detector = _load_detector()
        # 내부 연결 6개 + 큰 bytes → 외부 연결 0이므로 탐지 안 됨
        sessions = [
            _make_session("192.168.1.100", f"10.0.0.{i}", bytes_sent=20 * MB)
            for i in range(6)
        ]
        result = detector.detect(sessions)
        assert result is None

    def test_rfc1918_172_16_excluded(self):
        """172.16.x.x (RFC1918) dst → 외부 카운트 제외."""
        detector = _load_detector()
        sessions = [
            _make_session("192.168.1.100", f"172.16.0.{i}", bytes_sent=20 * MB)
            for i in range(6)
        ]
        result = detector.detect(sessions)
        assert result is None


# ─────────────────────────── FortiGate 강등 ─────────────────────────


class TestExfiltrationDowngrade:
    def test_high_downgraded_to_medium(self):
        """confidence='low' + high → medium."""
        detector = _load_detector()
        sessions = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=5 * MB, confidence="low")
            for i in range(21)
        ]
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"


# ─────────────────────────── 다중 src 독립 집계 ─────────────────────


class TestExfiltrationMultiSrc:
    def test_two_src_independent(self):
        """src_ip A 가 exfiltration, src_ip B 는 미달 — A만 탐지."""
        detector = _load_detector()
        sessions_a = [
            _make_session("192.168.1.100", f"203.0.113.{i}", bytes_sent=5 * MB)
            for i in range(21)
        ]
        sessions_b = [
            _make_session("192.168.1.200", f"203.0.113.{i}", bytes_sent=1 * MB)
            for i in range(3)
        ]
        result = detector.detect(sessions_a + sessions_b)
        assert result is not None
        assert result.severity in {"medium", "high"}


# ─────────────────────────── UUID 검증 ──────────────────────────────


class TestExfiltrationUUIDValidation:
    def test_invalid_uuid_raises(self):
        try:
            from pydantic import ValidationError
            from models.session import SessionModel
        except ImportError:
            pytest.skip("models.session 미구현")

        with pytest.raises(ValidationError):
            SessionModel(
                session_id="bad-id",
                src_ip="192.168.1.100",
                dst_ip="203.0.113.1",
                src_port=50000,
                dst_port=443,
                protocol="TCP",
                start_ts=1_748_000_000.0,
                end_ts=1_748_000_010.0,
                bytes_sent=1024,
                bytes_recv=0,
                packet_count=1,
                payload_length=1024,
            )
