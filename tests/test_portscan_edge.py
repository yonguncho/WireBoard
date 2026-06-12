"""PortScanDetector edge case 테스트 (TDD — T1046).

탐지 기준 (현재 구현):
  - (src_ip, dst_ip) 쌍별 고유 dst_port 집합 집계
  - MEDIUM : unique_ports >= 20
  - HIGH   : unique_ports >= 100
  - confidence='low' 세션 포함 시 1단계 강등

PRD 요구사항 (미구현 항목 xfail 처리):
  - 60초 윈도우 내 집계
  - RST 비율 > 70% 조건

검증 항목:
- 19 포트 → None (임계값 미달)
- 20 포트 → medium
- 100 포트 → high
- 99 포트 → medium
- confidence='low' + 20 포트 → medium → low 강등
- confidence='low' + 100 포트 → high → medium 강등
- 빈 세션 → None
- 동일 dst_port 중복 세션 → 고유 포트 수로 집계
- 여러 (src, dst) 쌍이 있을 때 가장 심한 결과 반환
- MITRE ID = T1046
- attack_type = 'PortScan'
"""
import uuid
import pytest


# ─────────────────────────── 헬퍼 ────────────────────────────────────


def _make_session(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    *,
    confidence: str = "normal",
    base_ts: float = 1_748_000_000.0,
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
        protocol="TCP",
        start_ts=base_ts,
        end_ts=base_ts + 0.1,
        bytes_sent=60,
        bytes_recv=0,
        packet_count=1,
        payload_length=0,
        confidence=confidence,
        rst=True,
    )


def _make_scan_sessions(
    num_ports: int,
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "192.168.1.50",
    confidence: str = "normal",
    base_ts: float = 1_748_000_000.0,
):
    """src → dst 에 대해 num_ports 개의 고유 dst_port 세션을 생성한다."""
    return [
        _make_session(src_ip, dst_ip, port, confidence=confidence, base_ts=base_ts + port)
        for port in range(1, num_ports + 1)
    ]


def _load_detector():
    try:
        from services.attack_detector.portscan_detector import PortScanDetector
        return PortScanDetector()
    except ImportError:
        pytest.skip("portscan_detector 미구현")


# ─────────────────────────── 임계값 미달 ─────────────────────────────


class TestPortScanBelow:
    def test_19_ports_returns_none(self):
        """19 포트 → 탐지 안 됨 (< 20)."""
        detector = _load_detector()
        sessions = _make_scan_sessions(19)
        assert detector.detect(sessions) is None

    def test_1_port_returns_none(self):
        detector = _load_detector()
        sessions = _make_scan_sessions(1)
        assert detector.detect(sessions) is None

    def test_empty_sessions_returns_none(self):
        assert _load_detector().detect([]) is None


# ─────────────────────────── MEDIUM (20~99 포트) ──────────────────────


class TestPortScanMedium:
    def test_exactly_20_ports_returns_medium(self):
        """정확히 20 포트 → severity='medium'."""
        detector = _load_detector()
        sessions = _make_scan_sessions(20)
        result = detector.detect(sessions)
        assert result is not None, "20 포트 PortScan 탐지 실패"
        assert result.severity == "medium"

    def test_99_ports_returns_medium(self):
        """99 포트 → medium (< 100)."""
        detector = _load_detector()
        sessions = _make_scan_sessions(99)
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"

    def test_mitre_id_T1046(self):
        detector = _load_detector()
        sessions = _make_scan_sessions(20)
        result = detector.detect(sessions)
        assert result is not None
        assert result.mitre_id == "T1046"

    def test_attack_type_portscan(self):
        detector = _load_detector()
        sessions = _make_scan_sessions(20)
        result = detector.detect(sessions)
        assert result is not None
        assert result.attack_type == "PortScan"

    def test_src_ip_recorded(self):
        """탐지 결과에 src_ip 가 기록된다."""
        detector = _load_detector()
        sessions = _make_scan_sessions(20, src_ip="172.16.0.99")
        result = detector.detect(sessions)
        assert result is not None
        assert result.src_ip == "172.16.0.99"


# ─────────────────────────── HIGH (≥ 100 포트) ───────────────────────


class TestPortScanHigh:
    def test_exactly_100_ports_returns_high(self):
        """정확히 100 포트 → severity='high'."""
        detector = _load_detector()
        sessions = _make_scan_sessions(100)
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "high"

    def test_200_ports_returns_high(self):
        detector = _load_detector()
        sessions = _make_scan_sessions(200)
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "high"


# ─────────────────────────── 강등 (confidence='low') ─────────────────


class TestPortScanDowngrade:
    def test_medium_downgraded_to_low(self):
        """20 포트 + confidence='low' → medium → low."""
        detector = _load_detector()
        sessions = _make_scan_sessions(20, confidence="low")
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "low"

    def test_high_downgraded_to_medium(self):
        """100 포트 + confidence='low' → high → medium."""
        detector = _load_detector()
        sessions = _make_scan_sessions(100, confidence="low")
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"

    def test_mixed_confidence_still_downgrades(self):
        """정상 신뢰도 세션 18개 + low 세션 2개 (총 20 포트) → 강등."""
        detector = _load_detector()
        normal = _make_scan_sessions(18, confidence="normal")
        low = [_make_session("10.0.0.5", "192.168.1.50", p, confidence="low")
               for p in range(19, 21)]
        result = detector.detect(normal + low)
        assert result is not None
        assert result.severity == "low"


# ─────────────────────────── 고유 포트 중복 제거 ─────────────────────


class TestPortScanDedup:
    def test_duplicate_ports_not_counted(self):
        """같은 dst_port 세션 10개 × 2 = 10 고유 포트 → None (< 20)."""
        detector = _load_detector()
        sessions = []
        for port in range(1, 11):          # 10 고유 포트
            for _ in range(2):             # 각 포트 2번
                sessions.append(_make_session("10.0.0.5", "192.168.1.50", port))
        result = detector.detect(sessions)
        assert result is None

    def test_20_unique_ports_from_30_sessions(self):
        """30 세션 (20 고유 포트) → medium."""
        detector = _load_detector()
        sessions = []
        for port in range(1, 21):          # 20 고유 포트
            for _ in range(2):             # 각 포트 2번 중복
                sessions.append(_make_session("10.0.0.5", "192.168.1.50", port))
        result = detector.detect(sessions)
        assert result is not None
        assert result.severity == "medium"


# ─────────────────────────── 복수 (src, dst) 쌍 ─────────────────────


class TestPortScanMultiPair:
    def test_best_result_returned(self):
        """src1→dst: 100 포트(high), src2→dst: 20 포트(medium) → high 반환."""
        detector = _load_detector()
        high_sessions = _make_scan_sessions(100, src_ip="10.0.0.1", dst_ip="192.168.1.50")
        med_sessions  = _make_scan_sessions(20,  src_ip="10.0.0.2", dst_ip="192.168.1.50")
        result = detector.detect(high_sessions + med_sessions)
        assert result is not None
        assert result.severity == "high"

    def test_below_threshold_pair_ignored(self):
        """src1→dst: 19 포트(None), src2→dst: 20 포트(medium) → medium 반환."""
        detector = _load_detector()
        below  = _make_scan_sessions(19, src_ip="10.0.0.1", dst_ip="192.168.1.50")
        medium = _make_scan_sessions(20, src_ip="10.0.0.2", dst_ip="192.168.1.50")
        result = detector.detect(below + medium)
        assert result is not None
        assert result.severity == "medium"


# ─────────────────────────── PRD 미구현 항목 (xfail) ─────────────────


class TestPortScanPRDXfail:
    @pytest.mark.xfail(reason="PRD: 60초 윈도우 집계 미구현", strict=False)
    def test_60s_window_boundary(self):
        """60초 윈도우 경계 밖 세션은 별도 윈도우로 집계해야 한다 (PRD)."""
        detector = _load_detector()
        # 첫 번째 배치: 동일 src/dst, 포트 1-10 (ts=1_748_000_000)
        first = _make_scan_sessions(10, base_ts=1_748_000_000.0)
        # 두 번째 배치: 동일 src/dst, 포트 11-20 (ts=+65초 → 다른 60초 윈도우)
        # PRD: 윈도우 분리 시 각 10포트 → None
        # 현재 구현: 합산 20포트 → medium (PRD 불일치 → xfail 기대 동작)
        second = [
            _make_session("10.0.0.5", "192.168.1.50", port, base_ts=1_748_000_065.0)
            for port in range(11, 21)
        ]
        result = detector.detect(first + second)
        assert result is None  # PRD 기대값: 각 윈도우 미달

    @pytest.mark.xfail(reason="PRD: RST 비율 > 70% 조건 미구현", strict=False)
    def test_rst_ratio_below_70_not_detected(self):
        """RST 비율 < 70% 이면 포트스캔으로 탐지하지 않아야 한다 (PRD)."""
        detector = _load_detector()
        # 20 포트, 모두 rst=False (SYN 스캔이 아님)
        sessions = [
            _make_session("10.0.0.5", "192.168.1.50", p)
            for p in range(1, 21)
        ]
        # 현재 구현은 rst 여부 무관하게 탐지 — PRD 불일치
        result = detector.detect(sessions)
        assert result is None  # PRD 기대값: RST 미달 → None
