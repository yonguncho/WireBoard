"""PCAP 비교 분석 edge case 테스트 (TDD).

대상: services.analytics.pcap_comparator.PcapComparator

인터페이스 가정:
  PcapComparator().compare(sessions_a, sessions_b) -> CompareResult
  CompareResult:
    common_ips: set[str]          # A, B 공통 IP
    only_in_a: set[str]           # A에만 있는 IP
    only_in_b: set[str]           # B에만 있는 IP
    protocol_diff: dict           # {"TCP": {"a": n, "b": m, "diff_pct": float}}
    byte_ratio: dict              # {"a_total": int, "b_total": int, "ratio": float}

검증 항목:
- 공통 IP 정확성
- A 전용 / B 전용 IP 정확성
- 프로토콜 분포 차이 % 계산
- byte_ratio 계산 (a_total / b_total)
- 빈 A + 빈 B → 공통 없음
- 빈 A + 비어있지 않은 B → only_in_b = B IP 전부
- 동일 세션 셋 A==B → common_ips = 전체, only_in_a/b = 빈 셋
- byte_ratio.ratio = a_total / b_total (0으로 나누기 방지)
"""
import uuid
import pytest


def _make_session(src_ip: str, dst_ip: str, protocol: str = "TCP", bytes_sent: int = 1024):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=443,
        protocol=protocol,
        start_ts=1_748_000_000.0,
        end_ts=1_748_000_002.0,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_sent // 2,
        packet_count=10,
        payload_length=bytes_sent,
        confidence="normal",
    )


def _make_session_fail(src_ip: str, dst_ip: str, rst: bool = True):
    from models.session import SessionModel
    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=50000, dst_port=443, protocol="TCP",
        start_ts=1_748_000_000.0, end_ts=1_748_000_002.0,
        bytes_sent=200, bytes_recv=0, packet_count=3,
        payload_length=0, confidence="normal", rst=rst,
    )


def _load_comparator():
    try:
        from services.analytics.pcap_comparator import PcapComparator
        return PcapComparator()
    except ImportError:
        pytest.skip("pcap_comparator 미구현")


class TestVerdict:
    """정상 vs 장애 한눈 판정 (verdict + change_type)."""

    def test_identical_captures_similar(self):
        cmp = _load_comparator()
        a = [_make_session("10.0.0.1", "10.0.0.2")]
        b = [_make_session("10.0.0.1", "10.0.0.2")]
        res = cmp.compare(a, b)
        assert res.verdict["verdict"] == "SIMILAR"
        for c in res.conversations:
            assert c["change_type"] == "STABLE"

    def test_healthy_to_failing_is_degraded(self):
        cmp = _load_comparator()
        # base: healthy conversation; current: same pair now resetting
        a = [_make_session("10.0.0.1", "10.0.0.2") for _ in range(4)]
        b = [_make_session_fail("10.0.0.1", "10.0.0.2") for _ in range(4)]
        res = cmp.compare(a, b)
        assert res.verdict["verdict"] == "DEGRADED"
        assert res.verdict["newly_failing"] >= 1
        degraded = [c for c in res.conversations if c["change_type"] == "DEGRADED"]
        assert len(degraded) >= 1

    def test_new_failing_conversation_degraded(self):
        cmp = _load_comparator()
        a = [_make_session("10.0.0.1", "10.0.0.2")]
        b = [_make_session("10.0.0.1", "10.0.0.2"),
             _make_session_fail("10.0.0.9", "10.0.0.2")]
        res = cmp.compare(a, b)
        types = {c["change_type"] for c in res.conversations}
        assert "NEW_FAILING" in types
        assert res.verdict["verdict"] == "DEGRADED"

    def test_failing_to_healthy_is_improved(self):
        cmp = _load_comparator()
        a = [_make_session_fail("10.0.0.1", "10.0.0.2") for _ in range(4)]
        b = [_make_session("10.0.0.1", "10.0.0.2") for _ in range(4)]
        res = cmp.compare(a, b)
        assert res.verdict["verdict"] == "IMPROVED"
        assert res.verdict["recovered"] >= 1

    def test_verdict_always_present(self):
        cmp = _load_comparator()
        res = cmp.compare([], [])
        assert "verdict" in res.verdict
        assert res.verdict["verdict"] in ("SIMILAR", "DEGRADED", "IMPROVED", "DIFFERENT")

    def test_normal_rst_teardown_not_failure(self):
        """데이터 교환 후 RST 종료(브라우저/LB 통상 동작)는 장애가 아니다."""
        from models.session import SessionModel
        cmp = _load_comparator()

        def _rst_close():
            return SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=50000, dst_port=443, protocol="TCP",
                start_ts=1_748_000_000.0, end_ts=1_748_000_002.0,
                bytes_sent=2048, bytes_recv=8192,  # 정상 데이터 교환
                packet_count=30, payload_length=2048,
                confidence="normal", rst=True,      # RST로 닫혔을 뿐
            )
        a = [_rst_close() for _ in range(4)]
        b = [_rst_close() for _ in range(4)]
        res = cmp.compare(a, b)
        assert res.verdict["verdict"] == "SIMILAR"
        assert res.verdict["newly_failing"] == 0

    def test_one_way_udp_not_failure(self):
        """단방향 UDP(syslog/브로드캐스트)는 응답이 없어도 장애가 아니다."""
        from models.session import SessionModel
        cmp = _load_comparator()

        def _syslog():
            return SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip="10.0.0.1", dst_ip="10.0.0.9",
                src_port=50000, dst_port=514, protocol="UDP",
                start_ts=1_748_000_000.0, end_ts=1_748_000_002.0,
                bytes_sent=500, bytes_recv=0,
                packet_count=5, payload_length=500,
                confidence="normal",
            )
        a = [_syslog()]
        b = [_syslog(), _syslog()]
        res = cmp.compare(a, b)
        assert res.verdict["newly_failing"] == 0
        assert res.verdict["verdict"] != "DEGRADED"


class TestIpDiff:
    def test_common_ips(self):
        """A, B 모두에 있는 IP."""
        comp = _load_comparator()
        sessions_a = [_make_session("10.0.0.1", "192.168.1.1")]
        sessions_b = [_make_session("10.0.0.1", "192.168.1.2")]
        result = comp.compare(sessions_a, sessions_b)
        assert "10.0.0.1" in result.common_ips

    def test_only_in_a(self):
        comp = _load_comparator()
        sessions_a = [_make_session("10.0.0.99", "192.168.1.1")]
        sessions_b = [_make_session("10.0.0.1", "192.168.1.1")]
        result = comp.compare(sessions_a, sessions_b)
        assert "10.0.0.99" in result.only_in_a
        assert "10.0.0.99" not in result.only_in_b

    def test_only_in_b(self):
        comp = _load_comparator()
        sessions_a = [_make_session("10.0.0.1", "192.168.1.1")]
        sessions_b = [_make_session("10.0.0.50", "192.168.1.1")]
        result = comp.compare(sessions_a, sessions_b)
        assert "10.0.0.50" in result.only_in_b
        assert "10.0.0.50" not in result.only_in_a

    def test_identical_sessions(self):
        """A == B → common_ips = A IPs, only_in_a/b 비어 있음."""
        comp = _load_comparator()
        s = _make_session("10.0.0.1", "192.168.1.1")
        # 두 다른 세션이지만 같은 IP 셋
        sessions_a = [_make_session("10.0.0.1", "192.168.1.1")]
        sessions_b = [_make_session("10.0.0.1", "192.168.1.1")]
        result = comp.compare(sessions_a, sessions_b)
        assert "10.0.0.1" in result.common_ips
        assert "10.0.0.1" not in result.only_in_a
        assert "10.0.0.1" not in result.only_in_b


class TestProtocolDiff:
    def test_protocol_diff_computed(self):
        """TCP 분포 A: 3, B: 1 → diff_pct 계산."""
        comp = _load_comparator()
        sessions_a = [_make_session("10.0.0.1", "192.168.1.1", protocol="TCP") for _ in range(3)]
        sessions_b = [_make_session("10.0.0.1", "192.168.1.1", protocol="TCP") for _ in range(1)]
        result = comp.compare(sessions_a, sessions_b)
        assert "TCP" in result.protocol_diff
        tcp = result.protocol_diff["TCP"]
        assert tcp["a"] == 3
        assert tcp["b"] == 1


class TestByteRatio:
    def test_byte_ratio_computed(self):
        comp = _load_comparator()
        sessions_a = [_make_session("10.0.0.1", "10.0.0.2", bytes_sent=2000)]
        sessions_b = [_make_session("10.0.0.3", "10.0.0.4", bytes_sent=1000)]
        result = comp.compare(sessions_a, sessions_b)
        assert result.byte_ratio["a_total"] > 0
        assert result.byte_ratio["b_total"] > 0
        assert abs(result.byte_ratio["ratio"] - 2.0) < 0.1

    def test_byte_ratio_b_zero_no_division_error(self):
        """B 세션 없을 때 0으로 나누기 방지."""
        comp = _load_comparator()
        sessions_a = [_make_session("10.0.0.1", "10.0.0.2", bytes_sent=1000)]
        result = comp.compare(sessions_a, [])
        assert "ratio" in result.byte_ratio
        assert result.byte_ratio["b_total"] == 0
        # ratio 는 inf 또는 None 허용 — 중요: ZeroDivisionError 없어야 함


class TestCompareEdge:
    def test_both_empty(self):
        comp = _load_comparator()
        result = comp.compare([], [])
        assert result.common_ips == set()
        assert result.only_in_a == set()
        assert result.only_in_b == set()

    def test_empty_a_nonempty_b(self):
        comp = _load_comparator()
        sessions_b = [_make_session("10.0.0.1", "192.168.1.1")]
        result = comp.compare([], sessions_b)
        assert "10.0.0.1" in result.only_in_b
        assert result.only_in_a == set()
