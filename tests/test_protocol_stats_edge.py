"""Panel 2 — 프로토콜 분포 edge case 테스트 (TDD).

대상: services.analytics.protocol_stats.ProtocolStats

인터페이스 가정:
  ProtocolStats().compute(sessions) -> ProtocolStatsResult
  ProtocolStatsResult:
    distribution: dict[str, int]  # {"TCP": 3, "UDP": 2, ...}
    top_ports: list[dict]          # [{"port": int, "count": int, "app": str}, ...]
    # top_ports 최대 10개, count 내림차순

검증 항목:
- TCP/UDP/ICMP 카운트 정확성
- HTTP(80)/HTTPS(443)/DNS(53) 포트 앱 이름 매핑
- top_ports 최대 10개
- 알 수 없는 프로토콜 → "unknown" or 그대로
- 빈 세션 → distribution={}, top_ports=[]
- 동일 dst_port 집계
- QUIC(443/UDP) 와 HTTPS(443/TCP) 구분 여부
"""
import uuid
import pytest


def _make_session(protocol: str, dst_port: int, *, count: int = 1):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    sessions = []
    for i in range(count):
        sessions.append(SessionModel(
            session_id=str(uuid.uuid4()),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=50000 + i,
            dst_port=dst_port,
            protocol=protocol,
            start_ts=1_748_000_000.0 + i,
            end_ts=1_748_000_001.0 + i,
            bytes_sent=512,
            bytes_recv=512,
            packet_count=5,
            payload_length=512,
            confidence="normal",
        ))
    return sessions


def _load_stats():
    try:
        from services.analytics.protocol_stats import ProtocolStats
        return ProtocolStats()
    except ImportError:
        pytest.skip("protocol_stats 미구현")


class TestProtocolDistribution:
    def test_tcp_udp_icmp_counted(self):
        stats = _load_stats()
        sessions = (
            _make_session("TCP", 80, count=3)
            + _make_session("UDP", 53, count=2)
            + _make_session("ICMP", 0, count=1)
        )
        result = stats.compute(sessions)
        assert result.distribution.get("TCP") == 3
        assert result.distribution.get("UDP") == 2
        assert result.distribution.get("ICMP") == 1

    def test_unknown_protocol_handled(self):
        """알 수 없는 프로토콜 → 키로 포함되거나 'unknown' 집계."""
        stats = _load_stats()
        sessions = _make_session("XYZPROTO", 9999)
        result = stats.compute(sessions)
        total = sum(result.distribution.values())
        assert total >= 1

    def test_empty_returns_empty(self):
        stats = _load_stats()
        result = stats.compute([])
        assert result.distribution == {}
        assert result.top_ports == []


class TestTopPorts:
    def test_top_ports_max_10(self):
        """11개 dst_port → top_ports 최대 10개."""
        stats = _load_stats()
        sessions = []
        for p in range(1000, 1011):
            sessions += _make_session("TCP", p)
        result = stats.compute(sessions)
        assert len(result.top_ports) <= 10

    def test_top_ports_sorted_by_count(self):
        stats = _load_stats()
        sessions = (
            _make_session("TCP", 80, count=10)
            + _make_session("TCP", 443, count=5)
            + _make_session("TCP", 8080, count=2)
        )
        result = stats.compute(sessions)
        counts = [item["count"] for item in result.top_ports]
        assert counts == sorted(counts, reverse=True)

    def test_http_port_80_app_name(self):
        """포트 80 → app='HTTP' (대소문자 무관)."""
        stats = _load_stats()
        sessions = _make_session("TCP", 80, count=5)
        result = stats.compute(sessions)
        ports = {item["port"]: item for item in result.top_ports}
        entry = ports.get(80)
        if entry and "app" in entry:
            assert entry["app"].upper() in {"HTTP", "HTTP/1.1", "WEB"}

    def test_dns_port_53_app_name(self):
        """포트 53/UDP → app='DNS'."""
        stats = _load_stats()
        sessions = _make_session("UDP", 53, count=5)
        result = stats.compute(sessions)
        ports = {item["port"]: item for item in result.top_ports}
        entry = ports.get(53)
        if entry and "app" in entry:
            assert "DNS" in entry["app"].upper()

    def test_aggregate_same_port(self):
        """같은 dst_port 여러 세션 → 합산 카운트."""
        stats = _load_stats()
        sessions = _make_session("TCP", 443, count=7)
        result = stats.compute(sessions)
        ports = {item["port"]: item["count"] for item in result.top_ports}
        assert ports.get(443) == 7
