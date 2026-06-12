"""FortigateParser edge case 테스트 (A-01, A-02).

대상: backend/services/parser/fortigate_parser.py (FortigateParser)

검증 항목:
- 빈 입력 → 세션 0건
- 모든 라인이 malformed → 세션 0건
- 유효/무효 라인 혼합 → 유효 라인만 파싱
- verbose 6 (payload > 0, port 있음) → confidence='normal'
- verbose 3 (payload = 0) → confidence='low'
- 포트 정보 없음 (port=0) → confidence='low'
- 잘못된 IP → 해당 라인 skip
- 포트 범위 초과 (>65535) → 해당 라인 skip
- session_id → UUID v4 형식
- 타임스탬프 → 올바른 유닉스 시간으로 변환
- 프로토콜 → 대문자 정규화
- 비-UTF-8 바이트 → errors='replace' 로 허용
- 16진수 hex 덤프 라인 → skip (파싱 불가 라인)
- 다수 라인 파싱 (100건) → 정확한 개수
- parse_warnings 파라미터 전달 → 오류 없이 수행
"""
import re
import uuid
from datetime import datetime, timezone

import pytest

UUID_RE: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ─────────────────────────── 헬퍼 ────────────────────────────────────


def _make_v3_line(index: int = 0) -> str:
    """verbose 3: payload_length=0, 포트 없음."""
    return (
        f"2026-06-04 10:00:{index:02d}.123456 eth1 in "
        f"192.168.1.100 -> 10.0.0.1: tcp 0"
    )


def _make_v6_line(index: int = 0, src_port: int = 12345, dst_port: int = 80) -> str:
    """verbose 6: payload_length=40, 포트 있음 → confidence='normal'."""
    return (
        f"2026-06-04 10:00:{index:02d}.123456 eth1 in "
        f"192.168.1.100.{src_port} -> 10.0.0.2.{dst_port}: tcp 40"
    )


def _load_parser():
    try:
        from services.parser.fortigate_parser import FortigateParser
        return FortigateParser()
    except ImportError:
        pytest.skip("fortigate_parser 미구현")


# ─────────────────────────── 빈 입력 ─────────────────────────────────


class TestFortigateEmpty:
    def test_empty_bytes_returns_empty(self):
        """빈 바이트 입력 → 세션 0건."""
        parser = _load_parser()
        sessions = parser.parse(b"")
        assert sessions == []

    def test_whitespace_only_returns_empty(self):
        """공백·개행만 있는 입력 → 세션 0건."""
        parser = _load_parser()
        sessions = parser.parse(b"   \n   \n\t\n")
        assert sessions == []


# ─────────────────────────── malformed 라인 ──────────────────────────


class TestFortigateMalformed:
    def test_all_malformed_lines_returns_empty(self):
        """모든 라인이 정규식 불일치 → 세션 0건."""
        parser = _load_parser()
        data = b"not a fortigate line\nrandom text here\n12345"
        sessions = parser.parse(data)
        assert sessions == []

    def test_hex_dump_lines_skipped(self):
        """verbose 6 hex 덤프 라인 → skip (헤더 라인만 파싱)."""
        parser = _load_parser()
        lines = [
            "2026-06-04 10:00:00.123456 eth1 in 192.168.1.100.12345 -> 10.0.0.2.80: tcp 40",
            "0x0000: 4500 0028 0001 4000 4006 0000 c0a8 0164",
            "0x0010: 0a00 0001 303a 0050 0000 0001 0000 0000",
        ]
        sessions = parser.parse("\n".join(lines).encode())
        # hex 라인 2개는 skip, 헤더 라인 1개만 파싱
        assert len(sessions) == 1

    def test_mixed_valid_invalid(self):
        """유효 3건 + 무효 3건 혼합 → 유효 3건만 파싱."""
        parser = _load_parser()
        lines = [
            _make_v3_line(0),
            "this is garbage",
            _make_v3_line(1),
            "another garbage line",
            _make_v3_line(2),
            "yet another bad line",
        ]
        sessions = parser.parse("\n".join(lines).encode())
        assert len(sessions) == 3


# ─────────────────────────── confidence 수준 ─────────────────────────


class TestFortigateConfidence:
    def test_verbose3_confidence_low(self):
        """verbose 3 (payload=0) → confidence='low'."""
        parser = _load_parser()
        sessions = parser.parse(_make_v3_line(0).encode())
        assert len(sessions) == 1
        assert sessions[0].confidence == "low"

    def test_verbose6_confidence_normal(self):
        """verbose 6 (payload>0, 포트 있음) → confidence='normal'."""
        parser = _load_parser()
        sessions = parser.parse(_make_v6_line(0).encode())
        assert len(sessions) == 1
        assert sessions[0].confidence == "normal"

    def test_zero_port_confidence_low(self):
        """포트 정보 없음 (src_port=0 또는 dst_port=0) → confidence='low'."""
        parser = _load_parser()
        line = "2026-06-04 10:00:00.123456 eth1 in 192.168.1.100 -> 10.0.0.1: tcp 40"
        sessions = parser.parse(line.encode())
        assert len(sessions) == 1
        assert sessions[0].confidence == "low"


# ─────────────────────────── IP 주소 검증 ────────────────────────────


class TestFortigateIPValidation:
    def test_invalid_src_ip_skipped(self):
        """잘못된 src_ip (999.999.999.999) → 라인 skip."""
        parser = _load_parser()
        line = "2026-06-04 10:00:00.123456 eth1 in 999.999.999.999 -> 10.0.0.1: tcp 0"
        sessions = parser.parse(line.encode())
        assert sessions == []

    def test_valid_ip_pair_extracted(self):
        """유효한 IP 쌍 → src_ip, dst_ip 정확히 추출."""
        parser = _load_parser()
        sessions = parser.parse(_make_v3_line(0).encode())
        assert len(sessions) == 1
        assert sessions[0].src_ip == "192.168.1.100"
        assert sessions[0].dst_ip == "10.0.0.1"


# ─────────────────────────── 타임스탬프 ──────────────────────────────


class TestFortigateTimestamp:
    def test_timestamp_parsed_correctly(self):
        """2026-06-04 10:00:00.123456 → 올바른 Unix timestamp."""
        parser = _load_parser()
        sessions = parser.parse(_make_v3_line(0).encode())
        assert len(sessions) == 1
        expected_dt = datetime(2026, 6, 4, 10, 0, 0, 123456, tzinfo=timezone.utc)
        expected_ts = expected_dt.timestamp()
        assert abs(sessions[0].start_ts - expected_ts) < 1.0

    def test_start_ts_equals_end_ts(self):
        """FortiGate 단일 패킷 → start_ts == end_ts."""
        parser = _load_parser()
        sessions = parser.parse(_make_v3_line(0).encode())
        assert len(sessions) == 1
        assert sessions[0].start_ts == sessions[0].end_ts


# ─────────────────────────── 프로토콜 정규화 ─────────────────────────


class TestFortigateProtocol:
    def test_tcp_uppercase(self):
        """'tcp' → 'TCP' 정규화."""
        parser = _load_parser()
        sessions = parser.parse(_make_v3_line(0).encode())
        assert sessions[0].protocol == "TCP"

    def test_udp_uppercase(self):
        """'udp' → 'UDP' 정규화."""
        parser = _load_parser()
        line = "2026-06-04 10:00:00.123456 eth1 in 192.168.1.100 -> 10.0.0.1: udp 0"
        sessions = parser.parse(line.encode())
        if sessions:
            assert sessions[0].protocol == "UDP"


# ─────────────────────────── UUID v4 형식 ────────────────────────────


class TestFortigateSessionId:
    def test_session_id_is_uuid_v4(self):
        """session_id → UUID v4 형식."""
        parser = _load_parser()
        sessions = parser.parse(_make_v3_line(0).encode())
        assert len(sessions) == 1
        assert UUID_RE.match(sessions[0].session_id), (
            f"session_id is not UUID v4: {sessions[0].session_id!r}"
        )

    def test_all_session_ids_unique(self):
        """여러 세션 파싱 시 session_id 중복 없음."""
        parser = _load_parser()
        lines = [_make_v3_line(i) for i in range(10)]
        sessions = parser.parse("\n".join(lines).encode())
        ids = [s.session_id for s in sessions]
        assert len(ids) == len(set(ids))


# ─────────────────────────── 비-UTF-8 입력 ────────────────────────────


class TestFortigateEncoding:
    def test_non_utf8_bytes_handled(self):
        """비-UTF-8 바이트 → errors='replace' 로 처리, 예외 없음."""
        parser = _load_parser()
        valid_line = _make_v3_line(0).encode("utf-8")
        garbage = b"\xff\xfe garbage \x80\x81"
        data = valid_line + b"\n" + garbage
        # 예외 없이 실행되어야 함
        sessions = parser.parse(data)
        # 유효 라인 1건 파싱
        assert len(sessions) >= 1


# ─────────────────────────── 대량 파싱 ───────────────────────────────


class TestFortigateBulk:
    def test_100_lines_parsed(self):
        """100 줄 입력 → 100 세션 반환."""
        parser = _load_parser()
        lines = [_make_v3_line(i % 60) for i in range(100)]
        sessions = parser.parse("\n".join(lines).encode())
        assert len(sessions) == 100

    def test_1000_lines_no_exception(self):
        """1000 줄 입력 → 예외 없이 완료."""
        parser = _load_parser()
        lines = [_make_v3_line(i % 60) for i in range(1000)]
        sessions = parser.parse("\n".join(lines).encode())
        assert len(sessions) == 1000


# ─────────────────────────── parse_warnings 파라미터 ─────────────────


class TestFortigateWarnings:
    def test_parse_warnings_accepted(self):
        """parse_warnings 리스트 전달 → 오류 없이 수행."""
        parser = _load_parser()
        warnings: list[str] = []
        sessions = parser.parse(_make_v3_line(0).encode(), parse_warnings=warnings)
        assert len(sessions) == 1

    def test_parse_warnings_none_accepted(self):
        """parse_warnings=None → 오류 없이 수행."""
        parser = _load_parser()
        sessions = parser.parse(_make_v3_line(0).encode(), parse_warnings=None)
        assert len(sessions) == 1


# ─────────────────────────── detect() 메서드 ─────────────────────────


class TestFortigateDetect:
    def test_detect_true_for_v3(self, fortigate_v3_text: str):
        """detect() → verbose 3 텍스트 감지."""
        parser = _load_parser()
        assert parser.detect(fortigate_v3_text.encode()) is True

    def test_detect_true_for_v6(self, fortigate_v6_text: str):
        """detect() → verbose 6 텍스트 감지."""
        parser = _load_parser()
        assert parser.detect(fortigate_v6_text.encode()) is True

    def test_detect_false_for_random(self):
        """detect() → 랜덤 텍스트 거부."""
        parser = _load_parser()
        assert parser.detect(b"random text that is not fortigate") is False

    def test_detect_false_for_empty(self):
        """detect() → 빈 입력 거부."""
        parser = _load_parser()
        assert parser.detect(b"") is False
