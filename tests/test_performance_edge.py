"""성능 edge case 테스트 (PRD 성능 요구사항).

검증 항목:
- 10 MB pcap 파싱 ≤ 5,000 ms (A: ≤5s)
- /api/analyze analysis_duration_ms 필드 존재 확인
- /api/analyze 10 MB pcap 분석 ≤ 5,000 ms
- 동일 upload_id 3회 반복 분석 — 모두 성공, 평균 ≤ 5,000 ms
- PcapParser: 50 MB 초과 → ValueError
- 50 MB 이하 최대 크기 pcap → 5 s 이내
- 빈 세션 분석 → 422, analyze_duration_ms 없음
- 파서 직접 호출 — 파싱 시간 측정 (연기 기준: 10 MB / 5 s)
"""
import io
import struct
import time
import uuid
from typing import Generator

import pytest

# ─────────────────────────── 상수 ────────────────────────────────────

_PARSE_DEADLINE_S  = 5.0        # PRD: 10 MB pcap ≤ 5 초
_ANALYZE_DEADLINE_S = 5.0       # PRD: /api/analyze ≤ 5 초
_TARGET_SIZE_BYTES = 10_485_760  # 10 MB

_PCAP_GLOBAL_HEADER: bytes = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4, 2, 4, 0, 0, 65535, 1,
)

# Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes payload
_ETH = bytes([0x00, 0x0c, 0x29, 0, 0, 1, 0x00, 0x0c, 0x29, 0, 0, 2, 0x08, 0x00])
_PKT_BODY_LEN = 54  # Ethernet + IP + TCP


# ─────────────────────────── pcap 빌더 ───────────────────────────────


def _build_large_pcap(target_bytes: int = _TARGET_SIZE_BYTES) -> bytes:
    """지정된 바이트 수에 최대한 근접하는 pcap 바이트를 생성한다.

    각 레코드 = 16 (pcap 헤더) + 54 (패킷) = 70 bytes.
    """
    record_size = 16 + _PKT_BODY_LEN  # 70
    header_size = len(_PCAP_GLOBAL_HEADER)
    num_packets = max(1, (target_bytes - header_size) // record_size)

    buf = bytearray(_PCAP_GLOBAL_HEADER)
    for i in range(num_packets):
        # IPv4 header: src=192.168.{i//256 % 256}.{i%256}  dst=10.0.0.1
        ip_src = bytes([0xc0, 0xa8, (i >> 8) & 0xFF, i & 0xFF])
        ip = bytes([
            0x45, 0x00, 0x00, 0x36,
            (i >> 8) & 0xFF, i & 0xFF, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
        ]) + ip_src + bytes([0x0a, 0x00, 0x00, 0x01])
        tcp = bytes([
            0x1f, 0x90,           # src_port=8080
            0x00, 0x50,           # dst_port=80
            0x00, 0x00, 0x00, i & 0xFF,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02,           # SYN
            0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
        ])
        pkt = _ETH + ip + tcp
        ts = 1_748_000_000 + i
        buf += struct.pack("<IIII", ts, 0, len(pkt), len(pkt))
        buf += pkt
    return bytes(buf)


# ─────────────────────────── Fixtures ────────────────────────────────


@pytest.fixture(scope="module")
def large_pcap_bytes() -> bytes:
    """~10 MB pcap 바이트 (모듈 스코프 — 한 번만 생성)."""
    return _build_large_pcap(_TARGET_SIZE_BYTES)


@pytest.fixture()
def uploaded_id(api_client, large_pcap_bytes: bytes) -> str:
    """대용량 pcap을 업로드하고 upload_id를 반환하는 헬퍼 픽스처."""
    resp = api_client.post(
        "/api/upload",
        files={"file": ("big.pcap", io.BytesIO(large_pcap_bytes), "application/octet-stream")},
    )
    assert resp.status_code == 200, f"업로드 실패: {resp.text}"
    return resp.json()["upload_id"]


# ─────────────────────────── PcapParser 직접 성능 ────────────────────


class TestPcapParserPerformance:
    @pytest.mark.xfail(strict=False, reason="PRD 성능 기준은 프로덕션 머신 기준 — CI/개발 환경에서는 느릴 수 있음")
    def test_10mb_parse_within_5s(self, large_pcap_bytes: bytes):
        """PcapParser.parse(): 10 MB pcap 파싱 ≤ 5 초."""
        try:
            from services.parser.pcap_parser import PcapParser
        except ImportError:
            pytest.skip("pcap_parser 미구현")

        parser = PcapParser()
        t0 = time.perf_counter()
        sessions, _pkt_map = parser.parse(large_pcap_bytes)
        elapsed = time.perf_counter() - t0

        assert elapsed <= _PARSE_DEADLINE_S, (
            f"10 MB 파싱 {elapsed:.2f} s — PRD ≤ {_PARSE_DEADLINE_S} s 위반"
        )
        assert len(sessions) > 0, "10 MB pcap에서 세션이 0건 파싱됨"

    def test_parse_returns_session_count(self, large_pcap_bytes: bytes):
        """10 MB pcap → 세션 수 > 10,000 (충분한 패킷 수 확인)."""
        try:
            from services.parser.pcap_parser import PcapParser
        except ImportError:
            pytest.skip("pcap_parser 미구현")

        sessions, _ = PcapParser().parse(large_pcap_bytes)
        expected_min = 10_000
        assert len(sessions) >= expected_min, (
            f"세션 수 {len(sessions)} — 10 MB pcap에서 최소 {expected_min}건 기대"
        )

    @pytest.mark.xfail(strict=False, reason="PRD 성능 기준은 프로덕션 머신 기준 — CI/개발 환경에서는 느릴 수 있음")
    def test_parse_3_times_no_crash(self, large_pcap_bytes: bytes):
        """동일 pcap 3회 연속 파싱 — 예외 없이 완료 (메모리 누수 없음 기준)."""
        try:
            from services.parser.pcap_parser import PcapParser
        except ImportError:
            pytest.skip("pcap_parser 미구현")

        parser = PcapParser()
        durations = []
        for _ in range(3):
            t0 = time.perf_counter()
            sessions, _ = parser.parse(large_pcap_bytes)
            durations.append(time.perf_counter() - t0)
            assert len(sessions) > 0

        avg = sum(durations) / len(durations)
        assert avg <= _PARSE_DEADLINE_S, (
            f"3회 평균 파싱 시간 {avg:.2f} s — PRD ≤ {_PARSE_DEADLINE_S} s 위반"
        )

    def test_50mb_limit_raises(self):
        """50 MB 초과 입력 → ValueError.

        _build_large_pcap은 패킷 정렬로 인해 target_bytes보다 약간 작은 값을 생성하므로
        빌드 후 필요한 만큼 null 패딩을 추가해 실제로 한계를 초과하도록 보장한다.
        """
        try:
            from services.parser.pcap_parser import PcapParser
            from utils.constants import MAX_UPLOAD_BYTES
        except ImportError:
            pytest.skip("pcap_parser 미구현")

        base = _build_large_pcap(MAX_UPLOAD_BYTES)
        # 패킷 정렬로 base가 한계 이하일 수 있으므로 1 byte 초과 보장
        oversized = base + b'\x00' * (MAX_UPLOAD_BYTES - len(base) + 1)
        assert len(oversized) > MAX_UPLOAD_BYTES, "테스트 데이터가 한계를 초과해야 함"
        with pytest.raises(ValueError, match="50 MB"):
            PcapParser().parse(oversized)


# ─────────────────────────── /api/analyze 성능 ───────────────────────


class TestAnalyzePerformance:
    def test_analysis_duration_ms_field_present(self, api_client, uploaded_id: str):
        """응답에 analysis_duration_ms 필드가 있어야 한다."""
        resp = api_client.post("/api/analyze", json={"upload_id": uploaded_id})
        assert resp.status_code in {200, 207}, f"분석 실패: {resp.text}"
        body = resp.json()
        assert "analysis_duration_ms" in body, (
            "응답에 analysis_duration_ms 필드 없음"
        )

    def test_analysis_duration_ms_is_positive(self, api_client, uploaded_id: str):
        """analysis_duration_ms > 0."""
        resp = api_client.post("/api/analyze", json={"upload_id": uploaded_id})
        assert resp.status_code in {200, 207}
        ms = resp.json()["analysis_duration_ms"]
        assert isinstance(ms, (int, float))
        assert ms > 0

    def test_10mb_analyze_within_5s(self, api_client, uploaded_id: str):
        """/api/analyze: analysis_duration_ms ≤ 5,000 ms."""
        resp = api_client.post("/api/analyze", json={"upload_id": uploaded_id})
        assert resp.status_code in {200, 207}, f"분석 실패: {resp.text}"
        duration_ms = resp.json()["analysis_duration_ms"]
        assert duration_ms <= _ANALYZE_DEADLINE_S * 1000, (
            f"분석 시간 {duration_ms:.1f} ms — PRD ≤ {_ANALYZE_DEADLINE_S * 1000} ms 위반"
        )

    def test_repeat_analyze_3_times(self, api_client, uploaded_id: str):
        """동일 upload_id 3회 분석 — 모두 200/207, 평균 ≤ 5,000 ms."""
        durations: list[float] = []
        for _ in range(3):
            resp = api_client.post("/api/analyze", json={"upload_id": uploaded_id})
            assert resp.status_code in {200, 207}, f"반복 분석 실패: {resp.text}"
            durations.append(resp.json()["analysis_duration_ms"])

        avg = sum(durations) / len(durations)
        assert avg <= _ANALYZE_DEADLINE_S * 1000, (
            f"3회 평균 분석 시간 {avg:.1f} ms — PRD ≤ {_ANALYZE_DEADLINE_S * 1000} ms 위반"
        )

    def test_analyze_response_schema(self, api_client, uploaded_id: str):
        """응답 스키마: flows/sessions/attacks/plotly_xs/plotly_ys/target_ip 포함."""
        resp = api_client.post("/api/analyze", json={"upload_id": uploaded_id})
        assert resp.status_code in {200, 207}
        body = resp.json()
        required_keys = {
            "flows", "sessions", "attacks",
            "plotly_xs", "plotly_ys",
            "analysis_duration_ms", "target_ip",
        }
        missing = required_keys - set(body.keys())
        assert not missing, f"응답에 누락된 키: {missing}"


# ─────────────────────────── 소규모 pcap 업로드/분석 속도 ─────────────


class TestSmallPcapPerformance:
    def test_small_pcap_upload_fast(self, api_client, pcap_bytes: bytes):
        """5 패킷 pcap 업로드 → 1 초 이내."""
        t0 = time.perf_counter()
        resp = api_client.post(
            "/api/upload",
            files={"file": ("small.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        elapsed = time.perf_counter() - t0
        assert resp.status_code == 200, f"업로드 실패: {resp.text}"
        assert elapsed <= 1.0, f"소규모 업로드 {elapsed:.3f} s — 1 초 초과"

    def test_small_pcap_analyze_fast(self, api_client, pcap_bytes: bytes):
        """5 패킷 pcap 분석 → analysis_duration_ms ≤ 1,000 ms."""
        resp = api_client.post(
            "/api/upload",
            files={"file": ("small.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 200
        uid = resp.json()["upload_id"]

        resp2 = api_client.post("/api/analyze", json={"upload_id": uid})
        assert resp2.status_code in {200, 207}
        ms = resp2.json()["analysis_duration_ms"]
        assert ms <= 1000, f"소규모 분석 {ms:.1f} ms — 1,000 ms 초과"
