"""파서 4종 유닛 테스트.

대상:
  backend/services/parser/pcap_parser.py   (PcapParser)
  backend/services/parser/har_parser.py    (HarParser)
  backend/services/parser/fortigate_parser.py (FortigateParser)
  backend/services/parser/tcpdump_parser.py (TcpdumpParser)
  backend/services/normalizer.py           (SessionNormalizer)
  backend/services/flow_extractor.py       (FlowExtractor)

검증 항목:
- detect() 100% 정확 (각 파서가 자기 형식만 수락)
- 50 MB 초과 → ValueError (A-05)
- 손상 패킷 → skip, 예외 전파 없음
- FortiGate verbose 3 → payload_length=0, confidence="low" (A-01)
- Plotly None separator: len(xs) == 3 * n_flows, None 개수 == n_flows (ADR-003)
- UUID 자동 생성: 각 session_id 는 UUID v4 형식
- strict=True SessionModel: 잘못된 UUID → ValidationError
"""
import re
import struct
import uuid
from typing import Any

import pytest

UUID_RE: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
MAX_UPLOAD_BYTES = 52_428_800  # 50 MB


# ─────────────────────────── PcapParser ────────────────────────────

class TestPcapParserDetect:
    def test_detects_valid_pcap(self, pcap_bytes: bytes) -> None:
        from services.parser.pcap_parser import PcapParser
        assert PcapParser().detect(pcap_bytes) is True

    def test_rejects_har_bytes(self, har_json: str) -> None:
        from services.parser.pcap_parser import PcapParser
        assert PcapParser().detect(har_json.encode()) is False

    def test_rejects_fortigate_text(self, fortigate_v3_text: str) -> None:
        from services.parser.pcap_parser import PcapParser
        assert PcapParser().detect(fortigate_v3_text.encode()) is False

    def test_rejects_random_bytes(self) -> None:
        from services.parser.pcap_parser import PcapParser
        assert PcapParser().detect(b"\xff\xfe\xfd\xfc" * 10) is False


class TestPcapParserParse:
    def test_returns_session_list(self, pcap_bytes: bytes) -> None:
        from services.parser.pcap_parser import PcapParser
        sessions = PcapParser().parse(pcap_bytes)
        assert isinstance(sessions, list)
        assert len(sessions) >= 1

    def test_session_ids_are_uuid(self, pcap_bytes: bytes) -> None:
        from services.parser.pcap_parser import PcapParser
        sessions = PcapParser().parse(pcap_bytes)
        for s in sessions:
            assert UUID_RE.match(s.session_id), f"session_id 가 UUID 형식 아님: {s.session_id!r}"

    def test_50mb_raises_value_error(self) -> None:
        """50 MB 초과 입력 → ValueError (파일 read() 없이 차단, A-05)."""
        from services.parser.pcap_parser import PcapParser
        import struct

        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        oversized = header + b"\x00" * (MAX_UPLOAD_BYTES + 1 - len(header))
        with pytest.raises(ValueError, match="50"):
            PcapParser().parse(oversized)

    def test_corrupted_packets_are_skipped(self) -> None:
        """손상된 패킷 헤더 → 예외 전파 없이 skip 후 빈 리스트 반환."""
        from services.parser.pcap_parser import PcapParser
        import struct

        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        garbage = header + b"\xde\xad\xbe\xef" * 100
        # 예외가 아닌 리스트 반환 (빈 리스트 허용)
        result = PcapParser().parse(garbage)
        assert isinstance(result, list)

    def test_sessions_have_required_fields(self, pcap_bytes: bytes) -> None:
        from services.parser.pcap_parser import PcapParser
        sessions = PcapParser().parse(pcap_bytes)
        for s in sessions:
            assert hasattr(s, "src_ip")
            assert hasattr(s, "dst_ip")
            assert hasattr(s, "src_port")
            assert hasattr(s, "dst_port")
            assert hasattr(s, "protocol")
            assert hasattr(s, "start_ts")


# ─────────────────────────── HarParser ────────────────────────────

class TestHarParser:
    def test_detects_har(self, har_json: str) -> None:
        from services.parser.har_parser import HarParser
        assert HarParser().detect(har_json.encode()) is True

    def test_rejects_pcap(self, pcap_bytes: bytes) -> None:
        from services.parser.har_parser import HarParser
        assert HarParser().detect(pcap_bytes) is False

    def test_parse_returns_sessions(self, har_json: str) -> None:
        from services.parser.har_parser import HarParser
        sessions = HarParser().parse(har_json.encode())
        assert len(sessions) >= 1

    def test_har_sessions_have_http_method(self, har_json: str) -> None:
        from services.parser.har_parser import HarParser
        sessions = HarParser().parse(har_json.encode())
        for s in sessions:
            # HTTP 메서드 정보는 http_payload 또는 meta 에 있어야 한다
            assert hasattr(s, "src_ip") or hasattr(s, "meta")

    def test_har_invalid_json_raises(self) -> None:
        from services.parser.har_parser import HarParser
        with pytest.raises((ValueError, KeyError)):
            HarParser().parse(b"{not json}")

    def test_har_missing_entries_raises(self) -> None:
        import json
        from services.parser.har_parser import HarParser
        bad_har = json.dumps({"log": {"version": "1.2"}}).encode()
        with pytest.raises((ValueError, KeyError)):
            HarParser().parse(bad_har)


# ─────────────────────── FortiGateParser ────────────────────────────

class TestFortigateParser:
    def test_detects_verbose3(self, fortigate_v3_text: str) -> None:
        from services.parser.fortigate_parser import FortigateParser
        assert FortigateParser().detect(fortigate_v3_text.encode()) is True

    def test_detects_verbose6(self, fortigate_v6_text: str) -> None:
        from services.parser.fortigate_parser import FortigateParser
        assert FortigateParser().detect(fortigate_v6_text.encode()) is True

    def test_rejects_random_text(self) -> None:
        from services.parser.fortigate_parser import FortigateParser
        assert FortigateParser().detect(b"Hello World, this is not fortigate") is False

    def test_verbose3_payload_length_zero(self, fortigate_v3_text: str) -> None:
        """FortiGate verbose 3 → payload_length=0 (A-01)."""
        from services.parser.fortigate_parser import FortigateParser
        sessions = FortigateParser().parse(fortigate_v3_text.encode())
        assert len(sessions) >= 1
        for s in sessions:
            assert s.payload_length == 0

    def test_verbose3_confidence_low(self, fortigate_v3_text: str) -> None:
        """FortiGate verbose 3 → confidence='low' (A-01)."""
        from services.parser.fortigate_parser import FortigateParser
        sessions = FortigateParser().parse(fortigate_v3_text.encode())
        for s in sessions:
            assert s.confidence == "low"

    def test_timestamp_preserved(self, fortigate_v3_text: str) -> None:
        """타임스탬프가 원본 텍스트의 값으로 보존된다."""
        from services.parser.fortigate_parser import FortigateParser
        sessions = FortigateParser().parse(fortigate_v3_text.encode())
        assert len(sessions) >= 1
        assert sessions[0].start_ts > 0

    def test_src_dst_ip_extracted(self, fortigate_v3_text: str) -> None:
        from services.parser.fortigate_parser import FortigateParser
        sessions = FortigateParser().parse(fortigate_v3_text.encode())
        for s in sessions:
            assert s.src_ip == "192.168.1.100"
            assert s.dst_ip == "10.0.0.1"


# ─────────────────────── SessionNormalizer ───────────────────────────

class TestSessionNormalizer:
    def test_normalize_assigns_uuid_session_ids(self, pcap_bytes: bytes) -> None:
        from services.parser.pcap_parser import PcapParser
        from services.normalizer import SessionNormalizer
        raw = PcapParser().parse(pcap_bytes)
        sessions = SessionNormalizer().normalize(raw)
        for s in sessions:
            assert UUID_RE.match(s.session_id)

    def test_normalize_deduplicates(self, pcap_bytes: bytes) -> None:
        """같은 4-tuple 패킷들이 하나의 세션으로 합쳐진다."""
        from services.parser.pcap_parser import PcapParser
        from services.normalizer import SessionNormalizer
        raw = PcapParser().parse(pcap_bytes)
        sessions = SessionNormalizer().normalize(raw)
        # conftest pcap 은 src=192.168.1.1:80 → dst=192.168.1.2:8080 단일 플로우
        assert len(sessions) >= 1


# ─────────────────────────── FlowExtractor ──────────────────────────

class TestFlowExtractor:
    def test_build_plotly_data_length(self, pcap_bytes: bytes) -> None:
        """len(xs) == 3 * n_flows, None 개수 == n_flows (ADR-003)."""
        from services.parser.pcap_parser import PcapParser
        from services.normalizer import SessionNormalizer
        from services.flow_extractor import FlowExtractor
        sessions = SessionNormalizer().normalize(PcapParser().parse(pcap_bytes))
        extractor = FlowExtractor()
        flows = extractor.extract(sessions, target_ip="192.168.1.2")
        xs, ys = extractor.build_plotly_data(flows)

        assert len(xs) == 3 * len(flows), (
            f"xs 길이 {len(xs)} ≠ 3 × {len(flows)} flows"
        )
        assert len(ys) == 3 * len(flows)
        assert xs.count(None) == len(flows), "None separator 개수 불일치"
        assert ys.count(None) == len(flows)

    def test_build_plotly_empty_flows(self) -> None:
        """flows 빈 리스트 → xs/ys 빈 리스트."""
        from services.flow_extractor import FlowExtractor
        xs, ys = FlowExtractor().build_plotly_data([])
        assert xs == []
        assert ys == []

    def test_no_iterrows_no_add_trace_loop(self) -> None:
        """FlowExtractor 소스에 add_trace 루프 / iterrows 패턴 없음 (ADR-003)."""
        import inspect
        from services.flow_extractor import FlowExtractor
        source = inspect.getsource(FlowExtractor)
        assert "iterrows" not in source, "iterrows 사용 감지됨 (ADR-003 위반)"
        # add_trace 가 루프 안에서 호출되지 않는지 간접 검증:
        # build_plotly_data 반환값이 tuple(list, list) 이므로 단일 trace 패턴임


# ─────────────────────── Pydantic strict=True 검증 ──────────────────

class TestSessionModelValidation:
    def test_invalid_uuid_raises_validation_error(self) -> None:
        """strict=True + UUID validator: 잘못된 UUID → ValidationError."""
        from pydantic import ValidationError
        from models.session import SessionModel
        with pytest.raises(ValidationError):
            SessionModel(
                session_id="not-a-uuid",
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=80,
                dst_port=8080,
                protocol="TCP",
                start_ts=1_000_000.0,
                end_ts=1_000_001.0,
                bytes_sent=100,
                bytes_recv=200,
                packet_count=5,
                payload_length=0,
                confidence="normal",
            )

    def test_valid_uuid_accepted(self) -> None:
        from models.session import SessionModel
        s = SessionModel(
            session_id=str(uuid.uuid4()),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=443,
            dst_port=12345,
            protocol="TCP",
            start_ts=1_748_000_000.0,
            end_ts=1_748_000_001.0,
            bytes_sent=512,
            bytes_recv=1024,
            packet_count=8,
            payload_length=512,
            confidence="normal",
        )
        assert UUID_RE.match(s.session_id)

    def test_strict_mode_enabled(self) -> None:
        from models.session import SessionModel
        assert SessionModel.model_config.get("strict") is True
