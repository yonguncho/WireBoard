"""JSON 상태 내보내기/다시 불러오기 edge case 테스트 (TDD).

대상: services.export.state_exporter.StateExporter
       services.export.state_loader.StateLoader

인터페이스 가정:
  StateExporter().export(sessions, annotations=[]) -> dict   (JSON-직렬화 가능)
  StateLoader().load(data: dict) -> (sessions, annotations)

검증 항목:
- export() 반환값이 JSON 직렬화 가능
- export() 후 load() → 세션 수 동일
- 세션 필드(src_ip, dst_ip, protocol 등) 왕복 후 동일
- annotation 메타데이터 왕복 보존
- 빈 세션 export → 빈 sessions load
- 손상된 JSON → load() 에서 ValueError/KeyError
- 필수 필드 누락 JSON → load() 에서 적절한 예외
- 세션 session_id UUID 형식 유지 (왕복 후에도 UUID v4)
- 다중 어노테이션 보존
"""
import json
import uuid
import re
import pytest

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _make_session(src_ip: str = "192.168.1.1", dst_ip: str = "10.0.0.1"):
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
        protocol="TCP",
        start_ts=1_748_000_000.0,
        end_ts=1_748_000_002.0,
        bytes_sent=1024,
        bytes_recv=2048,
        packet_count=10,
        payload_length=1024,
        confidence="normal",
    )


def _load_exporter():
    try:
        from services.export.state_exporter import StateExporter
        return StateExporter()
    except ImportError:
        pytest.skip("state_exporter 미구현")


def _load_loader():
    try:
        from services.export.state_loader import StateLoader
        return StateLoader()
    except ImportError:
        pytest.skip("state_loader 미구현")


class TestExport:
    def test_export_is_json_serializable(self):
        exporter = _load_exporter()
        sessions = [_make_session()]
        data = exporter.export(sessions)
        assert isinstance(data, dict)
        json.dumps(data)  # 직렬화 가능 여부

    def test_export_empty_sessions(self):
        exporter = _load_exporter()
        data = exporter.export([])
        assert isinstance(data, dict)

    def test_export_has_sessions_key(self):
        exporter = _load_exporter()
        data = exporter.export([_make_session()])
        assert "sessions" in data


class TestRoundTrip:
    def test_session_count_preserved(self):
        exporter = _load_exporter()
        loader = _load_loader()
        sessions = [_make_session() for _ in range(5)]
        data = exporter.export(sessions)
        loaded_sessions, _ = loader.load(data)
        assert len(loaded_sessions) == 5

    def test_session_fields_preserved(self):
        """src_ip, dst_ip, protocol 왕복 후 동일."""
        exporter = _load_exporter()
        loader = _load_loader()
        s = _make_session("192.168.1.100", "203.0.113.1")
        data = exporter.export([s])
        loaded, _ = loader.load(data)
        assert loaded[0].src_ip == "192.168.1.100"
        assert loaded[0].dst_ip == "203.0.113.1"
        assert loaded[0].protocol == "TCP"

    def test_session_id_uuid_preserved(self):
        """session_id 왕복 후 UUID v4 형식 유지."""
        exporter = _load_exporter()
        loader = _load_loader()
        sessions = [_make_session()]
        data = exporter.export(sessions)
        loaded, _ = loader.load(data)
        for s in loaded:
            assert UUID_RE.match(s.session_id), f"session_id UUID 형식 깨짐: {s.session_id!r}"

    def test_annotations_preserved(self):
        """어노테이션 왕복 보존."""
        exporter = _load_exporter()
        loader = _load_loader()
        annotations = [
            {"ts": 1_748_000_005.0, "text": "suspicious spike", "type": "marker"},
            {"ts": 1_748_000_010.0, "text": "DDoS start", "type": "comment"},
        ]
        data = exporter.export([_make_session()], annotations=annotations)
        _, loaded_annotations = loader.load(data)
        assert len(loaded_annotations) == 2
        texts = {a["text"] for a in loaded_annotations}
        assert "suspicious spike" in texts
        assert "DDoS start" in texts

    def test_empty_roundtrip(self):
        exporter = _load_exporter()
        loader = _load_loader()
        data = exporter.export([])
        loaded, annotations = loader.load(data)
        assert loaded == []
        assert annotations == []


class TestLoadErrors:
    def test_invalid_json_raises(self):
        """손상된 JSON dict → load() 에서 예외."""
        loader = _load_loader()
        with pytest.raises((ValueError, KeyError, Exception)):
            loader.load({"corrupted": True, "no_sessions": "oops"})

    def test_missing_sessions_key_raises(self):
        """sessions 키 없는 dict → 적절한 예외."""
        loader = _load_loader()
        with pytest.raises((ValueError, KeyError, Exception)):
            loader.load({})

    def test_invalid_session_uuid_raises(self):
        """session_id 가 UUID 형식 아닐 때 → load() 에서 예외 (ADR-004)."""
        loader = _load_loader()
        bad_data = {
            "sessions": [{
                "session_id": "not-a-uuid",
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "TCP",
                "start_ts": 1_748_000_000.0,
                "end_ts": 1_748_000_002.0,
                "bytes_sent": 1024,
                "bytes_recv": 2048,
                "packet_count": 10,
                "payload_length": 1024,
                "confidence": "normal",
            }]
        }
        with pytest.raises(Exception):
            loader.load(bad_data)
