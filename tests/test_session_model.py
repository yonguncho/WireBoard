"""SessionModel 유효성 검사기 단위 테스트."""
import math
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def _valid_kwargs(**overrides):
    base = dict(
        session_id=str(uuid.uuid4()),
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        start_ts=1_748_000_000.0,
        end_ts=1_748_000_010.0,
        bytes_sent=1024,
        bytes_recv=2048,
        packet_count=10,
        payload_length=1024,
    )
    base.update(overrides)
    return base


class TestSessionModelValid:
    def test_valid_session_created(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs())
        assert s.src_ip == "192.168.1.1"

    def test_confidence_default_normal(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs())
        assert s.confidence == "normal"

    def test_rst_default_false(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs())
        assert s.rst is False

    def test_meta_default_none(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs())
        assert s.meta is None

    def test_known_protocols_accepted(self):
        from models.session import SessionModel
        for proto in ("TCP", "UDP", "ICMP", "ICMP6", "ARP", "GRE", "ESP", "SCTP"):
            s = SessionModel(**_valid_kwargs(protocol=proto))
            assert s.protocol == proto

    def test_port_zero_accepted(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs(src_port=0, dst_port=0))
        assert s.src_port == 0

    def test_port_65535_accepted(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs(src_port=65535, dst_port=65535))
        assert s.dst_port == 65535

    def test_end_ts_equals_start_ts_accepted(self):
        from models.session import SessionModel
        ts = 1_748_000_000.0
        s = SessionModel(**_valid_kwargs(start_ts=ts, end_ts=ts))
        assert s.start_ts == s.end_ts


class TestSessionModelInvalidUUID:
    def test_non_v4_uuid_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        bad_id = "12345678-1234-1234-1234-123456789abc"  # not UUID v4
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(session_id=bad_id))

    def test_plain_string_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(session_id="not-a-uuid"))

    def test_empty_string_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(session_id=""))


class TestSessionModelInvalidIp:
    def test_invalid_ip_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(src_ip="not.an.ip"))

    def test_empty_ip_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(dst_ip=""))

    def test_out_of_range_ip_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(src_ip="999.999.999.999"))


class TestSessionModelInvalidPort:
    def test_negative_port_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(src_port=-1))

    def test_port_over_65535_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(dst_port=65536))


class TestSessionModelInvalidProtocol:
    def test_empty_protocol_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(protocol=""))

    def test_unknown_protocol_accepted(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs(protocol="CUSTOM"))
        assert s.protocol == "CUSTOM"

    def test_protocol_lowercased_to_upper(self):
        from models.session import SessionModel
        s = SessionModel(**_valid_kwargs(protocol="tcp"))
        assert s.protocol == "TCP"


class TestSessionModelInvalidTimestamp:
    def test_negative_start_ts_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(start_ts=-1.0))

    def test_nan_timestamp_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(start_ts=float("nan")))

    def test_inf_timestamp_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(start_ts=float("inf")))

    def test_end_before_start_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(start_ts=1_748_000_010.0, end_ts=1_748_000_000.0))


class TestSessionModelInvalidCounters:
    def test_negative_bytes_sent_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(bytes_sent=-1))

    def test_negative_bytes_recv_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(bytes_recv=-1))

    def test_negative_packet_count_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(packet_count=-1))

    def test_negative_payload_length_rejected(self):
        from models.session import SessionModel
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            SessionModel(**_valid_kwargs(payload_length=-1))
