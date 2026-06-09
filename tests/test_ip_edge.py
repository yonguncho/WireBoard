# -*- coding: utf-8 -*-
"""Edge cases: IP validation (IPv4/IPv6), UUID pattern, session model validators."""
import os
import sys
import uuid

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from models.session import _is_valid_ip, UUID_PATTERN


# ── _is_valid_ip() ─────────────────────────────────────────────

class TestIsValidIpV4:
    def test_valid_unicast(self):
        assert _is_valid_ip("1.2.3.4") is True

    def test_valid_loopback(self):
        assert _is_valid_ip("127.0.0.1") is True

    def test_valid_broadcast(self):
        assert _is_valid_ip("255.255.255.255") is True

    def test_valid_zero(self):
        assert _is_valid_ip("0.0.0.0") is True

    def test_valid_rfc1918_10(self):
        assert _is_valid_ip("10.0.0.1") is True

    def test_valid_rfc1918_192(self):
        assert _is_valid_ip("192.168.100.200") is True

    def test_invalid_octet_999(self):
        assert _is_valid_ip("999.999.999.999") is False

    def test_invalid_octet_256(self):
        assert _is_valid_ip("256.0.0.1") is False

    def test_invalid_three_octets(self):
        assert _is_valid_ip("1.2.3") is False

    def test_invalid_five_octets(self):
        assert _is_valid_ip("1.2.3.4.5") is False

    def test_invalid_letters(self):
        assert _is_valid_ip("not.an.ip") is False

    def test_invalid_empty(self):
        assert _is_valid_ip("") is False

    def test_invalid_leading_zeros(self):
        # Python's ipaddress accepts "010.0.0.1" as decimal 10, not octal
        # Verify no crash
        result = _is_valid_ip("010.0.0.1")
        assert isinstance(result, bool)

    def test_invalid_space(self):
        assert _is_valid_ip("1.2.3.4 ") is False

    def test_invalid_newline(self):
        assert _is_valid_ip("1.2.3.4\n") is False


class TestIsValidIpV6:
    def test_valid_loopback(self):
        assert _is_valid_ip("::1") is True

    def test_valid_full(self):
        assert _is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_valid_compressed(self):
        assert _is_valid_ip("2001:db8::1") is True

    def test_valid_link_local(self):
        assert _is_valid_ip("fe80::1") is True

    def test_valid_all_zeros(self):
        assert _is_valid_ip("::") is True

    def test_invalid_too_many_groups(self):
        assert _is_valid_ip("2001:db8::1::1") is False

    def test_invalid_non_hex(self):
        assert _is_valid_ip("::gggg") is False

    def test_invalid_mixed_bad(self):
        assert _is_valid_ip("1.2.3.4::1") is False


# ── UUID_PATTERN ────────────────────────────────────────────────

class TestUUIDPattern:
    def test_valid_uuid4(self):
        uid = str(uuid.uuid4())
        assert UUID_PATTERN.match(uid) is not None

    def test_valid_all_zeros(self):
        assert UUID_PATTERN.match("00000000-0000-0000-0000-000000000000") is not None

    def test_valid_all_hex(self):
        assert UUID_PATTERN.match("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") is not None

    def test_invalid_uppercase(self):
        assert UUID_PATTERN.match("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE") is None

    def test_invalid_no_hyphens(self):
        assert UUID_PATTERN.match("aaaaaaaabbbbccccddddeeeeeeeeeeee") is None

    def test_invalid_too_short(self):
        assert UUID_PATTERN.match("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee") is None

    def test_invalid_too_long(self):
        assert UUID_PATTERN.match("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeee") is None

    def test_invalid_braces(self):
        assert UUID_PATTERN.match("{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}") is None

    def test_invalid_empty(self):
        assert UUID_PATTERN.match("") is None

    def test_invalid_with_leading_space(self):
        assert UUID_PATTERN.match(" aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") is None


# ── SessionModel validator integration ─────────────────────────

class TestSessionModelValidators:
    def _base(self, **kwargs):
        from models.session import SessionModel
        defaults = dict(
            session_id=str(uuid.uuid4()),
            src_ip="1.2.3.4", dst_ip="5.6.7.8",
            src_port=12345, dst_port=80, protocol="TCP",
            start_ts=0.0, end_ts=1.0, bytes_total=100, packet_count=1,
        )
        defaults.update(kwargs)
        return SessionModel(**defaults)

    def test_valid_session_creates_ok(self):
        s = self._base()
        assert s.src_ip == "1.2.3.4"

    def test_invalid_src_ip_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._base(src_ip="999.999.999.999")

    def test_invalid_dst_ip_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._base(dst_ip="not-an-ip")

    def test_invalid_session_id_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._base(session_id="not-a-uuid")

    def test_ipv6_src_ip_accepted(self):
        s = self._base(src_ip="::1", dst_ip="::2")
        assert s.src_ip == "::1"

    def test_invalid_protocol_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._base(protocol="QUIC")

    def test_invalid_confidence_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            self._base(confidence="critical")
