"""SensitiveDataFilter — IPv4 주소와 32자리 hex 토큰을 로그에서 마스킹한다.

적용 대상: packetlens.access 로거 (미들웨어 access log)
캡처 토큰(secrets.token_hex(16) = 32 hex chars)과 IPv4 주소가 로그에 노출되지 않도록 한다.
"""
import ipaddress
import logging
import re

_HEX32_RE = re.compile(r'\b[0-9a-f]{32}\b', re.IGNORECASE)
_IPV4_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')


def _replace_ip(m: re.Match) -> str:
    try:
        ipaddress.IPv4Address(m.group())
        return '[IP-REDACTED]'
    except ValueError:
        return m.group()


def _mask_str(val: str) -> str:
    val = _HEX32_RE.sub('[REDACTED]', val)
    val = _IPV4_RE.sub(_replace_ip, val)
    return val


def _mask_value(val: object) -> object:
    if isinstance(val, str):
        return _mask_str(val)
    return val


class SensitiveDataFilter(logging.Filter):
    """IPv4 주소와 32자리 hex 토큰을 로그 레코드에서 마스킹한다."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _mask_str(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(_mask_value(a) for a in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: _mask_value(v) for k, v in record.args.items()}
        return True
