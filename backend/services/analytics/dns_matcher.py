"""DnsMatcher — DNS 쿼리↔응답 매칭 + 응답시간/무응답 분석.

"느림"의 상당 부분은 DNS다. NOC는 (1) 무응답/재시도, (2) SERVFAIL/REFUSED 급증,
(3) 응답시간 p95를 먼저 본다. packet_map(포트 53 세션)의 DNS 페이로드를
transaction ID로 매칭해 이를 계산한다.

DNS 헤더(txid/flags/rcode)는 항상 앞 12바이트에 있어 캡처 128B로 충분하다.
"""
from __future__ import annotations

import struct
from collections import defaultdict

from services.payload_extractor.dns_extractor import DNSExtractor

_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}

_extractor = DNSExtractor()


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return round(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac, 2)


def match(sessions: list, packet_map: dict) -> dict:
    """DNS 쿼리↔응답 매칭 결과 + 통계."""
    pending: dict[tuple, dict] = {}   # (session_id, txid, name) -> query
    pairs: list[dict] = []

    for s in sessions:
        if 53 not in (s.src_port, s.dst_port):
            continue
        pkts = packet_map.get(s.session_id, [])
        for p in pkts:
            hexs = getattr(p, "payload_hex", "")
            if not hexs:
                continue
            try:
                data = bytes.fromhex(hexs)
            except ValueError:
                continue
            if len(data) < 12:
                continue
            txid, flags = struct.unpack_from("!HH", data, 0)
            is_resp = bool(flags & 0x8000)
            rcode = flags & 0x000F
            res = _extractor.extract(data)
            name = res.query_name if res else None
            if not name:
                continue
            qtype = (res.query_type if res else None) or "A"
            key = (s.session_id, txid, name)

            if not is_resp:
                # 쿼리 — 같은 key의 첫 쿼리 시각만 보존(재시도는 무시)
                if key not in pending:
                    pending[key] = {"ts": p.ts, "name": name, "type": qtype,
                                    "client": p.direction == "fwd" and s.src_ip or s.src_ip}
            else:
                q = pending.pop(key, None)
                rt = None
                if q is not None and p.ts >= q["ts"]:
                    rt = round((p.ts - q["ts"]) * 1000, 2)
                pairs.append({
                    "name": name,
                    "type": qtype,
                    "rcode": _RCODE.get(rcode, str(rcode)),
                    "response_time_ms": rt,
                    "answered": True,
                    "answers": (res.response_ips[:4] if res else []),
                })

    # 매칭 안 된 쿼리 = 무응답
    for q in pending.values():
        pairs.append({
            "name": q["name"], "type": q["type"], "rcode": None,
            "response_time_ms": None, "answered": False, "answers": [],
        })

    # 통계
    rts = sorted(p["response_time_ms"] for p in pairs
                 if p["answered"] and p["response_time_ms"] is not None)
    rcode_dist: dict[str, int] = defaultdict(int)
    for p in pairs:
        if p["answered"]:
            rcode_dist[p["rcode"]] += 1
    answered = sum(1 for p in pairs if p["answered"])
    unanswered = sum(1 for p in pairs if not p["answered"])
    errors = sum(1 for p in pairs if p["answered"] and p["rcode"] not in ("NOERROR", None))

    # 느린 쿼리 top (응답시간 내림차순) + 무응답을 앞에 노출
    slowest = sorted(
        [p for p in pairs if p["response_time_ms"] is not None],
        key=lambda p: -p["response_time_ms"],
    )[:20]
    unanswered_list = [p for p in pairs if not p["answered"]][:20]

    return {
        "total": len(pairs),
        "answered": answered,
        "unanswered": unanswered,
        "errors": errors,
        "rcode_dist": dict(rcode_dist),
        "avg_ms": round(sum(rts) / len(rts), 2) if rts else 0.0,
        "p50_ms": _percentile(rts, 0.50),
        "p95_ms": _percentile(rts, 0.95),
        "max_ms": rts[-1] if rts else 0.0,
        "slowest": slowest,
        "unanswered_queries": unanswered_list,
    }
