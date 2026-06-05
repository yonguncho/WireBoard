"""PcapComparator — pcap A vs B 비교 분석."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel


@dataclass
class CompareResult:
    common_ips: set = field(default_factory=set)
    only_in_a: set = field(default_factory=set)
    only_in_b: set = field(default_factory=set)
    protocol_diff: dict = field(default_factory=dict)
    byte_ratio: dict = field(default_factory=dict)


def _get_ips(sessions: list[SessionModel]) -> set[str]:
    ips: set[str] = set()
    for s in sessions:
        ips.add(s.src_ip)
        ips.add(s.dst_ip)
    return ips


def _protocol_counts(sessions: list[SessionModel]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for s in sessions:
        counts[s.protocol] += 1
    return dict(counts)


class PcapComparator:
    def compare(
        self,
        sessions_a: list[SessionModel],
        sessions_b: list[SessionModel],
    ) -> CompareResult:
        ips_a = _get_ips(sessions_a)
        ips_b = _get_ips(sessions_b)

        common = ips_a & ips_b
        only_a = ips_a - ips_b
        only_b = ips_b - ips_a

        proto_a = _protocol_counts(sessions_a)
        proto_b = _protocol_counts(sessions_b)
        all_protos = set(proto_a) | set(proto_b)
        protocol_diff: dict[str, dict] = {}
        for proto in all_protos:
            a_cnt = proto_a.get(proto, 0)
            b_cnt = proto_b.get(proto, 0)
            total = a_cnt + b_cnt
            diff_pct = abs(a_cnt - b_cnt) / total * 100.0 if total else 0.0
            protocol_diff[proto] = {"a": a_cnt, "b": b_cnt, "diff_pct": round(diff_pct, 2)}

        a_total = sum(s.bytes_sent + s.bytes_recv for s in sessions_a)
        b_total = sum(s.bytes_sent + s.bytes_recv for s in sessions_b)
        ratio = a_total / b_total if b_total else 0.0

        return CompareResult(
            common_ips=common,
            only_in_a=only_a,
            only_in_b=only_b,
            protocol_diff=protocol_diff,
            byte_ratio={"a_total": a_total, "b_total": b_total, "ratio": round(ratio, 4)},
        )
