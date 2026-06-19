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
    conversations: list = field(default_factory=list)


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


def _conversation_stats(sessions: list[SessionModel]) -> dict[str, dict]:
    """대화 단위 집계. 키 = 방향 무관 IP쌍 + dst_port + protocol.

    같은 통신(예: client↔server:443/TCP)이 서로 다른 캡처에서 출발 포트만
    달라도 동일 대화로 묶이도록 IP쌍을 정렬해 방향성을 제거한다.
    """
    stats: dict[str, dict] = {}
    for s in sessions:
        ip_a, ip_b = sorted((s.src_ip, s.dst_ip))
        key = f"{ip_a}|{ip_b}|{s.dst_port}|{s.protocol}"
        st = stats.get(key)
        if st is None:
            st = {
                "key": key,
                "ip_a": ip_a, "ip_b": ip_b,
                "port": s.dst_port, "protocol": s.protocol,
                "sessions": 0, "packets": 0, "bytes": 0,
            }
            stats[key] = st
        st["sessions"] += 1
        st["packets"] += s.packet_count
        st["bytes"] += s.bytes_sent + s.bytes_recv
    return stats


def _build_conversations(
    sessions_a: list[SessionModel],
    sessions_b: list[SessionModel],
) -> list[dict]:
    """A·B 대화 집계를 키 기준으로 병합해 통계 차이를 산출."""
    conv_a = _conversation_stats(sessions_a)
    conv_b = _conversation_stats(sessions_b)
    conversations: list[dict] = []
    for key in set(conv_a) | set(conv_b):
        a = conv_a.get(key)
        b = conv_b.get(key)
        meta = a or b
        a_bytes = a["bytes"] if a else 0
        b_bytes = b["bytes"] if b else 0
        status = "both" if (a and b) else ("only_a" if a else "only_b")
        conversations.append({
            "key": key,
            "ip_a": meta["ip_a"], "ip_b": meta["ip_b"],
            "port": meta["port"], "protocol": meta["protocol"],
            "a_sessions": a["sessions"] if a else 0,
            "a_packets":  a["packets"]  if a else 0,
            "a_bytes":    a_bytes,
            "b_sessions": b["sessions"] if b else 0,
            "b_packets":  b["packets"]  if b else 0,
            "b_bytes":    b_bytes,
            "byte_delta": b_bytes - a_bytes,
            "status":     status,
        })
    return conversations


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
        # None when b_total=0: current capture is empty, ratio is undefined
        ratio = None if b_total == 0 else round(a_total / b_total, 4)

        return CompareResult(
            common_ips=common,
            only_in_a=only_a,
            only_in_b=only_b,
            protocol_diff=protocol_diff,
            byte_ratio={"a_total": a_total, "b_total": b_total, "ratio": ratio},
            conversations=_build_conversations(sessions_a, sessions_b),
        )
