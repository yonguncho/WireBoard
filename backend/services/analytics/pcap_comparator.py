"""PcapComparator — pcap A(base) vs B(current) comparison.

Beyond raw byte deltas, this classifies each conversation into an at-a-glance
change type (NEW / GONE / SURGE / DROP / DEGRADED / STABLE) and rolls those up
into a single verdict (DEGRADED / IMPROVED / DIFFERENT / SIMILAR) so a
"normal vs failure" comparison is readable without manual math.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel

# A conversation whose byte volume moved by >= this factor is a surge/drop.
_SURGE_FACTOR = 3.0
# Failure ratio (0..1) at/above which a conversation is considered "failing".
_FAIL_RATIO = 0.5


@dataclass
class CompareResult:
    common_ips: set = field(default_factory=set)
    only_in_a: set = field(default_factory=set)
    only_in_b: set = field(default_factory=set)
    protocol_diff: dict = field(default_factory=dict)
    byte_ratio: dict = field(default_factory=dict)
    conversations: list = field(default_factory=list)
    verdict: dict = field(default_factory=dict)


def _is_fail_session(s: SessionModel) -> bool:
    """Heuristic per-session failure signal — TCP only.

    Deliberately conservative to avoid false DEGRADED verdicts:
    - One-way UDP (syslog, SNMP traps, NetFlow, mDNS/SSDP broadcast) never
      gets a reply by design — not a failure.
    - An RST alone is NOT a failure: browsers, load balancers, and firewalls
      routinely close healthy connections with RST after data was exchanged.
      A failure is a connection where the peer never sent anything back:
      either a request with no reply, or an RST teardown with no data at all
      within a handshake-sized packet count (a real refused connection).
    """
    if (s.protocol or "").upper() != "TCP":
        return False
    if s.bytes_sent > 0 and s.bytes_recv == 0:
        return True  # request sent, nothing came back
    if (getattr(s, "rst", False) and s.bytes_sent == 0 and s.bytes_recv == 0
            and s.packet_count <= 3):
        return True  # refused during handshake (SYN → RST)
    return False


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
    """Aggregate by direction-agnostic IP pair + dst_port + protocol."""
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
                "sessions": 0, "packets": 0, "bytes": 0, "fail": 0,
            }
            stats[key] = st
        st["sessions"] += 1
        st["packets"] += s.packet_count
        st["bytes"] += s.bytes_sent + s.bytes_recv
        if _is_fail_session(s):
            st["fail"] += 1
    return stats


def _fail_ratio(stat: dict | None) -> float:
    if not stat or stat["sessions"] == 0:
        return 0.0
    return stat["fail"] / stat["sessions"]


def _classify(a: dict | None, b: dict | None) -> str:
    """At-a-glance change type for one conversation."""
    if a and not b:
        return "GONE"
    if b and not a:
        # a brand-new conversation that is mostly failing is a new failure
        return "NEW_FAILING" if _fail_ratio(b) >= _FAIL_RATIO else "NEW"
    # both present
    a_fail, b_fail = _fail_ratio(a), _fail_ratio(b)
    if b_fail >= _FAIL_RATIO and b_fail - a_fail >= 0.25:
        return "DEGRADED"
    if a_fail >= _FAIL_RATIO and a_fail - b_fail >= 0.25:
        return "RECOVERED"
    a_bytes = a["bytes"] if a else 0
    b_bytes = b["bytes"] if b else 0
    if a_bytes == 0 and b_bytes == 0:
        return "STABLE"
    if b_bytes >= a_bytes * _SURGE_FACTOR and (b_bytes - a_bytes) > 1024:
        return "SURGE"
    if a_bytes >= b_bytes * _SURGE_FACTOR and (a_bytes - b_bytes) > 1024:
        return "DROP"
    return "STABLE"


def _build_conversations(
    sessions_a: list[SessionModel],
    sessions_b: list[SessionModel],
) -> list[dict]:
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
            "a_fail":     a["fail"] if a else 0,
            "b_sessions": b["sessions"] if b else 0,
            "b_packets":  b["packets"]  if b else 0,
            "b_bytes":    b_bytes,
            "b_fail":     b["fail"] if b else 0,
            "byte_delta": b_bytes - a_bytes,
            "status":     status,
            "change_type": _classify(a, b),
        })
    return conversations


def _build_verdict(conversations: list[dict], a_total: int, b_total: int) -> dict:
    """Roll conversation change types up into a single normal-vs-failure verdict."""
    counts: dict[str, int] = defaultdict(int)
    for c in conversations:
        counts[c["change_type"]] += 1

    newly_failing = counts.get("DEGRADED", 0) + counts.get("NEW_FAILING", 0)
    recovered = counts.get("RECOVERED", 0)
    structural = counts.get("NEW", 0) + counts.get("NEW_FAILING", 0) + counts.get("GONE", 0)
    volume = counts.get("SURGE", 0) + counts.get("DROP", 0)

    # 2-decimal rounding — must match routers/compare.py's top-level field
    if a_total > 0:
        traffic_delta_pct = round((b_total - a_total) / a_total * 100.0, 2)
    elif b_total > 0:
        traffic_delta_pct = None
    else:
        traffic_delta_pct = 0.0

    if newly_failing > 0 and newly_failing >= recovered:
        verdict = "DEGRADED"
        headline = (
            f"{newly_failing} conversation(s) started failing in the current "
            f"capture — likely a service/network regression."
        )
    elif recovered > 0 and recovered > newly_failing:
        verdict = "IMPROVED"
        headline = f"{recovered} previously-failing conversation(s) recovered."
    elif structural >= 3 or volume >= 3:
        verdict = "DIFFERENT"
        headline = (
            f"Traffic shape changed materially "
            f"({counts.get('NEW', 0) + counts.get('NEW_FAILING', 0)} new, "
            f"{counts.get('GONE', 0)} gone, {volume} surged/dropped)."
        )
    else:
        verdict = "SIMILAR"
        headline = "The two captures look materially similar."

    # top movers for the UI: failures first, then biggest byte swings
    _rank = {"NEW_FAILING": 0, "DEGRADED": 1, "GONE": 2, "DROP": 3, "SURGE": 4,
             "NEW": 5, "RECOVERED": 6, "STABLE": 9}
    top_changes = sorted(
        [c for c in conversations if c["change_type"] != "STABLE"],
        key=lambda c: (_rank.get(c["change_type"], 9), -abs(c["byte_delta"])),
    )[:15]

    return {
        "verdict": verdict,
        "headline": headline,
        "traffic_delta_pct": traffic_delta_pct,
        "counts": dict(counts),
        "newly_failing": newly_failing,
        "recovered": recovered,
        "top_changes": top_changes,
    }


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
        ratio = None if b_total == 0 else round(a_total / b_total, 4)

        conversations = _build_conversations(sessions_a, sessions_b)
        verdict = _build_verdict(conversations, a_total, b_total)

        return CompareResult(
            common_ips=common,
            only_in_a=only_a,
            only_in_b=only_b,
            protocol_diff=protocol_diff,
            byte_ratio={"a_total": a_total, "b_total": b_total, "ratio": ratio},
            conversations=conversations,
            verdict=verdict,
        )
