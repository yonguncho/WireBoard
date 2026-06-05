"""DnsAnalyzer — Panel 8: DNS 쿼리 분석 + NXDOMAIN."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel

_NXDOMAIN_RATE_THRESHOLD = 0.5


@dataclass
class DnsAnalysisResult:
    query_counts: dict = field(default_factory=dict)
    query_types: dict = field(default_factory=dict)
    nxdomain_count: int = 0
    nxdomain_domains: list = field(default_factory=list)
    nxdomain_sources: list = field(default_factory=list)
    entries: list = field(default_factory=list)


class DnsAnalyzer:
    def analyze(self, sessions: list[SessionModel]) -> DnsAnalysisResult:
        query_counts: dict[str, int] = defaultdict(int)
        query_types: dict[str, int] = defaultdict(int)
        nxdomain_count = 0
        nxdomain_domains: set[str] = set()
        src_total: dict[str, int] = defaultdict(int)
        src_nxdomain: dict[str, int] = defaultdict(int)
        entries: list[dict] = []
        seen_entries: set[tuple] = set()

        for s in sessions:
            if not s.meta:
                continue
            domain = s.meta.get("dns_query")
            if not domain:
                continue
            query_counts[domain] += 1
            qtype = s.meta.get("dns_type", "") or "A"
            if qtype:
                query_types[qtype] += 1
            rcode = s.meta.get("dns_rcode", "")
            src_total[s.src_ip] += 1
            if rcode == "NXDOMAIN":
                nxdomain_count += 1
                nxdomain_domains.add(domain)
                src_nxdomain[s.src_ip] += 1
            nxdomain = rcode == "NXDOMAIN"
            response = s.meta.get("dns_response") or (rcode if rcode and rcode not in ("NOERROR", "") else None)
            key = (domain, qtype, rcode)
            if key not in seen_entries:
                seen_entries.add(key)
                entries.append({"domain": domain, "type": qtype, "response": response, "nxdomain": nxdomain})

        nxdomain_sources = [
            ip for ip, cnt in src_nxdomain.items()
            if src_total[ip] > 0 and cnt / src_total[ip] >= _NXDOMAIN_RATE_THRESHOLD
        ]

        return DnsAnalysisResult(
            query_counts=dict(query_counts),
            query_types=dict(query_types),
            nxdomain_count=nxdomain_count,
            nxdomain_domains=sorted(nxdomain_domains),
            nxdomain_sources=nxdomain_sources,
            entries=entries,
        )
