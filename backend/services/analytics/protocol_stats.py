"""ProtocolStats — Panel 2: 프로토콜 분포 + Top 10 포트."""
from collections import defaultdict
from dataclasses import dataclass, field

from models.session import SessionModel

_PORT_APP: dict[tuple[int, str], str] = {
    (80, "TCP"): "HTTP",
    (443, "TCP"): "HTTPS",
    (443, "UDP"): "QUIC",
    (53, "UDP"): "DNS",
    (53, "TCP"): "DNS",
    (22, "TCP"): "SSH",
    (21, "TCP"): "FTP",
    (25, "TCP"): "SMTP",
    (587, "TCP"): "SMTP",
    (3389, "TCP"): "RDP",
    (8080, "TCP"): "HTTP-ALT",
    (3306, "TCP"): "MySQL",
    (5432, "TCP"): "PostgreSQL",
    (27017, "TCP"): "MongoDB",
    (6379, "TCP"): "Redis",
}


@dataclass
class ProtocolStatsResult:
    distribution: dict = field(default_factory=dict)
    top_ports: list = field(default_factory=list)


class ProtocolStats:
    def compute(self, sessions: list[SessionModel]) -> ProtocolStatsResult:
        if not sessions:
            return ProtocolStatsResult()

        proto_counts: dict[str, int] = defaultdict(int)
        port_counts: dict[int, int] = defaultdict(int)
        port_proto: dict[int, str] = {}

        for s in sessions:
            proto_counts[s.protocol] += 1
            port_counts[s.dst_port] += 1
            if s.dst_port not in port_proto:
                port_proto[s.dst_port] = s.protocol

        sorted_ports = sorted(port_counts.items(), key=lambda x: (-x[1], x[0]))
        top_ports = []
        for port, count in sorted_ports[:10]:
            proto = port_proto.get(port, "TCP")
            app = _PORT_APP.get((port, proto), _PORT_APP.get((port, "TCP"), ""))
            top_ports.append({"port": port, "count": count, "app": app})

        return ProtocolStatsResult(
            distribution=dict(proto_counts),
            top_ports=top_ports,
        )
