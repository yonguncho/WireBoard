"""FlowExtractor — 세션 → 플로우 변환 + Plotly None-separator 데이터 생성."""
from dataclasses import dataclass

from models.session import SessionModel


@dataclass
class Flow:
    flow_id: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float
    end_ts: float
    bytes_total: int


class FlowExtractor:
    def extract(self, sessions: list[SessionModel]) -> list[Flow]:
        flows: list[Flow] = []
        for flow_idx, s in enumerate(sessions):
            flows.append(Flow(
                flow_id=flow_idx,
                src_ip=s.src_ip,
                dst_ip=s.dst_ip,
                src_port=s.src_port,
                dst_port=s.dst_port,
                protocol=s.protocol,
                start_ts=s.start_ts,
                end_ts=s.end_ts,
                bytes_total=s.bytes_sent + s.bytes_recv,
            ))
        return flows

    def build_plotly_data(self, flows: list[Flow]) -> tuple[list, list]:
        """ADR-003: None separator 패턴 — 단일 trace로 모든 플로우 표현."""
        if not flows:
            return [], []

        xs: list = []
        ys: list = []
        for flow in flows:
            xs += [flow.start_ts, flow.end_ts, None]
            ys += [flow.flow_id, flow.flow_id, None]

        return xs, ys
