"""FlowExtractor — 세션 → 플로우 변환 + Plotly None-separator 데이터 생성."""
from dataclasses import dataclass

from models.session import SessionModel


@dataclass
class Flow:
    flow_id: str  # == session_id — stable across analyze() calls
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float
    end_ts: float
    bytes_total: int


class FlowExtractor:
    def extract(self, sessions: list[SessionModel], target_ip: str | None = None) -> list[Flow]:
        return [
            Flow(
                flow_id=s.session_id,
                src_ip=s.src_ip,
                dst_ip=s.dst_ip,
                src_port=s.src_port,
                dst_port=s.dst_port,
                protocol=s.protocol,
                start_ts=s.start_ts,
                end_ts=s.end_ts,
                bytes_total=s.bytes_sent + s.bytes_recv,
            )
            for s in sessions
        ]

    def build_plotly_data(self, flows: list[Flow]) -> tuple[list, list]:
        """ADR-003: None separator 패턴 — 단일 trace로 모든 플로우 표현."""
        if not flows:
            return [], []

        xs: list = []
        ys: list = []
        for y_idx, flow in enumerate(flows):
            xs += [flow.start_ts, flow.end_ts, None]
            ys += [y_idx, y_idx, None]  # sequential int for Plotly Y-axis

        return xs, ys
