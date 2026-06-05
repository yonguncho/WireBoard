"""StateExporter — 세션 + 어노테이션 JSON export."""
import json

from models.session import SessionModel


class StateExporter:
    def export(self, sessions: list[SessionModel], annotations: list | None = None) -> dict:
        if annotations is None:
            annotations = []
        return {
            "version": "1.0",
            "sessions": [s.model_dump() for s in sessions],
            "annotations": list(annotations),
        }
