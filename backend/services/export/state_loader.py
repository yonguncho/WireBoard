"""StateLoader — JSON → 세션 + 어노테이션 복원."""
from models.session import SessionModel


class StateLoader:
    def load(self, data: dict) -> tuple[list[SessionModel], list]:
        if not isinstance(data, dict):
            raise ValueError("data는 dict여야 합니다")
        if "sessions" not in data:
            raise KeyError("sessions 필드가 없습니다")
        raw_sessions = data["sessions"]
        if not isinstance(raw_sessions, list):
            raise ValueError("sessions는 list여야 합니다")

        sessions = []
        for item in raw_sessions:
            if not isinstance(item, dict):
                raise ValueError(f"세션 항목은 dict여야 합니다: {item!r}")
            sessions.append(SessionModel(**item))

        annotations = data.get("annotations", [])
        if not isinstance(annotations, list):
            annotations = []

        return sessions, annotations
