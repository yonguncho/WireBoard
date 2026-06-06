"""StateLoader — JSON → 세션 + 어노테이션 복원."""
import logging

from pydantic import ValidationError

from models.session import SessionModel

logger = logging.getLogger(__name__)


class StateLoader:
    def load(
        self,
        data: dict,
        parse_warnings: list[str] | None = None,
    ) -> tuple[list[SessionModel], list]:
        """data를 세션 + 어노테이션으로 복원한다.

        parse_warnings가 주어지면 개별 세션 오류를 skip하고 경고를 수집한다.
        주어지지 않으면(기본) 오류 시 즉시 예외를 올린다 (ADR-004 준수).
        """
        if not isinstance(data, dict):
            raise ValueError("data는 dict여야 합니다")
        version = data.get("version", "1.0")
        if version != "1.0":
            logger.warning("예상치 못한 state version: %s (expected 1.0) — 하위 호환 시도", version)
        if "sessions" not in data:
            raise KeyError("sessions 필드가 없습니다")
        raw_sessions = data["sessions"]
        if not isinstance(raw_sessions, list):
            raise ValueError("sessions는 list여야 합니다")

        sessions = []
        for item in raw_sessions:
            if not isinstance(item, dict):
                if parse_warnings is not None:
                    msg = f"세션 항목 타입 오류 (skip): {item!r}"
                    logger.warning(msg)
                    parse_warnings.append(msg)
                    continue
                raise ValueError(f"세션 항목은 dict여야 합니다: {item!r}")
            try:
                sessions.append(SessionModel(**item))
            except (ValidationError, KeyError, TypeError) as exc:
                if parse_warnings is not None:
                    msg = f"세션 복원 실패 (skip): {exc}"
                    logger.warning(msg)
                    parse_warnings.append(msg)
                else:
                    raise

        annotations = data.get("annotations", [])
        if not isinstance(annotations, list):
            annotations = []

        return sessions, annotations
