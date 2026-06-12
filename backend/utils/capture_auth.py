"""Shared helper for capture-scoped access control."""
import secrets

from fastapi import HTTPException


def check_capture_token(capture, x_upload_token: str | None) -> None:
    """Raise 403 if capture has a token and the provided token doesn't match."""
    if capture.capture_token:
        provided = x_upload_token or ""
        if not secrets.compare_digest(provided, capture.capture_token):
            raise HTTPException(
                status_code=403,
                detail={"code": "forbidden", "msg": "X-Upload-Token이 일치하지 않습니다"},
            )
