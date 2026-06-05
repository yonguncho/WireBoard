"""PacketLens v5.0 — FastAPI 진입점."""
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)
_access_logger = logging.getLogger("packetlens.access")

from routers.upload import router as upload_router
from routers.analyze import router as analyze_router
from routers.panels import router as panels_router
from routers.annotations import router as annotations_router
from routers.export import router as export_router
from routers.filter import router as filter_router
from routers.compare import router as compare_router
from store.session_store import SessionStore


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Per-request structured JSON logs: request / response / error events."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        _access_logger.info(json.dumps({
            "event": "request",
            "requestId": request_id,
            "timestamp": started_at,
            "method": request.method,
            "path": request.url.path,
        }))

        try:
            response = await call_next(request)
            duration_ms = round((time.monotonic() - t0) * 1000, 2)
            _access_logger.info(json.dumps({
                "event": "response",
                "requestId": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "statusCode": response.status_code,
                "durationMs": duration_ms,
            }))
            return response
        except Exception as exc:
            duration_ms = round((time.monotonic() - t0) * 1000, 2)
            _access_logger.error(json.dumps({
                "event": "error",
                "requestId": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
                "durationMs": duration_ms,
            }))
            raise


app = FastAPI(title="PacketLens", version="5.0.0")
app.add_middleware(StructuredLoggingMiddleware)

_annotations_store: defaultdict = defaultdict(list)
app.state.annotations_store = _annotations_store
app.state.session_store = SessionStore(
    ttl_seconds=900.0,  # 15분 — integration.md §4 TTL_SECONDS=900
    on_evict=lambda key: _annotations_store.pop(key, None),
)
logger.info("PacketLens 서버 초기화 완료 (session TTL=900s)")

app.include_router(upload_router)
app.include_router(analyze_router)
app.include_router(panels_router)
app.include_router(annotations_router)
app.include_router(export_router)
app.include_router(filter_router)
app.include_router(compare_router)

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
    logger.info("정적 파일 서빙: %s", _STATIC_DIR)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
