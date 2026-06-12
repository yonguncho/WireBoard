"""PacketLens v5.0 — FastAPI 진입점."""
import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)
_access_logger = logging.getLogger("packetlens.access")

from utils.log_filter import SensitiveDataFilter
_sensitive_filter = SensitiveDataFilter()
_access_logger.addFilter(_sensitive_filter)
logging.getLogger("routers.upload").addFilter(_sensitive_filter)
logging.getLogger("routers.analyze").addFilter(_sensitive_filter)
logging.getLogger("routers.filter").addFilter(_sensitive_filter)

from routers.upload import router as upload_router
from routers.analyze import router as analyze_router
from routers.panels import router as panels_router
from routers.annotations import router as annotations_router
from routers.export import router as export_router
from routers.filter import router as filter_router
from routers.compare import router as compare_router
from routers.drilldown import router as drilldown_router
from routers.summary import router as summary_router
from routers.flow import router as flow_router
from routers.packets import router as packets_router
from routers.geoip import router as geoip_router
from routers.yara_scan import router as yara_router
from routers.network_health import router as health_router
from routers.stream import router as stream_router
from store.session_store import SessionStore
from services.analytics.geoip_analyzer import GeoIpAnalyzer
from services.attack_detector.yara_detector import YaraDetector


_SENSITIVE_PREFIXES = (
    "/api/stream/", "/api/export/", "/api/packets/", "/api/analyze/",
    "/api/annotations/", "/api/flow/", "/api/drilldown/", "/api/summary/",
    "/api/panels/",
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'none'",
}

_SPA_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:;"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """모든 응답에 보안 헤더 추가; 민감 API는 no-store Cache-Control 적용.

    API 경로: default-src 'none' (strict)
    SPA/정적 경로: self-only CSP (스크립트·스타일 로딩 허용)
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for key, val in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, val)
        path = request.url.path
        if any(path.startswith(p) for p in _SENSITIVE_PREFIXES):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        # SPA 정적 응답은 self 리소스 로딩이 가능한 완화된 CSP 적용
        if not path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = _SPA_CSP
        return response


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Per-request structured JSON logs: request / response / error events.

    각 이벤트를 print()로 stdout에 출력합니다. 이를 통해 테스트에서
    contextlib.redirect_stdout 으로 캡처할 수 있습니다.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        req_event = json.dumps({
            "event": "request",
            "requestId": request_id,
            "ts": started_at,
            "method": request.method,
            "path": request.url.path,
        })
        print(req_event, flush=True)
        _access_logger.info(req_event)

        try:
            response = await call_next(request)
            duration_ms = round((time.monotonic() - t0) * 1000, 2)
            resp_event = json.dumps({
                "event": "response",
                "requestId": request_id,
                "ts": datetime.now(timezone.utc).isoformat(),
                "status": response.status_code,
                "durationMs": duration_ms,
            })
            print(resp_event, flush=True)
            _access_logger.info(resp_event)
            return response
        except Exception as exc:
            duration_ms = round((time.monotonic() - t0) * 1000, 2)
            err_event = json.dumps({
                "event": "error",
                "requestId": request_id,
                "ts": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
                "durationMs": duration_ms,
            })
            print(err_event, flush=True)
            _access_logger.error(err_event)
            raise


app = FastAPI(title="WireBoard", version="5.5.0")
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(StructuredLoggingMiddleware)

_annotations_lock = threading.Lock()
_annotations_store: defaultdict = defaultdict(list)


def _on_evict(key: str) -> None:
    with _annotations_lock:
        _annotations_store.pop(key, None)


app.state.annotations_store = _annotations_store
app.state.annotations_lock = _annotations_lock
app.state.session_store = SessionStore(
    ttl_seconds=900.0,  # 15분 — integration.md §4 TTL_SECONDS=900
    on_evict=_on_evict,
)
app.state.geoip_analyzer = GeoIpAnalyzer()
app.state.yara_detector = YaraDetector()
logger.info("WireBoard 서버 초기화 완료 (session TTL=900s)")

app.include_router(upload_router)
app.include_router(analyze_router)
app.include_router(panels_router)
app.include_router(annotations_router)
app.include_router(export_router)
app.include_router(filter_router)
app.include_router(compare_router)
app.include_router(drilldown_router)
app.include_router(summary_router)
app.include_router(flow_router)
app.include_router(packets_router)
app.include_router(geoip_router)
app.include_router(yara_router)
app.include_router(health_router)
app.include_router(stream_router)

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    _assets_dir = os.path.join(_STATIC_DIR, "assets")
    if os.path.isdir(_assets_dir):
        app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")

    @app.get("/favicon.svg", include_in_schema=False)
    async def _favicon():
        return FileResponse(os.path.join(_STATIC_DIR, "favicon.svg"))

    @app.get("/icons.svg", include_in_schema=False)
    async def _icons():
        return FileResponse(os.path.join(_STATIC_DIR, "icons.svg"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa_fallback(full_path: str):
        # ADR-EXE-002: React Router SPA fallback — 알 수 없는 경로는 index.html 반환
        # 단, /api/* 미등록 경로는 HTML 대신 404 JSON 반환
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail={"code": "not_found", "msg": f"/{full_path}"})
        index_path = os.path.join(_STATIC_DIR, "index.html")
        return FileResponse(index_path)

    logger.info("정적 파일 서빙 (SPA fallback): %s", _STATIC_DIR)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8764, reload=False)
