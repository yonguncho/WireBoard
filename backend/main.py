"""WireBoard v5.0 — FastAPI 진입점."""
import logging

from fastapi import FastAPI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

from routers.upload import router as upload_router
from routers.analyze import router as analyze_router
from routers.panels import router as panels_router
from routers.annotations import router as annotations_router
from routers.export import router as export_router
from store.session_store import SessionStore

app = FastAPI(title="WireBoard", version="5.0.0")
app.state.session_store = SessionStore(ttl_seconds=900.0)  # 15분 — integration.md §4 TTL_SECONDS=900
logger.info("WireBoard 서버 초기화 완료 (session TTL=900s)")

app.include_router(upload_router)
app.include_router(analyze_router)
app.include_router(panels_router)
app.include_router(annotations_router)
app.include_router(export_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
