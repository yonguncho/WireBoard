"""FastAPI dependency helpers."""
from fastapi import Request
from store.session_store import SessionStore


def get_store(request: Request) -> SessionStore:
    return request.app.state.session_store
