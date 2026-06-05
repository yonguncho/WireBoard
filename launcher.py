"""WireBoard v5.0 — PyInstaller entry point."""
import socket
import sys
import webbrowser
from pathlib import Path

if getattr(sys, "frozen", False):
    # PyInstaller bundle: _MEIPASS has the extracted files
    base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
else:
    base = Path(__file__).parent

sys.path.insert(0, str(base / "backend"))

import uvicorn  # noqa: E402

_DEFAULT_PORT = 8765


def find_free_port(start: int = _DEFAULT_PORT) -> int:
    port = start
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    raise RuntimeError("사용 가능한 포트를 찾을 수 없습니다")


if __name__ == "__main__":
    port = find_free_port(_DEFAULT_PORT)
    webbrowser.open(f"http://127.0.0.1:{port}")
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
