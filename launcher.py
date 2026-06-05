"""WireBoard v5.1 — PyInstaller entry point."""
import socket
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
else:
    base = Path(__file__).parent

sys.path.insert(0, str(base / "backend"))

import uvicorn  # noqa: E402

_DEFAULT_PORT = 8765
_VERSION = "5.1.0"

_BANNER = """
╔══════════════════════════════════════════════════════╗
║          WireBoard v{ver} — PCAP Analysis Tool         ║
╠══════════════════════════════════════════════════════╣
║  로컬 전용 서버입니다. 네트워크에 노출되지 않습니다.         ║
║  Ctrl+C 로 종료합니다.                                ║
╚══════════════════════════════════════════════════════╝
""".format(ver=_VERSION)


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
    print(_BANNER)
    print(f"  >> 브라우저에서 접속하세요: http://127.0.0.1:{port}")
    print(f"  >> 서버 시작 중...\n")
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
