"""WireBoard v5.5.0 — PyInstaller entry point."""
import logging
import os
import socket
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path

_VERSION = "5.5.3"
_DEFAULT_PORT = 8765

_BANNER = """
╔══════════════════════════════════════════════════════╗
║       WireBoard v{ver} — PCAP Analysis Tool          ║
╠══════════════════════════════════════════════════════╣
║  로컬 전용 서버 (외부 네트워크 미노출)                        ║
║  종료: Ctrl+C                                        ║
╚══════════════════════════════════════════════════════╝
""".format(ver=_VERSION)


def _pause(msg: str = "\n[Enter] 키를 눌러 창을 닫으세요..."):
    try:
        input(msg)
    except Exception:
        pass


def find_free_port(start: int = _DEFAULT_PORT) -> int:
    port = start
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    raise RuntimeError("사용 가능한 포트를 찾을 수 없습니다")


def _wait_and_open_browser(port: int, timeout: float = 30.0) -> None:
    """서버가 실제로 응답할 때까지 폴링 후 브라우저 오픈."""
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        # 타임아웃 — 그냥 열어보기
        pass
    webbrowser.open(url)
    print(f"  >> 브라우저 오픈: {url}")


def main():
    # PyInstaller onefile: 임시 디렉토리에 압축 해제된 파일들
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).parent

    backend_path = str(base / "backend")
    sys.path.insert(0, backend_path)

    # uvicorn 임포트 실패 시 원인 표시
    try:
        import uvicorn
    except ImportError as e:
        print(f"\n[오류] uvicorn 임포트 실패: {e}")
        print(f"  backend 경로: {backend_path}")
        print(f"  경로 존재 여부: {os.path.isdir(backend_path)}")
        _pause()
        sys.exit(1)

    # 포트 확보
    try:
        port = find_free_port(_DEFAULT_PORT)
    except RuntimeError as e:
        print(f"\n[오류] 포트 할당 실패: {e}")
        _pause()
        sys.exit(1)

    # 브라우저 HTTP/2 preconnect 프로브 경고 억제 (기능 영향 없는 노이즈)
    class _SuppressInvalidHTTP(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            return "Invalid HTTP request received" not in record.getMessage()

    logging.getLogger("uvicorn.error").addFilter(_SuppressInvalidHTTP())

    print(_BANNER)
    print(f"  >> 접속 주소 : http://127.0.0.1:{port}")
    print(f"  >> 서버 시작 중... (Ctrl+C 로 종료)\n")

    # 서버 준비 완료 후 브라우저 자동 실행 (백그라운드 스레드)
    t = threading.Thread(
        target=_wait_and_open_browser,
        args=(port,),
        daemon=True,
    )
    t.start()

    try:
        uvicorn.run("main:app", host="127.0.0.1", port=port, reload=False)
    except KeyboardInterrupt:
        print("\nWireBoard 정상 종료.")
    except Exception:
        print(f"\n[서버 오류]\n{traceback.format_exc()}")
        _pause()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(f"\n[치명적 오류]\n{traceback.format_exc()}")
        _pause()
        sys.exit(1)
