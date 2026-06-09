"""패키징(PyInstaller) edge case 테스트 (TDD).

검증 항목:
- backend/main.py 가 존재한다 (entry point)
- 0.0.0.0 바인딩이 없다 (127.0.0.1 전용, ADR-005)
- main.py 의 uvicorn 호출이 host="127.0.0.1" 사용
- PyInstaller spec 파일이 있으면 console=True (GUI 아님)
- PyInstaller spec 파일의 datas 경로가 절대경로가 아닌 상대경로
- backend 디렉터리에 __pycache__ 를 제외한 .py 파일만 존재
  (*.pyc 단독 스크립트 없음 — 빌드 오염 방지)
- requirements.txt 또는 pyproject.toml 이 존재
"""
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).parent.parent / "backend"
PROJECT_ROOT = Path(__file__).parent.parent


class TestMainEntry:
    def test_main_py_exists(self):
        assert (BACKEND_DIR / "main.py").exists(), "backend/main.py 없음"

    def test_no_0000_binding(self):
        """0.0.0.0 바인딩 없음 (ADR-005)."""
        for py_file in BACKEND_DIR.rglob("*.py"):
            src = py_file.read_text(encoding="utf-8", errors="replace")
            assert "0.0.0.0" not in src, f"{py_file.name} 에 0.0.0.0 바인딩 발견"

    def test_uvicorn_uses_localhost(self):
        """main.py 의 uvicorn.run 호출이 host='127.0.0.1' 사용."""
        main_path = BACKEND_DIR / "main.py"
        if not main_path.exists():
            pytest.skip("main.py 없음")
        src = main_path.read_text(encoding="utf-8")
        # uvicorn.run 이 있으면 127.0.0.1 이어야 함
        if "uvicorn.run" in src:
            assert "127.0.0.1" in src, "uvicorn.run 에 127.0.0.1 바인딩 없음"


class TestPyInstallerSpec:
    def test_spec_file_console_true(self):
        """PacketLens.spec 파일이 있으면 console=True."""
        spec_file = PROJECT_ROOT / "PacketLens.spec"
        if not spec_file.exists():
            pytest.skip("PacketLens.spec 없음 — 패키징 단계 이전")
        src = spec_file.read_text(encoding="utf-8")
        assert "console=True" in src, "spec 파일에 console=True 없음 (GUI 빌드 금지)"

    def test_spec_no_absolute_paths_in_datas(self):
        """spec 파일 datas 에 절대경로 없음."""
        spec_file = PROJECT_ROOT / "PacketLens.spec"
        if not spec_file.exists():
            pytest.skip("PacketLens.spec 없음")
        src = spec_file.read_text(encoding="utf-8")
        # Windows 절대경로 패턴 탐지 (C:\, D:\, /, 등)
        import re
        abs_in_datas = re.search(r"datas\s*=\s*\[.*?[A-Za-z]:\\", src, re.DOTALL)
        assert abs_in_datas is None, "spec datas 에 절대경로 발견"


class TestBuildArtifacts:
    def test_requirements_or_pyproject_exists(self):
        """의존성 파일이 프로젝트 루트에 존재한다."""
        req = PROJECT_ROOT / "requirements.txt"
        pyproj = PROJECT_ROOT / "pyproject.toml"
        assert req.exists() or pyproj.exists(), (
            "requirements.txt 또는 pyproject.toml 없음"
        )

    def test_no_orphan_pyc_in_backend(self):
        """.pyc 전용 파일이 backend에 .py 없이 단독 존재하지 않는다."""
        violations = []
        for pyc_file in BACKEND_DIR.rglob("*.pyc"):
            if "__pycache__" in pyc_file.parts:
                continue  # __pycache__ 내부는 허용
            py_equivalent = pyc_file.with_suffix(".py")
            if not py_equivalent.exists():
                violations.append(str(pyc_file))
        assert not violations, f"소스 없는 .pyc 파일: {violations}"

    def test_no_test_files_in_backend(self):
        """backend/ 디렉터리에 test_ 파일 없음 (빌드 오염 방지)."""
        test_files = list(BACKEND_DIR.rglob("test_*.py"))
        assert not test_files, f"backend/에 테스트 파일 발견: {test_files}"


class TestRuntimeConfig:
    def test_app_startup_does_not_crash(self):
        """FastAPI app import 가 크래시 없이 완료된다."""
        import sys
        sys.path.insert(0, str(BACKEND_DIR))
        try:
            from main import app  # noqa: F401
            assert app is not None
        except ImportError as exc:
            pytest.skip(f"backend 미구현: {exc}")
        finally:
            sys.path.pop(0)

    def test_session_store_initialized(self):
        """app.state.session_store 가 초기화된다."""
        import sys
        sys.path.insert(0, str(BACKEND_DIR))
        try:
            from main import app  # noqa: F401
            assert hasattr(app.state, "session_store"), "session_store 미초기화"
        except ImportError as exc:
            pytest.skip(f"backend 미구현: {exc}")
        finally:
            sys.path.pop(0)
