# -*- coding: utf-8 -*-
"""선택적 내보내기 의존성(openpyxl/reportlab) 부재 시 동작.

배포 EXE 에는 두 패키지가 포함되지 않는다. 그 상태에서 ImportError 가 그대로
올라가 HTTP 500 이 되던 것을, 원인을 밝히는 501 로 닫도록 바꿨다.
"""
import builtins
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.export_service import ExportDependencyMissing, ExportService


def _block(monkeypatch, prefix):
    """지정 모듈 임포트만 실패시킨다."""
    real = builtins.__import__

    def fake(name, *a, **kw):
        if name == prefix or name.startswith(prefix + "."):
            raise ImportError(f"No module named {name!r}")
        return real(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake)


class TestOptionalExportDependencies:
    def test_excel_without_openpyxl_raises_typed_error(self, monkeypatch):
        _block(monkeypatch, "openpyxl")
        with pytest.raises(ExportDependencyMissing) as e:
            ExportService()._to_excel([], [])
        assert e.value.module == "openpyxl"
        assert e.value.fmt == "excel"

    def test_pdf_without_reportlab_raises_typed_error(self, monkeypatch):
        _block(monkeypatch, "reportlab")
        with pytest.raises(ExportDependencyMissing) as e:
            ExportService()._to_pdf([])
        assert e.value.module == "reportlab"
        assert e.value.fmt == "pdf"

    def test_message_names_the_missing_package(self, monkeypatch):
        _block(monkeypatch, "openpyxl")
        with pytest.raises(ExportDependencyMissing) as e:
            ExportService()._to_excel([], [])
        assert "openpyxl" in str(e.value)

    def test_unaffected_formats_still_work(self):
        """json/csv 는 표준 라이브러리만 쓰므로 영향이 없어야 한다."""
        svc = ExportService()
        assert svc.export([], [], "json") == b"[]"
        assert isinstance(svc.export([], [], "csv"), bytes)
