"""PDF Export edge case 테스트 (TDD).

대상: services.report.pdf_exporter.PdfExporter

인터페이스 가정:
  PdfExporter().generate(analysis_result: dict, output_path: Path) -> Path
  반환: 생성된 PDF 파일 경로

analysis_result 필드:
  target_ip: str
  sessions: list[SessionModel]
  attacks: list[dict]           # {"type": str, "severity": str, "mitre_id": str}
  summary: dict                 # 요약 통계

검증 항목:
- PDF 파일 생성 (파일 존재, 크기 > 0)
- PDF 시그니처: b'%PDF' 로 시작
- target_ip 가 포함된 내용 (텍스트 검색)
- attack 정보 포함 여부
- 빈 세션 → 빈 PDF 생성 (에러 없음)
- output_path 없을 때 임시 파일 생성
- 동일 경로 재호출 → 덮어쓰기 (에러 없음)
- summary 통계 포함 여부
"""
import tempfile
import uuid
from pathlib import Path

import pytest


def _make_analysis_result(
    target_ip: str = "192.168.1.100",
    attacks: list | None = None,
    session_count: int = 3,
):
    try:
        from models.session import SessionModel
    except ImportError:
        pytest.skip("models.session 미구현")

    sessions = [
        SessionModel(
            session_id=str(uuid.uuid4()),
            src_ip="10.0.0.1",
            dst_ip=target_ip,
            src_port=50000 + i,
            dst_port=443,
            protocol="TCP",
            start_ts=1_748_000_000.0 + i,
            end_ts=1_748_000_002.0 + i,
            bytes_sent=1024,
            bytes_recv=2048,
            packet_count=10,
            payload_length=1024,
            confidence="normal",
        )
        for i in range(session_count)
    ]

    return {
        "target_ip": target_ip,
        "sessions": sessions,
        "attacks": attacks or [],
        "summary": {
            "total_sessions": session_count,
            "total_bytes": 1024 * session_count,
            "start_ts": 1_748_000_000.0,
            "end_ts": 1_748_000_000.0 + session_count,
        },
    }


def _load_exporter():
    try:
        from services.report.pdf_exporter import PdfExporter
        return PdfExporter()
    except ImportError:
        pytest.skip("pdf_exporter 미구현")


class TestPdfFileCreation:
    def test_pdf_file_created(self, tmp_path: Path):
        """PDF 파일이 생성된다."""
        exporter = _load_exporter()
        output = tmp_path / "report.pdf"
        result, _ = exporter.generate(_make_analysis_result(), output_path=output)
        assert result.exists(), "PDF 파일 생성 실패"

    def test_pdf_file_not_empty(self, tmp_path: Path):
        exporter = _load_exporter()
        output = tmp_path / "report.pdf"
        exporter.generate(_make_analysis_result(), output_path=output)
        assert output.stat().st_size > 0

    def test_pdf_signature(self, tmp_path: Path):
        """파일이 %PDF 시그니처로 시작한다."""
        exporter = _load_exporter()
        output = tmp_path / "report.pdf"
        exporter.generate(_make_analysis_result(), output_path=output)
        with open(output, "rb") as f:
            magic = f.read(4)
        assert magic == b"%PDF", f"PDF 시그니처 불일치: {magic!r}"


class TestPdfContent:
    def test_target_ip_in_pdf(self, tmp_path: Path):
        """target_ip 가 PDF 내용에 포함된다 (텍스트 레이어 검색)."""
        exporter = _load_exporter()
        output = tmp_path / "report.pdf"
        exporter.generate(_make_analysis_result(target_ip="10.20.30.40"), output_path=output)
        content = output.read_bytes()
        assert b"10.20.30.40" in content, "target_ip 가 PDF에 없음"

    def test_attack_info_in_pdf(self, tmp_path: Path):
        """공격 타입이 PDF 내용에 포함된다."""
        exporter = _load_exporter()
        attacks = [{"type": "PortScan", "severity": "high", "mitre_id": "T1046"}]
        result = _make_analysis_result(attacks=attacks)
        output = tmp_path / "report_attacks.pdf"
        exporter.generate(result, output_path=output)
        content = output.read_bytes()
        assert b"PortScan" in content or b"T1046" in content


class TestPdfEdge:
    def test_empty_sessions_no_error(self, tmp_path: Path):
        """세션 없어도 PDF 생성 (에러 없음)."""
        exporter = _load_exporter()
        output = tmp_path / "empty.pdf"
        result, _ = exporter.generate(_make_analysis_result(session_count=0), output_path=output)
        assert result.exists()

    def test_overwrite_existing_file(self, tmp_path: Path):
        """기존 PDF 경로에 재호출 → 덮어쓰기 (에러 없음)."""
        exporter = _load_exporter()
        output = tmp_path / "overwrite.pdf"
        exporter.generate(_make_analysis_result(), output_path=output)
        exporter.generate(_make_analysis_result(), output_path=output)
        assert output.exists()

    def test_auto_temp_path(self):
        """output_path 미지정 → 임시 파일 자동 생성."""
        exporter = _load_exporter()
        result, _ = exporter.generate(_make_analysis_result())
        assert result is not None
        assert result.exists()
        result.unlink(missing_ok=True)
