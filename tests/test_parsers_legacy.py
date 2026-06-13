"""파서 등록/해제 시나리오 테스트 (레거시 호환성 검증).

TcpdumpParser가 _PARSERS에 등록되어 있는지 확인하고,
동적으로 제거/추가해도 upload 엔드포인트가 정상 동작하는지 검증.
"""
import io
import os
import sys

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


class TestParserRegistration:
    """_PARSERS 목록에 4종 파서가 모두 등록되어 있는지 검증."""

    def test_tcpdump_parser_is_registered(self):
        """TcpdumpParser가 _PARSERS 목록에 포함되어 있다."""
        from routers.upload import _PARSERS
        from services.parser.tcpdump_parser import TcpdumpParser
        assert any(isinstance(p, TcpdumpParser) for p in _PARSERS), \
            "TcpdumpParser가 _PARSERS에 없음"

    def test_pcap_parser_is_registered(self):
        from routers.upload import _PARSERS
        from services.parser.pcap_parser import PcapParser
        assert any(isinstance(p, PcapParser) for p in _PARSERS), "PcapParser 누락"

    def test_har_parser_is_registered(self):
        from routers.upload import _PARSERS
        from services.parser.har_parser import HarParser
        assert any(isinstance(p, HarParser) for p in _PARSERS), "HarParser 누락"

    def test_fortigate_parser_is_registered(self):
        from routers.upload import _PARSERS
        from services.parser.fortigate_parser import FortigateParser
        assert any(isinstance(p, FortigateParser) for p in _PARSERS), "FortigateParser 누락"

    def test_parser_list_has_exactly_four_entries(self):
        from routers.upload import _PARSERS
        assert len(_PARSERS) == 4, f"파서 수가 4가 아님: {len(_PARSERS)}"


class TestParserDynamicRemoveRestore:
    """_PARSERS에서 TcpdumpParser를 제거/복원하며 업로드 결과를 검증."""

    def test_tcpdump_removed_upload_rejected(self, api_client, tcpdump_text):
        """TcpdumpParser 제거 시 tcpdump 파일 업로드가 거부된다 (400/415/422)."""
        import routers.upload as upload_mod
        from services.parser.tcpdump_parser import TcpdumpParser

        original = list(upload_mod._PARSERS)
        upload_mod._PARSERS[:] = [p for p in original if not isinstance(p, TcpdumpParser)]
        try:
            resp = api_client.post(
                "/api/upload",
                files={
                    "file": (
                        "capture.tcpdump",
                        io.BytesIO(tcpdump_text.encode()),
                        "text/plain",
                    )
                },
            )
            assert resp.status_code in (400, 415, 422), (
                f"TcpdumpParser 없이 업로드가 {resp.status_code}로 성공했음"
            )
        finally:
            upload_mod._PARSERS[:] = original

    def test_tcpdump_restored_upload_succeeds(self, api_client, tcpdump_text):
        """TcpdumpParser 제거 후 복원하면 tcpdump 파일 업로드가 성공한다."""
        import routers.upload as upload_mod
        from services.parser.tcpdump_parser import TcpdumpParser

        original = list(upload_mod._PARSERS)
        upload_mod._PARSERS[:] = [p for p in original if not isinstance(p, TcpdumpParser)]
        upload_mod._PARSERS.append(TcpdumpParser())
        try:
            resp = api_client.post(
                "/api/upload",
                files={
                    "file": (
                        "capture.tcpdump",
                        io.BytesIO(tcpdump_text.encode()),
                        "text/plain",
                    )
                },
            )
            assert resp.status_code == 200, (
                f"TcpdumpParser 복원 후 업로드 실패: {resp.status_code}"
            )
        finally:
            upload_mod._PARSERS[:] = original

    def test_parsers_restored_after_removal(self, api_client, tcpdump_text):
        """제거/복원 후 원본 _PARSERS 상태가 보존된다."""
        import routers.upload as upload_mod
        from services.parser.tcpdump_parser import TcpdumpParser

        original_ids = [id(p) for p in upload_mod._PARSERS]
        original_len = len(upload_mod._PARSERS)

        backup = list(upload_mod._PARSERS)
        upload_mod._PARSERS[:] = [p for p in backup if not isinstance(p, TcpdumpParser)]
        upload_mod._PARSERS[:] = backup  # 즉시 복원

        assert len(upload_mod._PARSERS) == original_len
        assert [id(p) for p in upload_mod._PARSERS] == original_ids
