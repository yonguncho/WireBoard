"""파서 등록/해제 시나리오 테스트.

아키텍처: 바이너리 pcap은 매직 판정 후 스트리밍 파싱(PcapParser)으로 처리하고,
텍스트 포맷(HAR/FortiGate/tcpdump)은 _TEXT_PARSERS 목록의 detect 루프로 처리한다.
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
    """_TEXT_PARSERS 목록에 텍스트 파서 3종이 등록되어 있는지 검증."""

    def test_tcpdump_parser_is_registered(self):
        from routers.upload import _TEXT_PARSERS
        from services.parser.tcpdump_parser import TcpdumpParser
        assert any(isinstance(p, TcpdumpParser) for p in _TEXT_PARSERS)

    def test_har_parser_is_registered(self):
        from routers.upload import _TEXT_PARSERS
        from services.parser.har_parser import HarParser
        assert any(isinstance(p, HarParser) for p in _TEXT_PARSERS)

    def test_fortigate_parser_is_registered(self):
        from routers.upload import _TEXT_PARSERS
        from services.parser.fortigate_parser import FortigateParser
        assert any(isinstance(p, FortigateParser) for p in _TEXT_PARSERS)

    def test_text_parser_list_has_exactly_three_entries(self):
        from routers.upload import _TEXT_PARSERS
        assert len(_TEXT_PARSERS) == 3, f"텍스트 파서 수가 3이 아님: {len(_TEXT_PARSERS)}"

    def test_pcap_handled_via_streaming(self, api_client):
        """바이너리 pcap은 _TEXT_PARSERS가 아니라 스트리밍 경로로 처리된다."""
        from conftest import build_pcap
        resp = api_client.post(
            "/api/upload",
            files={"file": ("c.pcap", io.BytesIO(build_pcap(num_packets=3)), "application/octet-stream")},
        )
        assert resp.status_code == 200
        assert resp.json()["source_type"] == "pcap"


class TestParserDynamicRemoveRestore:
    """_TEXT_PARSERS에서 TcpdumpParser를 제거/복원하며 업로드 결과를 검증."""

    def test_tcpdump_removed_upload_rejected(self, api_client, tcpdump_text):
        import routers.upload as upload_mod
        from services.parser.tcpdump_parser import TcpdumpParser

        original = list(upload_mod._TEXT_PARSERS)
        upload_mod._TEXT_PARSERS[:] = [p for p in original if not isinstance(p, TcpdumpParser)]
        try:
            resp = api_client.post(
                "/api/upload",
                files={"file": ("capture.tcpdump", io.BytesIO(tcpdump_text.encode()), "text/plain")},
            )
            assert resp.status_code in (400, 415, 422)
        finally:
            upload_mod._TEXT_PARSERS[:] = original

    def test_tcpdump_restored_upload_succeeds(self, api_client, tcpdump_text):
        import routers.upload as upload_mod
        from services.parser.tcpdump_parser import TcpdumpParser

        original = list(upload_mod._TEXT_PARSERS)
        upload_mod._TEXT_PARSERS[:] = [p for p in original if not isinstance(p, TcpdumpParser)]
        upload_mod._TEXT_PARSERS.append(TcpdumpParser())
        try:
            resp = api_client.post(
                "/api/upload",
                files={"file": ("capture.tcpdump", io.BytesIO(tcpdump_text.encode()), "text/plain")},
            )
            assert resp.status_code == 200
        finally:
            upload_mod._TEXT_PARSERS[:] = original

    def test_parsers_restored_after_removal(self, api_client, tcpdump_text):
        import routers.upload as upload_mod
        from services.parser.tcpdump_parser import TcpdumpParser

        original_ids = [id(p) for p in upload_mod._TEXT_PARSERS]
        original_len = len(upload_mod._TEXT_PARSERS)

        backup = list(upload_mod._TEXT_PARSERS)
        upload_mod._TEXT_PARSERS[:] = [p for p in backup if not isinstance(p, TcpdumpParser)]
        upload_mod._TEXT_PARSERS[:] = backup

        assert len(upload_mod._TEXT_PARSERS) == original_len
        assert [id(p) for p in upload_mod._TEXT_PARSERS] == original_ids
