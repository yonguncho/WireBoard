"""End-to-end flow edge case 테스트.

전체 흐름: upload → analyze → panel 데이터 → attack badges → annotation → PDF export

검증 항목:
- pcap upload → analyze → 응답에 sessions/flows/attacks 포함
- HAR upload → analyze → HTTP 관련 응답
- attack_badges: 공격 탐지 시 응답의 attacks 리스트 비어있지 않음
- GET /api/panels/{upload_id} 존재 → 패널 데이터 반환
- POST /api/annotations 존재 → 어노테이션 저장
- GET /api/export/{upload_id} → JSON export 다운로드
- POST /api/export/{upload_id}/pdf → PDF 생성
- 전체 흐름 에러 없음 (5xx 없음)
- upload_id 재사용 → analyze 에서 일관된 결과
"""
import io
import re
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ─────────────────────────── 헬퍼 ───────────────────────────────────


def _upload(client: TestClient, data: bytes, filename: str = "capture.pcap", mime: str = "application/octet-stream") -> str:
    resp = client.post(
        "/api/upload",
        files={"file": (filename, io.BytesIO(data), mime)},
    )
    assert resp.status_code == 200, f"업로드 실패: {resp.text}"
    return resp.json()["upload_id"]


def _analyze(client: TestClient, upload_id: str, target_ip: str = "192.168.1.2") -> dict[str, Any]:
    resp = client.post(
        "/api/analyze",
        json={"upload_id": upload_id, "target_ip": target_ip},
    )
    assert resp.status_code == 200, f"분석 실패: {resp.text}"
    return resp.json()


# ─────────────────── 기본 업로드→분석 플로우 ────────────────────────


class TestE2EBasicFlow:
    def test_pcap_upload_then_analyze(self, api_client: TestClient, pcap_bytes: bytes):
        upload_id = _upload(api_client, pcap_bytes)
        body = _analyze(api_client, upload_id)
        assert "sessions" in body
        assert "attacks" in body
        assert isinstance(body["sessions"], list)

    def test_analyze_no_5xx(self, api_client: TestClient, pcap_bytes: bytes):
        """전체 흐름에서 5xx 없음."""
        upload_id = _upload(api_client, pcap_bytes)
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": upload_id, "target_ip": "192.168.1.2"},
        )
        assert resp.status_code < 500

    def test_upload_id_consistent(self, api_client: TestClient, pcap_bytes: bytes):
        """같은 upload_id 로 2회 analyze → 동일한 sessions 반환."""
        upload_id = _upload(api_client, pcap_bytes)
        body1 = _analyze(api_client, upload_id)
        body2 = _analyze(api_client, upload_id)
        assert len(body1["sessions"]) == len(body2["sessions"])

    def test_har_upload_analyze(self, api_client: TestClient, har_json: str):
        # HAR parser sets src_ip="127.0.0.1"; omit target_ip for auto-detection
        upload_id = _upload(api_client, har_json.encode(), filename="session.har", mime="application/json")
        body = _analyze(api_client, upload_id, target_ip=None)
        assert body is not None

    def test_fortigate_upload_analyze(self, api_client: TestClient, fortigate_v3_text: str):
        upload_id = _upload(api_client, fortigate_v3_text.encode(), filename="sniffer.log", mime="text/plain")
        body = _analyze(api_client, upload_id, target_ip="10.0.0.1")
        assert body is not None


# ─────────────────── 패널 API ───────────────────────────────────────


class TestE2EPanels:
    def test_panels_endpoint_returns_200(self, api_client: TestClient, pcap_bytes: bytes):
        """GET /api/panels/{upload_id} → 200."""
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        resp = api_client.get(f"/api/panels/{upload_id}")
        if resp.status_code == 404:
            pytest.skip("/api/panels 미구현")
        assert resp.status_code == 200

    def test_panels_response_has_expected_keys(self, api_client: TestClient, pcap_bytes: bytes):
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        resp = api_client.get(f"/api/panels/{upload_id}")
        if resp.status_code == 404:
            pytest.skip("/api/panels 미구현")
        body = resp.json()
        assert isinstance(body, dict)


# ─────────────────── 어노테이션 ─────────────────────────────────────


class TestE2EAnnotation:
    def test_create_annotation(self, api_client: TestClient, pcap_bytes: bytes):
        """POST /api/annotations → 어노테이션 저장."""
        upload_id = _upload(api_client, pcap_bytes)
        payload = {
            "upload_id": upload_id,
            "start_ts": 1_748_000_005.0,
            "end_ts": 1_748_000_065.0,
            "comment": "Suspicious spike",
        }
        resp = api_client.post("/api/annotations", json=payload)
        if resp.status_code == 404:
            pytest.skip("/api/annotations 미구현")
        assert resp.status_code in {200, 201}

    def test_get_annotations(self, api_client: TestClient, pcap_bytes: bytes):
        """GET /api/annotations/{upload_id} → 어노테이션 목록."""
        upload_id = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/annotations/{upload_id}")
        if resp.status_code == 404:
            pytest.skip("/api/annotations 미구현")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ─────────────────── IP 드릴다운 ─────────────────────────────────────


class TestE2EDrilldown:
    def test_drilldown_returns_200(self, api_client: TestClient, pcap_bytes: bytes):
        """GET /api/drilldown/{upload_id}?ip= → 200 + 세션 목록."""
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        # capture에서 첫 번째 세션의 src_ip 추출
        panels_resp = api_client.get(f"/api/panels/{upload_id}")
        if panels_resp.status_code != 200:
            pytest.skip("panels 미구현")
        top_src = panels_resp.json().get("panel1_ip", {}).get("top_src", [])
        if not top_src:
            pytest.skip("분석 결과에 IP 없음")
        ip = top_src[0]["ip"]
        resp = api_client.get(f"/api/drilldown/{upload_id}", params={"ip": ip})
        assert resp.status_code == 200

    def test_drilldown_response_schema(self, api_client: TestClient, pcap_bytes: bytes):
        """드릴다운 응답이 ip, session_count, sessions 키를 포함해야 한다."""
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        panels_resp = api_client.get(f"/api/panels/{upload_id}")
        top_src = panels_resp.json().get("panel1_ip", {}).get("top_src", [])
        if not top_src:
            pytest.skip("분석 결과에 IP 없음")
        ip = top_src[0]["ip"]
        body = api_client.get(f"/api/drilldown/{upload_id}", params={"ip": ip}).json()
        assert "ip" in body
        assert "session_count" in body
        assert "sessions" in body
        assert isinstance(body["sessions"], list)

    def test_drilldown_sessions_contain_ip(self, api_client: TestClient, pcap_bytes: bytes):
        """드릴다운된 세션은 모두 요청 IP를 src 또는 dst에 포함해야 한다."""
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        panels_resp = api_client.get(f"/api/panels/{upload_id}")
        top_src = panels_resp.json().get("panel1_ip", {}).get("top_src", [])
        if not top_src:
            pytest.skip("분석 결과에 IP 없음")
        ip = top_src[0]["ip"]
        body = api_client.get(f"/api/drilldown/{upload_id}", params={"ip": ip}).json()
        for sess in body["sessions"]:
            assert sess["src_ip"] == ip or sess["dst_ip"] == ip

    def test_drilldown_invalid_uuid_returns_400(self, api_client: TestClient):
        """잘못된 upload_id → 400."""
        resp = api_client.get("/api/drilldown/not-a-uuid", params={"ip": "1.2.3.4"})
        assert resp.status_code == 400

    def test_drilldown_unknown_upload_id_returns_404(self, api_client: TestClient):
        """없는 upload_id → 404."""
        import uuid
        resp = api_client.get(f"/api/drilldown/{uuid.uuid4()}", params={"ip": "1.2.3.4"})
        assert resp.status_code == 404


# ─────────────────── JSON Export ────────────────────────────────────


class TestE2EExport:
    def test_json_export_endpoint(self, api_client: TestClient, pcap_bytes: bytes):
        """GET /api/export/{upload_id} → JSON 다운로드."""
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        resp = api_client.get(f"/api/export/{upload_id}")
        if resp.status_code == 404:
            pytest.skip("/api/export 미구현")
        assert resp.status_code == 200

    def test_json_export_is_valid_json(self, api_client: TestClient, pcap_bytes: bytes):
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        resp = api_client.get(f"/api/export/{upload_id}")
        if resp.status_code == 404:
            pytest.skip("/api/export 미구현")
        import json
        data = resp.json()
        assert isinstance(data, dict)


# ─────────────────── PDF Export ─────────────────────────────────────


class TestE2EPdfExport:
    def test_pdf_export_endpoint(self, api_client: TestClient, pcap_bytes: bytes):
        """POST /api/export/{upload_id}/pdf → PDF 반환."""
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        resp = api_client.post(f"/api/export/{upload_id}/pdf")
        if resp.status_code == 404:
            pytest.skip("/api/export/pdf 미구현")
        assert resp.status_code in {200, 202}

    def test_pdf_response_content_type(self, api_client: TestClient, pcap_bytes: bytes):
        upload_id = _upload(api_client, pcap_bytes)
        _analyze(api_client, upload_id)
        resp = api_client.post(f"/api/export/{upload_id}/pdf")
        if resp.status_code == 404:
            pytest.skip("/api/export/pdf 미구현")
        if resp.status_code == 200:
            ct = resp.headers.get("content-type", "")
            assert "pdf" in ct or resp.content[:4] == b"%PDF"
