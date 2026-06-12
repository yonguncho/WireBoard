"""POST /api/annotations + GET /api/annotations/{upload_id} 전용 단위 테스트."""
import io
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


def _make_app():
    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


def _upload(client, pcap_bytes: bytes) -> tuple[str, str]:
    r = client.post("/api/upload", files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")})
    assert r.status_code == 200
    return r.json()["upload_id"], r.json()["capture_token"]


def _annotation_payload(upload_id: str, comment: str = "Test note") -> dict:
    return {
        "upload_id": upload_id,
        "start_ts": 1_748_000_005.0,
        "end_ts": 1_748_000_065.0,
        "comment": comment,
    }


class TestAnnotationsPost:
    def test_create_returns_201(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        r = client.post("/api/annotations", json=_annotation_payload(uid),
                        headers={"X-Upload-Token": capture_token})
        assert r.status_code == 201

    def test_create_returns_status_created(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        body = client.post("/api/annotations", json=_annotation_payload(uid),
                           headers={"X-Upload-Token": capture_token}).json()
        assert body["status"] == "created"

    def test_create_annotation_body_in_response(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        body = client.post("/api/annotations", json=_annotation_payload(uid, "My comment"),
                           headers={"X-Upload-Token": capture_token}).json()
        ann = body["annotation"]
        assert ann["upload_id"] == uid
        assert ann["comment"] == "My comment"
        assert ann["start_ts"] == 1_748_000_005.0
        assert ann["end_ts"] == 1_748_000_065.0

    def test_invalid_uuid_returns_400(self):
        client = _make_app()
        r = client.post("/api/annotations", json={
            "upload_id": "not-a-uuid",
            "start_ts": 0.0,
            "end_ts": 1.0,
            "comment": "x",
        })
        assert r.status_code == 400

    def test_unknown_upload_id_returns_404(self):
        client = _make_app()
        r = client.post("/api/annotations", json={
            "upload_id": str(uuid.uuid4()),
            "start_ts": 0.0,
            "end_ts": 1.0,
            "comment": "x",
        })
        assert r.status_code == 404


class TestAnnotationsGet:
    def test_get_returns_list(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        r = client.get(f"/api/annotations/{uid}", headers={"X-Upload-Token": capture_token})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_empty_before_post(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        r = client.get(f"/api/annotations/{uid}", headers={"X-Upload-Token": capture_token})
        assert r.json() == []

    def test_get_after_post_returns_annotation(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        client.post("/api/annotations", json=_annotation_payload(uid, "First"),
                    headers={"X-Upload-Token": capture_token})
        r = client.get(f"/api/annotations/{uid}", headers={"X-Upload-Token": capture_token})
        assert r.status_code == 200
        items = r.json()
        assert len(items) == 1
        assert items[0]["comment"] == "First"

    def test_multiple_annotations_all_returned(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        client.post("/api/annotations", json=_annotation_payload(uid, "A"),
                    headers={"X-Upload-Token": capture_token})
        client.post("/api/annotations", json=_annotation_payload(uid, "B"),
                    headers={"X-Upload-Token": capture_token})
        client.post("/api/annotations", json=_annotation_payload(uid, "C"),
                    headers={"X-Upload-Token": capture_token})
        items = client.get(f"/api/annotations/{uid}",
                           headers={"X-Upload-Token": capture_token}).json()
        comments = [x["comment"] for x in items]
        assert set(comments) == {"A", "B", "C"}

    def test_annotation_fields_preserved(self, pcap_bytes):
        client = _make_app()
        uid, capture_token = _upload(client, pcap_bytes)
        client.post("/api/annotations", json=_annotation_payload(uid, "detail"),
                    headers={"X-Upload-Token": capture_token})
        item = client.get(f"/api/annotations/{uid}",
                          headers={"X-Upload-Token": capture_token}).json()[0]
        assert item["start_ts"] == 1_748_000_005.0
        assert item["end_ts"] == 1_748_000_065.0
        assert item["upload_id"] == uid

    def test_get_invalid_uuid_returns_400(self):
        client = _make_app()
        r = client.get("/api/annotations/not-a-uuid")
        assert r.status_code == 400

    def test_get_unknown_upload_id_returns_404(self):
        client = _make_app()
        r = client.get(f"/api/annotations/{uuid.uuid4()}")
        assert r.status_code == 404

    def test_annotations_isolated_per_upload(self, pcap_bytes):
        client = _make_app()
        uid_a, capture_token_a = _upload(client, pcap_bytes)
        uid_b, capture_token_b = _upload(client, pcap_bytes)
        client.post("/api/annotations", json=_annotation_payload(uid_a, "Only A"),
                    headers={"X-Upload-Token": capture_token_a})
        items_b = client.get(f"/api/annotations/{uid_b}",
                             headers={"X-Upload-Token": capture_token_b}).json()
        assert items_b == []
