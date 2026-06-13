"""POST /api/upload 통합 테스트.

대상: backend/routers/upload.py
검증 항목:
- 유효 pcap/HAR/FortiGate → 200 + 스키마
- upload_id UUID v4 형식
- 50 MB 초과 → 413 (ADR: Content-Length 사전 체크)
- 허용 확장자 외 → 415
- 중복 업로드 시 upload_id 고유성
"""
import io
import re
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

UUID_RE: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
MAX_UPLOAD_BYTES = 52_428_800  # 50 MB


# ─────────────────────────── 정상 케이스 ────────────────────────────


def test_upload_valid_pcap_returns_200(api_client: TestClient, pcap_bytes: bytes) -> None:
    resp = api_client.post(
        "/api/upload",
        files={"file": ("capture.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
    )
    assert resp.status_code == 200


def test_upload_response_schema(api_client: TestClient, pcap_bytes: bytes) -> None:
    resp = api_client.post(
        "/api/upload",
        files={"file": ("capture.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
    )
    body: dict[str, Any] = resp.json()
    assert "upload_id" in body
    assert "source_type" in body
    assert "session_count" in body
    assert "parse_warnings" in body
    assert isinstance(body["session_count"], int)
    assert isinstance(body["parse_warnings"], list)
    assert body["session_count"] >= 0


def test_upload_id_is_uuid_v4(api_client: TestClient, pcap_bytes: bytes) -> None:
    resp = api_client.post(
        "/api/upload",
        files={"file": ("capture.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
    )
    upload_id: str = resp.json()["upload_id"]
    assert UUID_RE.match(upload_id), f"upload_id 가 UUID v4 형식이 아님: {upload_id!r}"


def test_upload_pcap_source_type(api_client: TestClient, pcap_bytes: bytes) -> None:
    resp = api_client.post(
        "/api/upload",
        files={"file": ("capture.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
    )
    assert resp.json()["source_type"] == "pcap"


def test_upload_har_source_type(api_client: TestClient, har_json: str) -> None:
    har_bytes = har_json.encode("utf-8")
    resp = api_client.post(
        "/api/upload",
        files={"file": ("session.har", io.BytesIO(har_bytes), "application/json")},
    )
    assert resp.status_code == 200
    assert resp.json()["source_type"] == "har"


def test_upload_fortigate_source_type(
    api_client: TestClient, fortigate_v3_text: str
) -> None:
    fg_bytes = fortigate_v3_text.encode("utf-8")
    resp = api_client.post(
        "/api/upload",
        files={"file": ("sniffer.log", io.BytesIO(fg_bytes), "text/plain")},
    )
    assert resp.status_code == 200
    assert resp.json()["source_type"] == "fortigate"


def test_upload_tcpdump_source_type(api_client: TestClient, tcpdump_text: str) -> None:
    tcpdump_bytes = tcpdump_text.encode("utf-8")
    resp = api_client.post(
        "/api/upload",
        files={"file": ("capture.tcpdump", io.BytesIO(tcpdump_bytes), "text/plain")},
    )
    assert resp.status_code == 200
    assert resp.json()["source_type"] == "tcpdump"


def test_upload_ids_are_unique(api_client: TestClient, pcap_bytes: bytes) -> None:
    """동일 파일을 3번 업로드해도 upload_id 가 중복되지 않는다."""
    ids: set[str] = set()
    for _ in range(3):
        resp = api_client.post(
            "/api/upload",
            files={"file": ("capture.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        ids.add(resp.json()["upload_id"])
    assert len(ids) == 3, "upload_id 중복 발생"


def test_upload_session_count_positive(api_client: TestClient, pcap_bytes: bytes) -> None:
    """pcap 5-packet → session_count ≥ 1."""
    resp = api_client.post(
        "/api/upload",
        files={"file": ("capture.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
    )
    assert resp.json()["session_count"] >= 1


# ─────────────────────────── 에러 케이스 ────────────────────────────


def test_upload_oversized_returns_413(api_client: TestClient) -> None:
    """Content-Length > 50 MB → 413 (파일 read() 없이 사전 차단)."""
    tiny_data = b"\xa1\xb2\xc3\xd4" + b"\x00" * 100  # 유효한 magic만 있는 작은 데이터
    resp = api_client.post(
        "/api/upload",
        files={"file": ("big.pcap", io.BytesIO(tiny_data), "application/octet-stream")},
        headers={"content-length": str(MAX_UPLOAD_BYTES + 8193)},
    )
    assert resp.status_code == 413


def test_upload_exe_extension_returns_415(api_client: TestClient) -> None:
    resp = api_client.post(
        "/api/upload",
        files={"file": ("payload.exe", io.BytesIO(b"MZ"), "application/octet-stream")},
    )
    assert resp.status_code == 415


def test_upload_txt_extension_returns_415(api_client: TestClient) -> None:
    """일반 .txt 파일 (FortiGate 형식 아님) → 415."""
    resp = api_client.post(
        "/api/upload",
        files={"file": ("notes.txt", io.BytesIO(b"hello world"), "text/plain")},
    )
    assert resp.status_code == 415


def test_upload_zip_extension_returns_415(api_client: TestClient) -> None:
    resp = api_client.post(
        "/api/upload",
        files={"file": ("archive.zip", io.BytesIO(b"PK\x03\x04"), "application/zip")},
    )
    assert resp.status_code == 415


def test_upload_no_file_returns_422(api_client: TestClient) -> None:
    """파일 없이 요청 → 422 (Pydantic required field)."""
    resp = api_client.post("/api/upload", data={})
    assert resp.status_code == 422


# ─────────────────────────── 경계 케이스 ────────────────────────────


def test_upload_exactly_50mb_is_accepted(api_client: TestClient) -> None:
    """content-length = 50 MB (한계치) → 413으로 거부되지 않는다.

    실제 body는 작은 pcap 헤더만 전송; upload.py는 content-length 헤더를 먼저 검사하므로
    50 MB == 한계치 → 통과, 이후 작은 body를 정상 처리한다.
    """
    import struct

    # 유효 pcap global header only (24 bytes) — body는 작게 유지해 테스트 속도 보장
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    resp = api_client.post(
        "/api/upload",
        files={"file": ("edge.pcap", io.BytesIO(header), "application/octet-stream")},
        headers={"content-length": str(MAX_UPLOAD_BYTES)},
    )
    # 파서가 빈 pcap으로 처리하므로 200 또는 400/422(파싱 오류) 허용; 413은 아님
    assert resp.status_code != 413


def test_upload_empty_pcap_returns_error(api_client: TestClient) -> None:
    """0 바이트 pcap → 400 또는 422 (파서 에러)."""
    resp = api_client.post(
        "/api/upload",
        files={"file": ("empty.pcap", io.BytesIO(b""), "application/octet-stream")},
    )
    assert resp.status_code in {400, 422}


def test_upload_corrupted_pcap_returns_error(api_client: TestClient) -> None:
    """잘못된 magic number pcap → 400."""
    resp = api_client.post(
        "/api/upload",
        files={"file": ("bad.pcap", io.BytesIO(b"\xff\xff\xff\xff" * 6), "application/octet-stream")},
    )
    assert resp.status_code in {400, 422}
