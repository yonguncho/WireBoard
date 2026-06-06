"""GET /api/export/{upload_id}/ioc 통합 테스트.

대상: backend/routers/export.py
검증 항목:
- 공격·도메인 있는 capture → 200 + CSV 헤더 + IP/도메인 행
- 공격 없는 capture → 200 + 헤더만 있는 CSV
- 잘못된 UUID → 400
- 없는 upload_id → 404
"""
import io
import csv
import uuid
from typing import Generator

import pytest
from fastapi.testclient import TestClient


# ─────────────────────────── 헬퍼 ───────────────────────────────────────────


def _parse_csv(content: bytes) -> list[dict]:
    """CSV bytes → dict 목록 (헤더 포함)."""
    reader = csv.DictReader(io.StringIO(content.decode("utf-8")))
    return list(reader)


def _make_upload_and_analyze(client: TestClient, attacks: list, sessions_meta: list) -> str:
    """세션을 업로드 후 store에 공격 데이터를 직접 주입해 upload_id 반환.

    실제 파이프라인을 통하지 않고, session_store에 ParsedCapture를 직접 넣어
    IOC 엔드포인트만 단독 테스트한다.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

    from store.session_store import ParsedCapture, SessionStore
    from models.session import SessionModel

    # 최소 SessionModel 목록 생성
    built_sessions = []
    for i, meta in enumerate(sessions_meta):
        session = SessionModel(
            session_id=str(uuid.uuid4()),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345 + i,
            dst_port=443,
            protocol="TCP",
            start_ts=float(1_748_000_000 + i),
            end_ts=float(1_748_000_010 + i),
            bytes_sent=1000,
            bytes_recv=500,
            packet_count=10,
            payload_length=800,
            meta=meta,
        )
        built_sessions.append(session)

    capture = ParsedCapture(
        sessions=built_sessions,
        source_type="pcap",
        attacks=attacks,
        target_ip="10.0.0.1",
    )

    upload_id = str(uuid.uuid4())
    # TestClient의 app에서 session_store에 직접 put
    client.app.state.session_store.put(upload_id, capture)
    return upload_id


# ─────────────────────────── 테스트 ─────────────────────────────────────────


def test_ioc_export_basic(api_client: TestClient) -> None:
    """공격 있는 세션 → 200, CSV 헤더 + IP 및 도메인 행 포함."""
    attacks = [
        {"attack_type": "PortScan", "severity": "high", "mitre_id": "T1046",
         "description": "포트스캔 탐지", "src_ip": "1.2.3.4"},
        {"attack_type": "Beacon", "severity": "medium", "mitre_id": "T1071",
         "description": "C2 비콘", "src_ip": "5.6.7.8"},
    ]
    sessions_meta = [
        {"sni": "evil.com"},
        {"dns_query": "bad-domain.net"},
        {"host": "another-bad.io"},
        {},  # meta 없는 세션
    ]

    upload_id = _make_upload_and_analyze(api_client, attacks, sessions_meta)
    resp = api_client.get(f"/api/export/{upload_id}/ioc")

    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert f"ioc_" in resp.headers.get("content-disposition", "")

    rows = _parse_csv(resp.content)
    # CSV 헤더 필드 확인
    assert rows[0].keys() >= {"type", "value", "source"}

    types_values = {(r["type"], r["value"]) for r in rows}
    # IP 행 확인
    assert ("ip", "1.2.3.4") in types_values
    assert ("ip", "5.6.7.8") in types_values
    # 도메인 행 확인
    assert ("domain", "evil.com") in types_values
    assert ("domain", "bad-domain.net") in types_values
    assert ("domain", "another-bad.io") in types_values


def test_ioc_export_empty(api_client: TestClient) -> None:
    """공격 없고 도메인 메타도 없는 세션 → 200, 헤더만 있는 CSV."""
    upload_id = _make_upload_and_analyze(api_client, attacks=[], sessions_meta=[{}])
    resp = api_client.get(f"/api/export/{upload_id}/ioc")

    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]

    # 헤더 행만 존재해야 함 (데이터 행 없음)
    rows = _parse_csv(resp.content)
    assert len(rows) == 0  # DictReader는 헤더 제외하므로 0개여야 함

    # 원본 content에 헤더 행은 존재해야 함
    raw = resp.content.decode("utf-8")
    assert "type" in raw
    assert "value" in raw
    assert "source" in raw


def test_ioc_export_invalid_uuid(api_client: TestClient) -> None:
    """잘못된 UUID 형식 → 400."""
    resp = api_client.get("/api/export/not-a-valid-uuid/ioc")
    assert resp.status_code == 400
    body = resp.json()
    assert body["detail"]["code"] == "invalid_uuid"


def test_ioc_export_not_found(api_client: TestClient) -> None:
    """존재하지 않는 upload_id (유효한 UUID) → 404."""
    non_existent = str(uuid.uuid4())
    resp = api_client.get(f"/api/export/{non_existent}/ioc")
    assert resp.status_code == 404
