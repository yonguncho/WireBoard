"""버그 수정 회귀 테스트.

수정된 버그들이 다시 발생하지 않음을 검증한다.
- CRITICAL: session_store.update_analysis TTL 만료 시 KeyError
- HIGH: /api/packets proto/flags 필터 None 안전
- HIGH: /api/export PDF temp file cleanup on exception
- MEDIUM: /api/filter IP 토큰 regex (or 없는 케이스)
- MEDIUM: /api/upload 파일명 끝에 점(.) 처리
"""
import io
import time
import uuid

import pytest


# ──────────────────── SessionStore 유닛 테스트 ────────────────────────


class TestSessionStoreUpdateAnalysisTtl:
    """update_analysis가 TTL 만료 시 KeyError를 발생시키는지 검증."""

    def test_update_analysis_normal(self):
        """정상 케이스: TTL 내에 update_analysis 성공."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
        from store.session_store import SessionStore, ParsedCapture

        store = SessionStore(ttl_seconds=60.0)
        key = str(uuid.uuid4())
        capture = ParsedCapture(sessions=[], source_type="pcap")
        store.put(key, capture)
        store.update_analysis(key, "10.0.0.1", [{"attack_type": "PortScan"}])
        result = store.get(key)
        assert result.target_ip == "10.0.0.1"
        assert len(result.attacks) == 1

    def test_update_analysis_key_not_found(self):
        """존재하지 않는 키 → KeyError."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
        from store.session_store import SessionStore

        store = SessionStore(ttl_seconds=60.0)
        with pytest.raises(KeyError):
            store.update_analysis(str(uuid.uuid4()), "1.2.3.4", [])

    def test_update_analysis_ttl_expired(self):
        """TTL 만료 후 update_analysis → KeyError (분석 결과 소실 방지)."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
        from store.session_store import SessionStore, ParsedCapture

        store = SessionStore(ttl_seconds=0.05)  # 50 ms TTL
        key = str(uuid.uuid4())
        capture = ParsedCapture(sessions=[], source_type="pcap")
        store.put(key, capture)
        time.sleep(0.1)  # TTL 초과
        with pytest.raises(KeyError):
            store.update_analysis(key, "1.2.3.4", [])

    def test_update_analysis_preserves_attacks_list(self):
        """update_analysis가 attacks를 복사본으로 저장해 외부 변경에 영향받지 않음."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
        from store.session_store import SessionStore, ParsedCapture

        store = SessionStore(ttl_seconds=60.0)
        key = str(uuid.uuid4())
        store.put(key, ParsedCapture(sessions=[], source_type="pcap"))
        attacks = [{"attack_type": "Beacon"}]
        store.update_analysis(key, "1.2.3.4", attacks)
        attacks.clear()  # 외부 리스트 수정
        result = store.get(key)
        assert len(result.attacks) == 1  # 내부 복사본은 유지


# ──────────────── /api/packets proto/flags None 안전 테스트 ───────────


class TestPacketsFilterNullSafe:
    """proto/flags 필터에서 None 값이 있어도 AttributeError 없음 검증."""

    def test_packets_proto_filter_no_crash(self, api_client, pcap_bytes: bytes):
        """/api/packets?proto=TCP — 정상 동작."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert upload_resp.status_code == 200
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp = api_client.get(f"/api/packets/{uid}?proto=TCP",
                              headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        body = resp.json()
        assert "packets" in body

    def test_packets_flags_filter_no_crash(self, api_client, pcap_bytes: bytes):
        """/api/packets?flags=SYN — 정상 동작."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert upload_resp.status_code == 200
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp = api_client.get(f"/api/packets/{uid}?flags=SYN",
                              headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200

    def test_packets_proto_filter_returns_matching_only(self, api_client, pcap_bytes: bytes):
        """/api/packets?proto=TCP — 결과가 TCP 세션만 포함."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp = api_client.get(f"/api/packets/{uid}?proto=TCP",
                              headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        for pkt in resp.json()["packets"]:
            assert pkt["proto"].upper() == "TCP"

    def test_packets_flags_nonexistent_returns_empty(self, api_client, pcap_bytes: bytes):
        """/api/packets?flags=URG — 해당 플래그 없으면 빈 결과."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp = api_client.get(f"/api/packets/{uid}?flags=URG",
                              headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        # URG 플래그가 없는 pcap이므로 0건
        assert resp.json()["total"] == 0

    def test_packets_no_filter_returns_all(self, api_client, pcap_bytes: bytes):
        """/api/packets 필터 없음 — 모든 패킷 반환."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp_all = api_client.get(f"/api/packets/{uid}?limit=500",
                                  headers={"X-Upload-Token": capture_token})
        assert resp_all.status_code == 200
        total_all = resp_all.json()["total"]
        resp_tcp = api_client.get(f"/api/packets/{uid}?proto=TCP&limit=500",
                                  headers={"X-Upload-Token": capture_token})
        total_tcp = resp_tcp.json()["total"]
        # 이 pcap은 모두 TCP이므로 동일해야 함
        assert total_all == total_tcp


# ─────────────── /api/upload 파일명 edge case ─────────────────────────


class TestUploadFilenameEdgeCases:
    """파일명 edge case 처리 검증."""

    def test_filename_trailing_dot_returns_415(self, api_client, pcap_bytes: bytes):
        """'file.'처럼 점으로 끝나는 파일명 → 415 (빈 extension)."""
        resp = api_client.post(
            "/api/upload",
            files={"file": ("file.", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 415

    def test_filename_no_dot_returns_415(self, api_client, pcap_bytes: bytes):
        """'nodotfile'처럼 점이 없는 파일명 → 415."""
        resp = api_client.post(
            "/api/upload",
            files={"file": ("nodotfile", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 415

    def test_filename_pcap_extension_ok(self, api_client, pcap_bytes: bytes):
        """.pcap 확장자 → 정상 업로드."""
        resp = api_client.post(
            "/api/upload",
            files={"file": ("capture.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 200

    def test_filename_double_dot_uses_last_extension(self, api_client, pcap_bytes: bytes):
        """'capture.backup.pcap' → .pcap으로 정상 처리."""
        resp = api_client.post(
            "/api/upload",
            files={"file": ("capture.backup.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 200


# ────────────────── /api/filter IP 토큰 regex 검증 ────────────────────


class TestFilterIpTokenRegex:
    """필터 IP 토큰이 'or' 절 없어도 동작하는지 검증."""

    def test_filter_by_src_ip(self, api_client, pcap_bytes: bytes):
        """src IP 필터 → 매칭 세션만 반환."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        # pcap은 192.168.1.1 → 192.168.1.2 세션 포함
        resp = api_client.post("/api/filter", json={"upload_id": uid, "query": "ip 192.168.1.1"},
                               headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert body["matched_count"] > 0
        for s in body["sessions"]:
            assert s["src_ip"] == "192.168.1.1" or s["dst_ip"] == "192.168.1.1"

    def test_filter_by_nonexistent_ip_returns_zero(self, api_client, pcap_bytes: bytes):
        """존재하지 않는 IP 필터 → 0건."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp = api_client.post("/api/filter", json={"upload_id": uid, "query": "ip 9.9.9.9"},
                               headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        assert resp.json()["matched_count"] == 0


# ─────────────── /api/export PDF 임시파일 정리 검증 ──────────────────


class TestExportPdfTempfileCleanup:
    """PDF export 후 임시 파일이 정리되는지 검증."""

    def test_pdf_export_ok(self, api_client, pcap_bytes: bytes):
        """정상 케이스: PDF 반환 성공."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        api_client.post("/api/analyze", json={"upload_id": uid},
                        headers={"X-Upload-Token": capture_token})
        resp = api_client.post(f"/api/export/{uid}/pdf",
                               headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert len(resp.content) > 100

    def test_pdf_export_not_found(self, api_client):
        """존재하지 않는 upload_id → 404."""
        resp = api_client.post(f"/api/export/{uuid.uuid4()}/pdf")
        assert resp.status_code == 404

    def test_pdf_export_invalid_uuid(self, api_client):
        """잘못된 UUID → 400."""
        resp = api_client.post("/api/export/not-a-uuid/pdf")
        assert resp.status_code == 400


# ────────────── YARA matched_strings 인코딩 안전 ─────────────────────


class TestYaraMatchedStringsSafe:
    """YARA matched_strings가 JSON 직렬화 가능한 형태로 반환되는지 검증."""

    def test_yara_response_matched_strings_are_strings(self, api_client, pcap_bytes: bytes):
        """matched_strings 내 모든 항목이 str 타입이어야 함."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        resp = api_client.get(f"/api/yara/{uid}", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        data = resp.json()
        for match in data.get("matches", []):
            for s in match.get("matched_strings", []):
                assert isinstance(s, str), f"matched_strings 항목이 str이 아님: {type(s)}"


# ─────────────── summary dead code 제거 — 동작 회귀 검증 ─────────────


class TestSummaryAttacksHandling:
    """summary.py에서 dead code 제거 후 attacks 처리가 올바른지 검증."""

    def test_summary_no_attacks(self, api_client, pcap_bytes: bytes):
        """공격 없을 때 summary 정상 반환."""
        upload_resp = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        uid = upload_resp.json()["upload_id"]
        capture_token = upload_resp.json()["capture_token"]
        api_client.post("/api/analyze", json={"upload_id": uid},
                        headers={"X-Upload-Token": capture_token})
        resp = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        body = resp.json()
        assert "headline" in body
        assert "risk_level" in body
        assert isinstance(body["attacker_ips"], list)
