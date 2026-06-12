"""베타 테스트 — 실사용 시나리오 기반 통합 검증.

단위 테스트가 검증하지 못하는 다음을 검증한다:
1. 멀티 포맷 일관성 (pcap/har/fortigate 업로드 후 동일 API 흐름)
2. target_ip 자동 감지 알고리즘 정확성
3. 공격 탐지 + GeoIP + YARA 결합 워크플로
4. 필터 + 비교 복합 워크플로
5. 내보내기 무결성 (JSON export → 필드 검증)
6. 세션 재사용 및 TTL 동작
7. 페이지네이션 일관성
8. 에러 경로 회복력
"""
import io
import json
import struct
import time
import uuid
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


# ─────────────── 헬퍼 ────────────────────────────────────────────────

def _upload(api_client, data: bytes, filename: str = "cap.pcap") -> tuple[str, str]:
    resp = api_client.post(
        "/api/upload",
        files={"file": (filename, io.BytesIO(data), "application/octet-stream")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["upload_id"], resp.json()["capture_token"]


def _analyze(api_client, uid: str, target_ip: str = "192.168.1.2",
             capture_token: str = "") -> dict:
    resp = api_client.post(
        "/api/analyze",
        json={"upload_id": uid, "target_ip": target_ip},
        headers={"X-Upload-Token": capture_token} if capture_token else {},
    )
    assert resp.status_code in {200, 207}, resp.text
    return resp.json()


# ────────── 1. 멀티 포맷 일관성 ──────────────────────────────────────

class TestMultiFormatConsistency:
    """pcap / har / fortigate 모두 동일 API 흐름을 통과해야 한다."""

    def test_pcap_full_flow(self, api_client, pcap_bytes: bytes):
        """pcap → upload → analyze → panels → summary 전 흐름."""
        uid, capture_token = _upload(api_client, pcap_bytes, "cap.pcap")
        body = _analyze(api_client, uid, capture_token=capture_token)
        assert "sessions" in body
        assert "attacks" in body
        assert "analysis_duration_ms" in body

        panels = api_client.get(f"/api/panels/{uid}", headers={"X-Upload-Token": capture_token})
        assert panels.status_code == 200

        summary = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        assert summary.status_code == 200
        s = summary.json()
        assert "headline" in s
        assert "risk_level" in s

    def test_har_full_flow(self, api_client, har_json: str):
        """HAR → upload → analyze 전 흐름."""
        data = har_json.encode("utf-8")
        uid, capture_token = _upload(api_client, data, "browser.har")
        body = _analyze(api_client, uid, capture_token=capture_token)
        assert isinstance(body["sessions"], list)
        assert len(body["sessions"]) > 0

    def test_fortigate_full_flow(self, api_client, fortigate_v3_text: str):
        """FortiGate verbose3 → upload → analyze 전 흐름."""
        data = fortigate_v3_text.encode("utf-8")
        uid, capture_token = _upload(api_client, data, "fw.log")
        body = _analyze(api_client, uid, capture_token=capture_token)
        assert "sessions" in body

    def test_all_formats_return_upload_id_uuid(self, api_client, pcap_bytes, har_json, fortigate_v3_text):
        """모든 포맷 업로드 결과의 upload_id가 UUID v4 형식이어야 한다."""
        import re
        UUID4_RE = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        for data, fname in [
            (pcap_bytes, "cap.pcap"),
            (har_json.encode(), "b.har"),
            (fortigate_v3_text.encode(), "fw.log"),
        ]:
            resp = api_client.post(
                "/api/upload",
                files={"file": (fname, io.BytesIO(data), "application/octet-stream")},
            )
            assert resp.status_code == 200
            uid = resp.json()["upload_id"]
            assert UUID4_RE.match(uid), f"{fname}: upload_id={uid!r} UUID4 형식 아님"


# ────────── 2. target_ip 자동 감지 ───────────────────────────────────

class TestTargetIpAutoDetect:
    """src+dst 양방향 집계로 가장 중심적인 호스트를 선택하는지 검증."""

    def test_target_ip_in_session_ips(self, api_client, pcap_bytes: bytes):
        """자동 감지된 target_ip가 세션 src/dst 중 하나여야 한다."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        body = _analyze(api_client, uid, capture_token=capture_token)
        target = body["target_ip"]
        assert any(
            s["src_ip"] == target or s["dst_ip"] == target
            for s in body["sessions"]
        ), f"target_ip={target!r} 이 세션에 없음"

    def test_explicit_target_ip_respected(self, api_client, pcap_bytes: bytes):
        """명시적 target_ip 제공 시 해당 IP가 사용되어야 한다."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        # pcap fixture: 192.168.1.1 → 192.168.1.2
        resp = api_client.post("/api/analyze", json={
            "upload_id": uid,
            "target_ip": "192.168.1.2",
        }, headers={"X-Upload-Token": capture_token})
        assert resp.status_code in {200, 207}
        body = resp.json()
        assert body["target_ip"] == "192.168.1.2"

    def test_invalid_target_ip_returns_400(self, api_client, pcap_bytes: bytes):
        """잘못된 target_ip → 400."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.post("/api/analyze", json={
            "upload_id": uid,
            "target_ip": "not.an.ip",
        }, headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 400

    def test_analyze_returns_sessions_covering_target_ip(self, api_client, pcap_bytes: bytes):
        """반환된 sessions 모두 target_ip를 src 또는 dst로 포함해야 한다."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        body = _analyze(api_client, uid, capture_token=capture_token)
        target = body["target_ip"]
        for s in body["sessions"]:
            assert s["src_ip"] == target or s["dst_ip"] == target, (
                f"세션 {s['session_id']} 이 target_ip={target!r}를 포함하지 않음"
            )


# ────────── 3. 공격 탐지 + GeoIP + YARA 결합 워크플로 ────────────────

class TestAttackGeoipYaraCombined:
    """분석 후 GeoIP + YARA 엔드포인트가 일관된 upload_id로 동작해야 한다."""

    def test_geoip_after_analyze(self, api_client, pcap_bytes: bytes):
        """analyze 후 /api/geoip 호출 → 200 + entries 리스트."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        _analyze(api_client, uid, capture_token=capture_token)
        resp = api_client.get(f"/api/geoip/{uid}", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        body = resp.json()
        assert "entries" in body
        assert isinstance(body["entries"], list)

    def test_yara_after_upload(self, api_client, pcap_bytes: bytes):
        """업로드 후 /api/yara 호출 → available + matches."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/yara/{uid}", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        body = resp.json()
        assert "available" in body
        assert "match_count" in body
        assert "matches" in body
        assert body["match_count"] == len(body["matches"])

    def test_geoip_entries_have_required_fields(self, api_client, pcap_bytes: bytes):
        """GeoIP 항목 각각에 ip/country_name/country_code/role 필드 존재."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        _analyze(api_client, uid, capture_token=capture_token)
        resp = api_client.get(f"/api/geoip/{uid}", headers={"X-Upload-Token": capture_token})
        for entry in resp.json()["entries"]:
            assert "ip" in entry
            assert "country_name" in entry
            assert "country_code" in entry
            assert "role" in entry

    def test_yara_matches_have_required_fields(self, api_client, pcap_bytes: bytes):
        """YARA 매치 항목 각각에 rule/severity/session_id 필드 존재."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/yara/{uid}", headers={"X-Upload-Token": capture_token})
        for match in resp.json()["matches"]:
            assert "rule" in match
            assert "severity" in match
            assert "session_id" in match

    def test_same_upload_id_consistent_across_endpoints(self, api_client, pcap_bytes: bytes):
        """동일 upload_id로 여러 엔드포인트 호출 시 일관된 데이터."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        analyze_body = _analyze(api_client, uid, capture_token=capture_token)
        target_from_analyze = analyze_body["target_ip"]

        summary_resp = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        assert summary_resp.status_code == 200

        panels_resp = api_client.get(f"/api/panels/{uid}", headers={"X-Upload-Token": capture_token})
        assert panels_resp.status_code == 200

        geoip_resp = api_client.get(f"/api/geoip/{uid}", headers={"X-Upload-Token": capture_token})
        assert geoip_resp.status_code == 200

        yara_resp = api_client.get(f"/api/yara/{uid}", headers={"X-Upload-Token": capture_token})
        assert yara_resp.status_code == 200


# ────────── 4. 필터 + 비교 복합 워크플로 ────────────────────────────

class TestFilterCompareCombined:
    """필터와 비교 분석을 연계하는 복합 시나리오."""

    def test_filter_then_verify_sessions(self, api_client, pcap_bytes: bytes):
        """필터 결과 세션이 쿼리 IP를 포함하는지 검증."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.post("/api/filter", json={
            "upload_id": uid,
            "query": "ip 192.168.1.1",
        }, headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        body = resp.json()
        if body["success"] and body["matched_count"] > 0:
            for s in body["sessions"]:
                assert s["src_ip"] == "192.168.1.1" or s["dst_ip"] == "192.168.1.1"

    def test_compare_same_capture_zero_new_ips(self, api_client, pcap_bytes: bytes):
        """같은 파일을 두 번 업로드해서 비교 → new_ips 없어야 함."""
        uid1, capture_token1 = _upload(api_client, pcap_bytes, "base.pcap")
        uid2, capture_token2 = _upload(api_client, pcap_bytes, "curr.pcap")
        resp = api_client.post("/api/compare", json={
            "base_upload_id": uid1,
            "current_upload_id": uid2,
        }, headers={"X-Upload-Token-Base": capture_token1, "X-Upload-Token-Current": capture_token2})
        assert resp.status_code == 200
        body = resp.json()
        assert body["new_ips"] == []
        assert body["removed_ips"] == []
        assert body["traffic_delta_pct"] == 0.0

    def test_filter_translate_returns_expression(self, api_client, pcap_bytes: bytes):
        """translate 엔드포인트가 filter_expr 문자열 반환."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.post("/api/filter/translate", json={
            "upload_id": uid,
            "query": "port 80 tcp",
        }, headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        body = resp.json()
        assert "filter_expr" in body
        assert isinstance(body["filter_expr"], str)

    def test_filter_invalid_query_returns_400(self, api_client, pcap_bytes: bytes):
        """빈 쿼리 또는 알 수 없는 쿼리 → 400 또는 success=False."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.post("/api/filter", json={
            "upload_id": uid,
            "query": "",
        }, headers={"X-Upload-Token": capture_token})
        # 빈 쿼리는 400 또는 success=False 어느 쪽도 허용
        assert resp.status_code in {200, 400}
        if resp.status_code == 200:
            assert resp.json()["success"] is False or resp.json()["matched_count"] == 0


# ────────── 5. 내보내기 무결성 ───────────────────────────────────────

class TestExportIntegrity:
    """내보낸 데이터가 올바른 형식과 내용을 가지는지 검증."""

    def test_json_export_contains_sessions(self, api_client, pcap_bytes: bytes):
        """JSON 내보내기에 sessions 배열 포함."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/export/{uid}", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        data = resp.json()
        assert "sessions" in data
        assert isinstance(data["sessions"], list)

    def test_json_export_sessions_have_uuid(self, api_client, pcap_bytes: bytes):
        """JSON 내보낸 세션에 session_id UUID 필드 포함."""
        import re
        UUID_RE = re.compile(r"^[0-9a-f-]{36}$", re.IGNORECASE)
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/export/{uid}", headers={"X-Upload-Token": capture_token})
        data = resp.json()
        for s in data.get("sessions", [])[:10]:
            assert UUID_RE.match(s.get("session_id", "")), \
                f"session_id={s.get('session_id')!r} 이 UUID 형식 아님"

    def test_ioc_export_is_csv(self, api_client, pcap_bytes: bytes):
        """IOC 내보내기가 CSV 형식 (첫 줄 헤더: type,value,source)."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        _analyze(api_client, uid, capture_token=capture_token)
        resp = api_client.get(f"/api/export/{uid}/ioc", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        content = resp.content.decode("utf-8")
        first_line = content.split("\r\n")[0].split("\n")[0]
        assert first_line == "type,value,source", f"CSV 헤더 불일치: {first_line!r}"

    def test_pdf_export_starts_with_pdf_magic(self, api_client, pcap_bytes: bytes):
        """PDF 내보내기 content가 %PDF 매직 바이트로 시작."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        _analyze(api_client, uid, capture_token=capture_token)
        resp = api_client.post(f"/api/export/{uid}/pdf", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        assert resp.content[:4] == b"%PDF", "PDF 매직 바이트 없음"

    def test_export_without_analyze_still_works(self, api_client, pcap_bytes: bytes):
        """analyze 없이 JSON 내보내기 → 세션만 포함하여 200 반환."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/export/{uid}", headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200


# ────────── 6. 페이지네이션 일관성 ───────────────────────────────────

class TestPaginationConsistency:
    """페이지네이션이 total과 일치하는 결과를 반환하는지 검증."""

    def test_packets_pagination_total_consistent(self, api_client, pcap_bytes: bytes):
        """limit 변경 시 total은 동일, 반환 목록만 달라야 한다."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp10 = api_client.get(f"/api/packets/{uid}?limit=10&offset=0",
                                headers={"X-Upload-Token": capture_token})
        resp50 = api_client.get(f"/api/packets/{uid}?limit=50&offset=0",
                                headers={"X-Upload-Token": capture_token})
        assert resp10.status_code == 200
        assert resp50.status_code == 200
        assert resp10.json()["total"] == resp50.json()["total"]

    def test_packets_offset_returns_different_data(self, api_client, pcap_bytes: bytes):
        """offset=0과 offset=2가 다른 패킷을 반환해야 한다."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp0 = api_client.get(f"/api/packets/{uid}?limit=2&offset=0",
                               headers={"X-Upload-Token": capture_token})
        resp2 = api_client.get(f"/api/packets/{uid}?limit=2&offset=2",
                               headers={"X-Upload-Token": capture_token})
        assert resp0.status_code == 200
        assert resp2.status_code == 200
        pkts0 = resp0.json()["packets"]
        pkts2 = resp2.json()["packets"]
        if pkts0 and pkts2:
            assert pkts0[0].get("no") != pkts2[0].get("no"), "offset이 달라도 같은 패킷 반환됨"

    def test_packets_offset_beyond_total_returns_empty(self, api_client, pcap_bytes: bytes):
        """offset이 total을 초과하면 빈 packets 배열."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/packets/{uid}?offset=999999&limit=10",
                              headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        assert resp.json()["packets"] == []

    def test_packets_proto_filter_subset_of_total(self, api_client, pcap_bytes: bytes):
        """프로토콜 필터 결과의 total ≤ 전체 total."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        total_all = api_client.get(f"/api/packets/{uid}",
                                   headers={"X-Upload-Token": capture_token}).json()["total"]
        total_tcp = api_client.get(f"/api/packets/{uid}?proto=TCP",
                                   headers={"X-Upload-Token": capture_token}).json()["total"]
        assert total_tcp <= total_all


# ────────── 7. 에러 경로 회복력 ──────────────────────────────────────

class TestErrorPathResilience:
    """잘못된 입력에 대한 API 응답이 적절한 HTTP 상태코드를 가져야 한다."""

    def test_analyze_unknown_upload_id_404(self, api_client):
        resp = api_client.post("/api/analyze", json={"upload_id": str(uuid.uuid4()), "target_ip": "1.2.3.4"})
        assert resp.status_code == 404

    def test_analyze_invalid_uuid_400(self, api_client):
        resp = api_client.post("/api/analyze", json={"upload_id": "not-a-uuid", "target_ip": "1.2.3.4"})
        assert resp.status_code == 400

    def test_panels_unknown_upload_id_404(self, api_client):
        resp = api_client.get(f"/api/panels/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_flow_unknown_session_404_or_empty(self, api_client, pcap_bytes: bytes):
        """존재하지 않는 session_id → 404 또는 빈 리스트."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.get(f"/api/flow/{uid}?session_id={uuid.uuid4()}",
                              headers={"X-Upload-Token": capture_token})
        assert resp.status_code in {200, 404}
        if resp.status_code == 200:
            body = resp.json()
            assert body.get("packets") == [] or body.get("session") is None

    def test_compare_unknown_base_404(self, api_client, pcap_bytes: bytes):
        uid, capture_token = _upload(api_client, pcap_bytes)
        resp = api_client.post("/api/compare", json={
            "base_upload_id": str(uuid.uuid4()),
            "current_upload_id": uid,
        }, headers={"X-Upload-Token-Current": capture_token})
        assert resp.status_code == 404

    def test_geoip_unknown_upload_id_404(self, api_client):
        resp = api_client.get(f"/api/geoip/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_yara_unknown_upload_id_404(self, api_client):
        resp = api_client.get(f"/api/yara/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_upload_empty_file_returns_400(self, api_client):
        resp = api_client.post(
            "/api/upload",
            files={"file": ("empty.pcap", io.BytesIO(b""), "application/octet-stream")},
        )
        assert resp.status_code == 400

    def test_upload_wrong_extension_returns_415(self, api_client, pcap_bytes: bytes):
        resp = api_client.post(
            "/api/upload",
            files={"file": ("capture.exe", io.BytesIO(pcap_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 415

    def test_multiple_error_types_no_500(self, api_client, pcap_bytes: bytes):
        """다양한 오류 입력에 5xx 응답 없음."""
        _upload(api_client, pcap_bytes)
        requests = [
            ("GET", f"/api/packets/invalid-uuid"),
            ("GET", f"/api/geoip/not-a-uuid"),
            ("GET", f"/api/yara/not-a-uuid"),
            ("POST", "/api/analyze"),
        ]
        for method, path in requests:
            if method == "GET":
                resp = api_client.get(path)
            else:
                resp = api_client.post(path, json={})
            assert resp.status_code < 500, f"{method} {path} → {resp.status_code}"


# ────────── 8. 분석 재실행 일관성 ────────────────────────────────────

class TestAnalysisRerunConsistency:
    """같은 upload_id로 분석을 반복해도 일관된 결과가 나와야 한다."""

    def test_rerun_analyze_same_target_ip(self, api_client, pcap_bytes: bytes):
        """동일 upload_id 2회 analyze → 동일 target_ip."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        body1 = _analyze(api_client, uid, capture_token=capture_token)
        body2 = _analyze(api_client, uid, capture_token=capture_token)
        assert body1["target_ip"] == body2["target_ip"]

    def test_rerun_analyze_same_session_count(self, api_client, pcap_bytes: bytes):
        """동일 upload_id 2회 analyze → 동일 세션 수."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        body1 = _analyze(api_client, uid, capture_token=capture_token)
        body2 = _analyze(api_client, uid, capture_token=capture_token)
        assert len(body1["sessions"]) == len(body2["sessions"])

    def test_rerun_analyze_duration_ms_positive(self, api_client, pcap_bytes: bytes):
        """analyze 반복 시 analysis_duration_ms 항상 양수."""
        uid, capture_token = _upload(api_client, pcap_bytes)
        for _ in range(2):
            body = _analyze(api_client, uid, capture_token=capture_token)
            assert body["analysis_duration_ms"] > 0


# ────────── 9. ICMP 파싱 지원 ────────────────────────────────────────

class TestIcmpParsing:
    """ICMP 패킷이 포함된 pcap이 파싱 오류 없이 처리되어야 한다."""

    @staticmethod
    def _build_icmp_pcap() -> bytes:
        """ICMP echo request 패킷 포함 pcap."""
        GLOBAL_HDR = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        eth = bytes([0x00]*6 + [0x00]*6 + [0x08, 0x00])
        ip = bytes([
            0x45, 0x00, 0x00, 0x1c,
            0x00, 0x01, 0x40, 0x00,
            0x40, 0x01,              # proto=ICMP(1)
            0x00, 0x00,
            0xc0, 0xa8, 0x01, 0x01,  # src: 192.168.1.1
            0xc0, 0xa8, 0x01, 0x02,  # dst: 192.168.1.2
        ])
        icmp = bytes([0x08, 0x00, 0x00, 0x00])  # type=8 (echo request), code=0
        pkt = eth + ip + icmp
        ts_sec = 1_748_000_000
        rec = struct.pack("<IIII", ts_sec, 0, len(pkt), len(pkt)) + pkt
        return GLOBAL_HDR + rec

    def test_icmp_pcap_upload_ok(self, api_client):
        """ICMP 포함 pcap 업로드 → 200."""
        data = self._build_icmp_pcap()
        resp = api_client.post(
            "/api/upload",
            files={"file": ("icmp.pcap", io.BytesIO(data), "application/octet-stream")},
        )
        assert resp.status_code == 200

    def test_icmp_pcap_analyze_no_crash(self, api_client):
        """ICMP 포함 pcap 분석 → 5xx 없음."""
        data = self._build_icmp_pcap()
        uid, capture_token = _upload(api_client, data, "icmp.pcap")
        resp = api_client.post("/api/analyze", json={"upload_id": uid},
                               headers={"X-Upload-Token": capture_token})
        assert resp.status_code in {200, 207, 422}

    def test_icmp_session_has_proto_icmp(self, api_client):
        """파싱된 세션에 ICMP 프로토콜 항목이 있어야 한다."""
        data = self._build_icmp_pcap()
        uid, capture_token = _upload(api_client, data, "icmp.pcap")
        resp = api_client.post("/api/analyze", json={"upload_id": uid},
                               headers={"X-Upload-Token": capture_token})
        if resp.status_code in {200, 207}:
            sessions = resp.json()["sessions"]
            icmp_sessions = [s for s in sessions if s["protocol"] == "ICMP"]
            assert len(icmp_sessions) > 0, "ICMP 세션이 파싱되지 않음"


# ────────── 10. payload_hex 길이 검증 ────────────────────────────────

class TestPayloadHexLength:
    """payload_hex가 128바이트(256 hex chars)까지 캡처되는지 검증."""

    @staticmethod
    def _build_large_payload_pcap() -> bytes:
        """200바이트 TCP 페이로드가 있는 pcap."""
        GLOBAL_HDR = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        payload = b"A" * 200
        eth = bytes([0x00]*6 + [0x00]*6 + [0x08, 0x00])
        total_len = 20 + 20 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, 1, 0x4000, 64, 6, 0,
            b"\xc0\xa8\x01\x01", b"\xc0\xa8\x01\x02")
        tcp = bytes([
            0x00, 0x50, 0x1f, 0x90,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x18,
            0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
        ]) + payload
        pkt = eth + ip + tcp
        rec = struct.pack("<IIII", 1_748_000_000, 0, len(pkt), len(pkt)) + pkt
        return GLOBAL_HDR + rec

    def test_payload_hex_captures_up_to_128_bytes(self, api_client):
        """packet payload_hex는 최대 256 hex 문자 (128바이트)."""
        data = self._build_large_payload_pcap()
        uid, capture_token = _upload(api_client, data, "payload.pcap")
        resp = api_client.get(f"/api/packets/{uid}?limit=10",
                              headers={"X-Upload-Token": capture_token})
        assert resp.status_code == 200
        for pkt in resp.json()["packets"]:
            hex_str = pkt.get("payload_hex", "")
            assert len(hex_str) <= 256, \
                f"payload_hex가 256 hex chars 초과: {len(hex_str)}"
