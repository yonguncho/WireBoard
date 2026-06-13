"""GET /api/summary — 자연어 요약 엔드포인트 + summary_builder 유닛 테스트."""
import io
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


# ── Unit: summary_builder ──────────────────────────────────────────────────

class TestBuildSummaryClean:
    def test_no_attacks_returns_clean(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([], [])
        assert r.risk_level == "CLEAN"
        assert "이상 이벤트 없음" in r.headline
        assert r.attacker_ips == []
        assert r.victim_ips == []
        assert r.attack_timeline == []
        assert r.attack_explanations == {}
        assert len(r.recommendations) >= 1

    def test_clean_narrative_is_non_empty(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([], [])
        assert len(r.narrative) > 10


class TestBuildSummaryRiskLevel:
    def _a(self, sev, mitre="", src=None):
        return {"attack_type": "Test", "severity": sev,
                "mitre_id": mitre, "description": "", "src_ip": src}

    def test_high_severity_returns_HIGH(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._a("high")], [])
        assert r.risk_level == "HIGH"

    def test_medium_severity_returns_MEDIUM(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._a("medium")], [])
        assert r.risk_level == "MEDIUM"

    def test_low_severity_returns_LOW(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._a("low")], [])
        assert r.risk_level == "LOW"

    def test_mixed_severity_takes_max(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._a("low"), self._a("high"), self._a("medium")], [])
        assert r.risk_level == "HIGH"

    def test_severity_case_insensitive(self):
        """severity 대소문자 무관하게 처리 (B1 fix 검증)."""
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._a("HIGH")], [])
        assert r.risk_level == "HIGH"


class TestAttackerIpExtraction:
    """B1 fix: AttackResult.src_ip 필드를 통한 공격자 IP 추출 검증."""

    def test_src_ip_extracted_from_attack(self):
        from services.narrative.summary_builder import build_summary
        attacks = [{
            "attack_type": "PortScan", "severity": "high",
            "mitre_id": "T1046", "description": "...", "src_ip": "10.1.2.3",
        }]
        r = build_summary(attacks, [])
        assert "10.1.2.3" in r.attacker_ips

    def test_multiple_attacks_same_ip_deduplicated(self):
        from services.narrative.summary_builder import build_summary
        attacks = [
            {"attack_type": "PortScan", "severity": "high",
             "mitre_id": "T1046", "description": "", "src_ip": "10.1.2.3"},
            {"attack_type": "Beacon", "severity": "medium",
             "mitre_id": "T1071", "description": "", "src_ip": "10.1.2.3"},
        ]
        r = build_summary(attacks, [])
        assert r.attacker_ips.count("10.1.2.3") == 1

    def test_none_src_ip_ignored(self):
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "DDoS", "severity": "high",
                    "mitre_id": "T1498", "description": "", "src_ip": None}]
        r = build_summary(attacks, [])
        assert r.attacker_ips == []

    def test_empty_src_ip_ignored(self):
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "CommFailure", "severity": "medium",
                    "mitre_id": "T1499", "description": "", "src_ip": ""}]
        r = build_summary(attacks, [])
        assert r.attacker_ips == []

    def test_victim_ip_inferred_from_sessions(self):
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "PortScan", "severity": "high",
                    "mitre_id": "T1046", "description": "", "src_ip": "10.0.0.1"}]
        sessions = [
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.5",
             "bytes_sent": 100, "bytes_recv": 0,
             "start_ts": 1_748_000_000.0, "end_ts": 1_748_000_010.0},
        ]
        r = build_summary(attacks, sessions)
        assert "192.168.1.5" in r.victim_ips

    def test_victim_ips_capped_at_5(self):
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "PortScan", "severity": "high",
                    "mitre_id": "T1046", "description": "", "src_ip": "10.0.0.1"}]
        sessions = [
            {"src_ip": "10.0.0.1", "dst_ip": f"192.168.1.{i}",
             "bytes_sent": 10, "bytes_recv": 0,
             "start_ts": float(1_748_000_000 + i), "end_ts": float(1_748_000_001 + i)}
            for i in range(10)
        ]
        r = build_summary(attacks, sessions)
        assert len(r.victim_ips) <= 5


class TestMitreRecommendations:
    """B2/B3 fix: MITRE ID → 방어 권고 매핑 검증."""

    def _attack(self, mitre, src=None):
        return {"attack_type": "X", "severity": "high",
                "mitre_id": mitre, "description": "", "src_ip": src}

    def test_T1046_has_recommendations(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._attack("T1046")], [])
        assert len(r.recommendations) > 0
        assert any("포트스캔" in rec or "방화벽" in rec for rec in r.recommendations)

    def test_T1071_has_recommendations(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._attack("T1071")], [])
        assert len(r.recommendations) > 0
        assert any("C2" in rec or "도메인" in rec for rec in r.recommendations)

    def test_T1498_ddos_has_recommendations(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._attack("T1498")], [])
        assert len(r.recommendations) > 0

    def test_T1041_exfiltration_has_recommendations(self):
        """B2 fix: ExfiltrationDetector는 T1041을 사용. 방어 권고 맵에 있어야 함."""
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._attack("T1041")], [])
        assert len(r.recommendations) > 0
        assert any("아웃바운드" in rec or "유출" in rec or "격리" in rec for rec in r.recommendations)

    def test_T1110_bruteforce_has_recommendations(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._attack("T1110")], [])
        assert len(r.recommendations) > 0
        assert any("브루트포스" in rec or "잠금" in rec or "MFA" in rec for rec in r.recommendations)

    def test_T1499_commfailure_has_recommendations(self):
        """B3 fix: CommFailureDetector는 T1499를 사용. 방어 권고 맵에 있어야 함."""
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._attack("T1499")], [])
        assert len(r.recommendations) > 0

    def test_unknown_mitre_fallback_recommendation(self):
        from services.narrative.summary_builder import build_summary
        r = build_summary([self._attack("T9999")], [])
        assert len(r.recommendations) > 0  # 폴백 권고

    def test_recommendations_deduplicated(self):
        """같은 MITRE ID의 공격이 두 번 탐지돼도 권고는 중복되지 않아야 함."""
        from services.narrative.summary_builder import build_summary
        attacks = [
            {"attack_type": "PortScan", "severity": "high",
             "mitre_id": "T1046", "description": "", "src_ip": "1.2.3.4"},
            {"attack_type": "PortScan", "severity": "medium",
             "mitre_id": "T1046", "description": "", "src_ip": "1.2.3.5"},
        ]
        r = build_summary(attacks, [])
        assert len(r.recommendations) == len(set(r.recommendations))


class TestTimeline:
    def test_timeline_length_matches_attacks(self):
        from services.narrative.summary_builder import build_summary
        attacks = [
            {"attack_type": "PortScan", "severity": "high",
             "mitre_id": "T1046", "description": "", "src_ip": "1.2.3.4"},
            {"attack_type": "Beacon", "severity": "medium",
             "mitre_id": "T1071", "description": "", "src_ip": "1.2.3.4"},
        ]
        r = build_summary(attacks, [])
        assert len(r.attack_timeline) == 2

    def test_timeline_ts_zero_when_no_sessions(self):
        """세션 없으면 ts=0.0 — 프론트에서 '—' 표시 (B5 fix 검증)."""
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "PortScan", "severity": "high",
                    "mitre_id": "T1046", "description": "", "src_ip": "1.2.3.4"}]
        r = build_summary(attacks, [])
        assert r.attack_timeline[0]["ts"] == 0.0

    def test_timeline_ts_non_zero_when_sessions_present(self):
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "PortScan", "severity": "high",
                    "mitre_id": "T1046", "description": "", "src_ip": "1.2.3.4"}]
        sessions = [{"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1",
                     "bytes_sent": 100, "bytes_recv": 0,
                     "start_ts": 1_748_000_000.0, "end_ts": 1_748_000_600.0}]
        r = build_summary(attacks, sessions)
        assert r.attack_timeline[0]["ts"] >= 1_748_000_000.0

    def test_timeline_contains_src_ip(self):
        """timeline 항목에 src_ip 포함 여부 확인."""
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "PortScan", "severity": "high",
                    "mitre_id": "T1046", "description": "", "src_ip": "192.168.1.10"}]
        r = build_summary(attacks, [])
        assert r.attack_timeline[0]["src_ip"] == "192.168.1.10"


class TestNarrativeFormatting:
    def test_narrative_contains_newlines_when_detail_present(self):
        """불릿 포인트가 별도 줄에 있어야 함 (B4 fix 검증)."""
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "PortScan", "severity": "high",
                    "mitre_id": "T1046", "description": "100개 포트 스캔", "src_ip": "1.2.3.4"}]
        r = build_summary(attacks, [])
        assert "\n" in r.narrative
        assert "• 포트스캔" in r.narrative

    def test_narrative_no_bullets_when_no_description(self):
        from services.narrative.summary_builder import build_summary
        attacks = [{"attack_type": "PortScan", "severity": "high",
                    "mitre_id": "T1046", "description": "", "src_ip": "1.2.3.4"}]
        r = build_summary(attacks, [])
        assert "•" not in r.narrative


class TestAttackDetectorSrcIp:
    """B1 fix: 각 공격 탐지기가 src_ip 필드를 올바르게 반환하는지 확인."""

    def _session(self, src, dst, dport, **kwargs):
        from models.session import SessionModel
        return SessionModel(
            session_id=str(uuid.uuid4()),
            src_ip=src, dst_ip=dst,
            src_port=12345, dst_port=dport,
            protocol="TCP",
            start_ts=1_748_000_000.0,
            end_ts=1_748_000_010.0,
            bytes_sent=kwargs.get("bs", 100),
            bytes_recv=kwargs.get("br", 0),
            packet_count=kwargs.get("pc", 1),
            payload_length=0,
            rst=kwargs.get("rst", False),
        )

    def test_portscan_result_has_src_ip(self):
        from services.attack_detector.portscan_detector import PortScanDetector
        sessions = [self._session("10.0.0.1", "192.168.1.16", p) for p in range(1, 101)]
        res = PortScanDetector().detect(sessions)
        assert res is not None
        assert res.src_ip == "10.0.0.1"

    def test_beacon_result_has_src_ip(self):
        from services.attack_detector.beacon_detector import BeaconDetector
        from models.session import SessionModel
        sessions = []
        ts = 1_748_000_000.0
        for i in range(8):
            s = SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip="10.2.3.4", dst_ip="203.0.113.1",
                src_port=50000 + i, dst_port=443,
                protocol="TCP",
                start_ts=ts, end_ts=ts + 0.1,
                bytes_sent=200, bytes_recv=100,
                packet_count=3, payload_length=200,
            )
            sessions.append(s)
            ts += 60.0  # 60초 간격 → CV≈0%
        res = BeaconDetector().detect(sessions)
        assert res is not None
        assert res.src_ip == "10.2.3.4"

    def test_bruteforce_result_has_src_ip(self):
        from services.attack_detector.bruteforce_detector import BruteForceDetector
        sessions = [
            self._session("10.5.6.7", "192.168.1.1", 22, rst=True)
            for _ in range(55)
        ]
        res = BruteForceDetector().detect(sessions)
        assert res is not None
        assert res.src_ip == "10.5.6.7"

    def test_exfiltration_result_has_src_ip(self):
        from services.attack_detector.exfiltration_detector import ExfiltrationDetector
        _MB = 1_048_576
        sessions = [
            self._session("192.168.0.10", "8.8.8.8", 443, bs=600 * _MB // 25)
            for _ in range(25)
        ]
        res = ExfiltrationDetector().detect(sessions)
        assert res is not None
        assert res.src_ip == "192.168.0.10"

    def test_ddos_result_src_ip_empty(self):
        """DDoS는 distributed — src_ip = '' (empty string)."""
        from services.attack_detector.ddos_detector import DDoSDetector
        sessions = [
            self._session(f"10.0.{i}.1", "192.168.1.100", 80, pc=500)
            for i in range(60)
        ]
        res = DDoSDetector().detect(sessions)
        assert res is not None
        assert res.src_ip == ""

    def test_commfailure_result_src_ip_empty(self):
        """CommFailure는 aggregate — src_ip = '' (empty string)."""
        from services.attack_detector.comm_failure_detector import CommFailureDetector
        sessions = [
            self._session("10.0.0.1", "192.168.1.1", 80, rst=True)
            for _ in range(12)
        ]
        res = CommFailureDetector().detect(sessions)
        assert res is not None
        assert res.src_ip == ""


class TestAttackResultDowngrade:
    """AttackResult.downgrade()가 src_ip를 유지하는지 확인."""

    def test_downgrade_preserves_src_ip(self):
        from services.attack_detector.base import AttackResult
        r = AttackResult(
            attack_type="PortScan", severity="high",
            mitre_id="T1046", description="test", src_ip="1.2.3.4",
        )
        d = r.downgrade()
        assert d.src_ip == "1.2.3.4"
        assert d.severity == "medium"


class TestAnalyzeEndpointSrcIp:
    """analyze 엔드포인트가 attacks dict에 src_ip를 포함하는지 확인."""

    def test_analyze_attack_dict_has_src_ip(self, api_client):
        from conftest import build_pcap_portscan
        pcap = build_pcap_portscan(num_ports=100)
        up = api_client.post(
            "/api/upload",
            files={"file": ("scan.pcap", pcap, "application/octet-stream")},
        )
        assert up.status_code == 200
        uid = up.json()["upload_id"]
        capture_token = up.json()["capture_token"]
        r = api_client.post("/api/analyze", json={"upload_id": uid, "target_ip": "192.168.1.1"},
                            headers={"X-Upload-Token": capture_token})
        assert r.status_code in (200, 207)
        attacks = r.json().get("attacks", [])
        for a in attacks:
            assert "src_ip" in a, f"src_ip 키 누락: {a}"

    def test_portscan_attack_src_ip_non_empty(self, api_client):
        from conftest import build_pcap_portscan
        pcap = build_pcap_portscan(num_ports=100)
        up = api_client.post(
            "/api/upload",
            files={"file": ("scan.pcap", pcap, "application/octet-stream")},
        )
        uid = up.json()["upload_id"]
        capture_token = up.json()["capture_token"]
        r = api_client.post("/api/analyze", json={"upload_id": uid, "target_ip": "192.168.1.1"},
                            headers={"X-Upload-Token": capture_token})
        attacks = r.json().get("attacks", [])
        portscan = next((a for a in attacks if a["attack_type"] == "PortScan"), None)
        if portscan:
            assert portscan["src_ip"] != "", "PortScan src_ip는 비어있으면 안 됨"


class TestSummaryEndpoint:
    """GET /api/summary/{id} 통합 테스트."""

    def test_404_on_unknown_id(self, api_client):
        r = api_client.get(f"/api/summary/{uuid.uuid4()}")
        assert r.status_code == 404

    def test_400_on_bad_uuid(self, api_client):
        r = api_client.get("/api/summary/not-a-uuid")
        assert r.status_code == 400

    def test_400_on_non_v4_uuid(self, api_client):
        r = api_client.get("/api/summary/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 400

    def test_response_schema_after_analyze(self, api_client):
        from conftest import build_pcap
        pcap = build_pcap(num_packets=5)
        up = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", pcap, "application/octet-stream")},
        )
        uid = up.json()["upload_id"]
        capture_token = up.json()["capture_token"]
        api_client.post("/api/analyze", json={"upload_id": uid},
                        headers={"X-Upload-Token": capture_token})
        r = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        assert r.status_code == 200
        body = r.json()
        for key in ("headline", "narrative", "risk_level",
                    "attacker_ips", "victim_ips", "recommendations",
                    "attack_timeline", "attack_explanations"):
            assert key in body, f"응답에 '{key}' 키 누락"
        assert body["risk_level"] in ("CLEAN", "LOW", "MEDIUM", "HIGH")
        assert isinstance(body["attacker_ips"], list)
        assert isinstance(body["recommendations"], list)
        assert isinstance(body["attack_timeline"], list)
        assert isinstance(body["attack_explanations"], dict)

    def test_summary_before_analyze_returns_clean(self, api_client):
        """analyze 미실행 시 summary는 CLEAN을 반환해야 함."""
        from conftest import build_pcap
        pcap = build_pcap(num_packets=3)
        up = api_client.post(
            "/api/upload",
            files={"file": ("t.pcap", pcap, "application/octet-stream")},
        )
        uid = up.json()["upload_id"]
        capture_token = up.json()["capture_token"]
        # analyze 없이 바로 summary 요청
        r = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        assert r.status_code == 200
        assert r.json()["risk_level"] == "CLEAN"

    def test_portscan_summary_attacker_ip_populated(self, api_client):
        """PortScan 탐지 후 summary에 attacker_ips가 채워져야 함 (B1 fix 검증)."""
        from conftest import build_pcap_portscan
        pcap = build_pcap_portscan(num_ports=100)
        up = api_client.post(
            "/api/upload",
            files={"file": ("scan.pcap", pcap, "application/octet-stream")},
        )
        uid = up.json()["upload_id"]
        capture_token = up.json()["capture_token"]
        api_client.post("/api/analyze", json={"upload_id": uid},
                        headers={"X-Upload-Token": capture_token})
        r = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        body = r.json()
        if body["risk_level"] in ("HIGH", "MEDIUM", "LOW"):
            assert len(body["attacker_ips"]) > 0, "공격 탐지됐는데 attacker_ips 비어있음 (B1 bug)"

    def test_portscan_summary_has_recommendations(self, api_client):
        """PortScan 탐지 후 summary에 방어 권고가 있어야 함."""
        from conftest import build_pcap_portscan
        pcap = build_pcap_portscan(num_ports=100)
        up = api_client.post(
            "/api/upload",
            files={"file": ("scan.pcap", pcap, "application/octet-stream")},
        )
        uid = up.json()["upload_id"]
        capture_token = up.json()["capture_token"]
        api_client.post("/api/analyze", json={"upload_id": uid},
                        headers={"X-Upload-Token": capture_token})
        r = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        body = r.json()
        assert len(body["recommendations"]) > 0

    def test_narrative_has_newlines_when_attacks_present(self, api_client):
        """공격 탐지 시 narrative가 줄바꿈 포함 (B4 fix 검증)."""
        from conftest import build_pcap_portscan
        pcap = build_pcap_portscan(num_ports=100)
        up = api_client.post(
            "/api/upload",
            files={"file": ("scan.pcap", pcap, "application/octet-stream")},
        )
        uid = up.json()["upload_id"]
        capture_token = up.json()["capture_token"]
        api_client.post("/api/analyze", json={"upload_id": uid},
                        headers={"X-Upload-Token": capture_token})
        r = api_client.get(f"/api/summary/{uid}", headers={"X-Upload-Token": capture_token})
        body = r.json()
        if body["risk_level"] != "CLEAN":
            assert "\n" in body["narrative"], "narrative에 줄바꿈 없음 (B4 bug)"
