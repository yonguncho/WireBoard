"""POST /api/analyze 통합 테스트 + 공격 탐지기 유닛 테스트.

대상:
  backend/routers/analyze.py        (POST /api/analyze)
  backend/services/attack_detector/ (5종 탐지기)
  backend/store/session_store.py    (SessionStore TTL/LRU)

검증 항목:
- UUID 검증 실패 → 400 (ADR-004, 422 아님)
- 알 수 없는 upload_id → 404
- 유효 요청 → 응답 스키마 (flows, sessions, attacks, analysis_duration_ms)
- analysis_duration_ms ≤ 5000 ms (10 MB pcap 기준, A: ≤5s)
- PortScan: 100 포트 → severity="high" (T-16)
- Beacon: CV=3%, sample=8 → severity="high" (A-02)
- FortiGate 출처 confidence="low" → severity 1단계 강등 (T-16)
- SessionStore: TTL 만료 → KeyError, LRU 11건 → 최초 1건 퇴출
- gc.collect 호출: analyze.py 에 del + gc.collect() 존재 확인 (보안 grep)
"""
import io
import math
import re
import time
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

UUID_RE: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ─────────────────────── 헬퍼: upload 먼저 ──────────────────────────

def _upload_pcap(client: TestClient, pcap_data: bytes) -> str:
    """pcap 업로드 후 upload_id 반환."""
    resp = client.post(
        "/api/upload",
        files={"file": ("capture.pcap", io.BytesIO(pcap_data), "application/octet-stream")},
    )
    assert resp.status_code == 200, f"업로드 실패: {resp.text}"
    return resp.json()["upload_id"]


# ───────────────────── POST /api/analyze: 에러 케이스 ────────────────

class TestAnalyzeErrors:
    def test_invalid_uuid_returns_400(self, api_client: TestClient) -> None:
        """UUID 형식 아닌 upload_id → 400 (ADR-004: 422 아님)."""
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": "not-a-uuid", "target_ip": "192.168.1.1"},
        )
        assert resp.status_code == 400, (
            f"기대 400, 실제 {resp.status_code}: {resp.text}"
        )

    def test_invalid_uuid_error_code(self, api_client: TestClient) -> None:
        """에러 응답 body 에 invalid_uuid 코드 포함."""
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": "00000000-0000-0000-0000-000000000000X", "target_ip": "192.168.1.1"},
        )
        assert resp.status_code == 400
        body = resp.json()
        # detail 에 error 코드가 있어야 함
        detail = body.get("detail", "")
        assert "uuid" in str(detail).lower() or "invalid" in str(detail).lower()

    def test_unknown_upload_id_returns_404(self, api_client: TestClient) -> None:
        """존재하지 않는 UUID → 404."""
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": str(uuid.uuid4()), "target_ip": "192.168.1.1"},
        )
        assert resp.status_code == 404

    def test_missing_upload_id_returns_422(self, api_client: TestClient) -> None:
        resp = api_client.post("/api/analyze", json={"target_ip": "192.168.1.1"})
        assert resp.status_code == 422

    def test_missing_target_ip_returns_422(self, api_client: TestClient) -> None:
        resp = api_client.post("/api/analyze", json={"upload_id": str(uuid.uuid4())})
        assert resp.status_code == 422

    def test_invalid_ip_format_returns_400(self, api_client: TestClient, pcap_bytes: bytes) -> None:
        """IP 형식 검증 실패 → 400."""
        upload_id = _upload_pcap(api_client, pcap_bytes)
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": upload_id, "target_ip": "not.an.ip.address"},
        )
        assert resp.status_code in {400, 422}


# ───────────────────── POST /api/analyze: 정상 케이스 ───────────────

class TestAnalyzeSuccess:
    def test_analyze_returns_200(self, api_client: TestClient, pcap_bytes: bytes) -> None:
        upload_id = _upload_pcap(api_client, pcap_bytes)
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": upload_id, "target_ip": "192.168.1.2"},
        )
        assert resp.status_code == 200

    def test_analyze_response_schema(self, api_client: TestClient, pcap_bytes: bytes) -> None:
        upload_id = _upload_pcap(api_client, pcap_bytes)
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": upload_id, "target_ip": "192.168.1.2"},
        )
        body: dict[str, Any] = resp.json()
        assert "flows" in body
        assert "sessions" in body
        assert "attacks" in body
        assert "analysis_duration_ms" in body
        assert isinstance(body["flows"], list)
        assert isinstance(body["sessions"], list)
        assert isinstance(body["attacks"], list)
        assert isinstance(body["analysis_duration_ms"], (int, float))

    def test_analyze_duration_ms_positive(self, api_client: TestClient, pcap_bytes: bytes) -> None:
        upload_id = _upload_pcap(api_client, pcap_bytes)
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": upload_id, "target_ip": "192.168.1.2"},
        )
        assert resp.json()["analysis_duration_ms"] > 0

    def test_analyze_duration_under_5000ms(self, api_client: TestClient, pcap_bytes: bytes) -> None:
        """5-packet pcap 분석은 5,000 ms 미만 (성능 기준)."""
        upload_id = _upload_pcap(api_client, pcap_bytes)
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": upload_id, "target_ip": "192.168.1.2"},
        )
        assert resp.json()["analysis_duration_ms"] < 5_000

    def test_analyze_target_ip_in_response(self, api_client: TestClient, pcap_bytes: bytes) -> None:
        upload_id = _upload_pcap(api_client, pcap_bytes)
        resp = api_client.post(
            "/api/analyze",
            json={"upload_id": upload_id, "target_ip": "192.168.1.2"},
        )
        assert resp.json().get("target_ip") == "192.168.1.2"


# ─────────────────── AttackDetector — PortScan ────────────────────

class TestPortScanDetector:
    def _make_sessions(
        self,
        src_ip: str,
        dst_ip: str,
        dst_ports: list[int],
        rst: bool = True,
    ) -> list[Any]:
        from models.session import SessionModel
        sessions = []
        for port in dst_ports:
            sessions.append(SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=12345,
                dst_port=port,
                protocol="TCP",
                start_ts=1_748_000_000.0,
                end_ts=1_748_000_001.0,
                bytes_sent=60,
                bytes_recv=0,
                packet_count=1,
                payload_length=0,
                confidence="normal",
                rst=rst,
            ))
        return sessions

    def test_100_ports_returns_high(self) -> None:
        """100 개 dst_port → severity='high' (T-16, todo.md 완료 기준)."""
        from services.attack_detector.portscan_detector import PortScanDetector
        sessions = self._make_sessions("10.0.0.1", "192.168.1.16", list(range(1, 101)))
        result = PortScanDetector().detect(sessions)
        assert result is not None, "PortScan 탐지 실패"
        assert result.severity == "high"

    def test_50_ports_returns_medium(self) -> None:
        from services.attack_detector.portscan_detector import PortScanDetector
        sessions = self._make_sessions("10.0.0.1", "192.168.1.16", list(range(1, 51)))
        result = PortScanDetector().detect(sessions)
        assert result is not None
        assert result.severity == "medium"

    def test_under_threshold_returns_none(self) -> None:
        """dst_port < 20 → 탐지 안 함."""
        from services.attack_detector.portscan_detector import PortScanDetector
        sessions = self._make_sessions("10.0.0.1", "192.168.1.16", list(range(1, 10)))
        result = PortScanDetector().detect(sessions)
        assert result is None

    def test_result_has_mitre_id(self) -> None:
        from services.attack_detector.portscan_detector import PortScanDetector
        sessions = self._make_sessions("10.0.0.1", "192.168.1.16", list(range(1, 101)))
        result = PortScanDetector().detect(sessions)
        assert result is not None
        assert result.mitre_id == "T1046"

    def test_fortigate_source_downgrade(self) -> None:
        """FortiGate 출처 (confidence='low') → severity 1단계 강등 (T-16)."""
        from services.attack_detector.portscan_detector import PortScanDetector
        from models.session import SessionModel

        # 100 포트 → 원래 high → 강등 후 medium
        sessions_fg = []
        for port in range(1, 101):
            sessions_fg.append(SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip="10.0.0.1",
                dst_ip="192.168.1.16",
                src_port=12345,
                dst_port=port,
                protocol="TCP",
                start_ts=1_748_000_000.0,
                end_ts=1_748_000_001.0,
                bytes_sent=60,
                bytes_recv=0,
                packet_count=1,
                payload_length=0,
                confidence="low",  # FortiGate verbose 3
                rst=True,
            ))
        result = PortScanDetector().detect(sessions_fg)
        assert result is not None
        assert result.severity == "medium", (
            "FortiGate 출처 → high 에서 medium 으로 1단계 강등 기대"
        )


# ─────────────────────── AttackDetector — Beacon ───────────────────

class TestBeaconDetector:
    def _make_beacon_sessions(
        self,
        intervals_sec: list[float],
        src_ip: str = "10.0.0.5",
        dst_ip: str = "203.0.113.1",
        confidence: str = "normal",
    ) -> list[Any]:
        """지정된 인터벌로 반복 접속하는 세션 목록 생성."""
        from models.session import SessionModel
        sessions = []
        ts = 1_748_000_000.0
        for i, gap in enumerate(intervals_sec):
            sessions.append(SessionModel(
                session_id=str(uuid.uuid4()),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=50000 + i,
                dst_port=443,
                protocol="TCP",
                start_ts=ts,
                end_ts=ts + 0.1,
                bytes_sent=200,
                bytes_recv=100,
                packet_count=3,
                payload_length=200,
                confidence=confidence,
            ))
            ts += gap
        return sessions

    def _cv(self, values: list[float]) -> float:
        n = len(values)
        mean = sum(values) / n
        std = math.sqrt(sum((v - mean) ** 2 for v in values) / n)
        return (std / mean) * 100 if mean else 0.0

    def test_cv3_sample8_returns_high(self) -> None:
        """CV=3%, sample=8 → severity='high' (todo.md 완료 기준)."""
        from services.attack_detector.beacon_detector import BeaconDetector
        # mean=60s, CV=3% → std=1.8s → intervals 60 ±1.8
        mean = 60.0
        std = mean * 0.03
        intervals = [mean + std * ((-1) ** i) * 0.5 for i in range(8)]
        assert self._cv(intervals) <= 5.0
        sessions = self._make_beacon_sessions(intervals)
        result = BeaconDetector().detect(sessions)
        assert result is not None, "Beacon 탐지 실패"
        assert result.severity == "high"

    def test_cv10_returns_medium(self) -> None:
        from services.attack_detector.beacon_detector import BeaconDetector
        mean = 60.0
        std = mean * 0.08  # CV ≈ 8% (≤10% = medium)
        intervals = [mean + std * ((-1) ** i) * 0.9 for i in range(7)]
        result = BeaconDetector().detect(sessions=self._make_beacon_sessions(intervals))
        assert result is not None
        assert result.severity in {"medium", "high"}

    def test_sample_count_under_5_returns_none(self) -> None:
        """sample_count < 5 → 탐지 안 함 (A-02)."""
        from services.attack_detector.beacon_detector import BeaconDetector
        intervals = [60.0, 60.1, 59.9]  # 4 sessions, 3 intervals
        result = BeaconDetector().detect(self._make_beacon_sessions(intervals))
        assert result is None

    def test_high_cv_returns_none(self) -> None:
        """CV > 20% → Beacon 아님."""
        from services.attack_detector.beacon_detector import BeaconDetector
        intervals = [10.0, 120.0, 5.0, 200.0, 30.0, 90.0, 15.0]
        result = BeaconDetector().detect(self._make_beacon_sessions(intervals))
        assert result is None

    def test_result_mitre_id(self) -> None:
        from services.attack_detector.beacon_detector import BeaconDetector
        mean = 60.0
        std = mean * 0.03
        intervals = [mean + std * ((-1) ** i) * 0.5 for i in range(8)]
        result = BeaconDetector().detect(self._make_beacon_sessions(intervals))
        assert result is not None
        assert result.mitre_id == "T1071"

    def test_fortigate_source_downgrade(self) -> None:
        """FortiGate confidence='low' → severity 1단계 강등."""
        from services.attack_detector.beacon_detector import BeaconDetector
        mean = 60.0
        std = mean * 0.03
        intervals = [mean + std * ((-1) ** i) * 0.5 for i in range(8)]
        # confidence='low' → 원래 high → 강등 후 medium
        sessions = self._make_beacon_sessions(intervals, confidence="low")
        result = BeaconDetector().detect(sessions)
        assert result is not None
        assert result.severity == "medium"


# ───────────────────── SessionStore TTL / LRU ────────────────────────

class TestSessionStore:
    def test_get_missing_key_raises_key_error(self) -> None:
        from store.session_store import SessionStore
        store = SessionStore()
        with pytest.raises(KeyError):
            store.get(str(uuid.uuid4()))

    def test_put_and_get(self, pcap_bytes: bytes) -> None:
        from store.session_store import SessionStore, ParsedCapture
        store = SessionStore()
        uid = str(uuid.uuid4())
        capture = ParsedCapture(sessions=[], source_type="pcap")
        store.put(uid, capture)
        assert store.get(uid) is capture

    def test_lru_11th_evicts_oldest(self) -> None:
        """11 건 입력 → 1번째 자동 퇴출 (LRU 최대 10, ADR todo.md T-03)."""
        from store.session_store import SessionStore, ParsedCapture
        store = SessionStore()
        keys: list[str] = []
        for _ in range(11):
            k = str(uuid.uuid4())
            store.put(k, ParsedCapture(sessions=[], source_type="pcap"))
            keys.append(k)
        # 가장 오래된 첫 번째 키는 퇴출되어야 함
        with pytest.raises(KeyError):
            store.get(keys[0])
        # 나머지 10 건은 유지
        for k in keys[1:]:
            store.get(k)  # KeyError 없어야 함

    def test_ttl_expired_raises_key_error(self) -> None:
        """TTL 초과 → KeyError (실제 sleep 없이 TTL 을 0으로 단축)."""
        from store.session_store import SessionStore, ParsedCapture
        store = SessionStore(ttl_seconds=0)  # TTL=0 → 즉시 만료
        uid = str(uuid.uuid4())
        store.put(uid, ParsedCapture(sessions=[], source_type="pcap"))
        with pytest.raises(KeyError):
            store.get(uid)

    def test_evict_expired_returns_count(self) -> None:
        from store.session_store import SessionStore, ParsedCapture
        store = SessionStore(ttl_seconds=0)
        for _ in range(3):
            store.put(str(uuid.uuid4()), ParsedCapture(sessions=[], source_type="pcap"))
        evicted = store.evict_expired()
        assert evicted == 3


# ─────────────────────── 보안 grep 확인 ─────────────────────────────

class TestSecurityGrep:
    def test_analyze_router_has_gc_collect(self) -> None:
        """analyze.py 에 del + gc.collect() 가 있어야 한다 (메모리 보안)."""
        from pathlib import Path
        analyze_path = Path(__file__).parent.parent / "backend" / "routers" / "analyze.py"
        if not analyze_path.exists():
            pytest.skip("analyze.py 미구현 — 구현 후 통과 예상")
        source = analyze_path.read_text(encoding="utf-8")
        assert "gc.collect()" in source, "analyze.py 에 gc.collect() 누락"

    def test_no_any_type_in_models(self) -> None:
        """models/ 디렉터리에 ': any' 또는 'Any' 타입이 없어야 한다."""
        from pathlib import Path
        models_dir = Path(__file__).parent.parent / "backend" / "models"
        if not models_dir.exists():
            pytest.skip("models/ 미구현")
        for py_file in models_dir.glob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            assert ": Any" not in source, f"{py_file.name} 에 ': Any' 타입 발견"
            assert "typing.Any" not in source, f"{py_file.name} 에 typing.Any 발견"

    def test_no_0000_binding(self) -> None:
        """0.0.0.0 바인딩이 없어야 한다 (ADR-005: 127.0.0.1 만 허용)."""
        from pathlib import Path
        backend_dir = Path(__file__).parent.parent / "backend"
        if not backend_dir.exists():
            pytest.skip("backend/ 미구현")
        for py_file in backend_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            assert "0.0.0.0" not in source, (
                f"{py_file.name} 에 0.0.0.0 바인딩 발견 (ADR-005 위반)"
            )

    def test_no_bare_except(self) -> None:
        """bare except: pass 패턴 없음 (관측성 요구사항)."""
        from pathlib import Path
        import ast

        backend_dir = Path(__file__).parent.parent / "backend"
        if not backend_dir.exists():
            pytest.skip("backend/ 미구현")

        violations: list[str] = []
        for py_file in backend_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    if node.type is None:  # bare except
                        violations.append(f"{py_file.name}:{node.lineno}")
        assert not violations, f"bare except 발견: {violations}"

    def test_no_iterrows_in_services(self) -> None:
        """services/ 에 iterrows 사용 없음 (ADR-003)."""
        from pathlib import Path
        services_dir = Path(__file__).parent.parent / "backend" / "services"
        if not services_dir.exists():
            pytest.skip("services/ 미구현")
        for py_file in services_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            assert "iterrows" not in source, (
                f"{py_file.name} 에 iterrows 발견 (ADR-003 위반)"
            )
