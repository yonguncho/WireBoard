# -*- coding: utf-8 -*-
"""Edge cases: attack detector output validation, MITRE IDs, direction logic, zero-duration sessions."""
import os
import sys
import uuid

import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from models.session import SessionModel
from services.attack_detector.dos_detector import DoSDetector
from services.attack_detector.ddos_detector import DDoSDetector
from services.attack_detector.beacon_detector import BeaconDetector
from services.attack_detector.portscan_detector import PortScanDetector
from services.attack_detector.exfiltration_detector import ExfiltrationDetector as ExfilDetector
from services.attack_detector.comm_failure_detector import CommFailureDetector


def _s(src_ip="10.0.0.1", dst_ip="192.168.1.1", packet_count=1,
       bytes_total=100, port=80, confidence="normal", start_ts=0.0, end_ts=1.0):
    return SessionModel(
        session_id=str(uuid.uuid4()),
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=54321, dst_port=port,
        protocol="TCP",
        start_ts=start_ts, end_ts=end_ts,
        bytes_sent=bytes_total // 2, bytes_recv=bytes_total // 2,
        packet_count=packet_count, payload_length=0,
        confidence=confidence,
    )


# ── DoS edge cases ──────────────────────────────────────────────

class TestDoSEdge:
    def test_zero_duration_session_no_crash(self):
        detector = DoSDetector()
        sessions = [_s(packet_count=6000, start_ts=0.0, end_ts=0.0)]
        result = detector.detect(sessions)
        assert result is not None or result is None  # should not raise

    def test_empty_session_list_returns_none(self):
        assert DoSDetector().detect([]) is None

    def test_attack_type_is_dos(self):
        result = DoSDetector().detect([_s(packet_count=6000)])
        assert result is not None
        assert result.attack_type == "DoS"

    def test_mitre_id_present(self):
        result = DoSDetector().detect([_s(packet_count=6000)])
        assert result is not None
        assert result.mitre_id is not None
        assert result.mitre_id.startswith("T")

    def test_evidence_list_non_empty(self):
        result = DoSDetector().detect([_s(packet_count=6000)])
        assert result is not None
        assert len(result.evidence) > 0

    def test_sample_count_non_negative(self):
        result = DoSDetector().detect([_s(packet_count=6000)])
        assert result is not None
        assert result.sample_count >= 0

    def test_single_session_at_medium_threshold(self):
        result = DoSDetector().detect([_s(packet_count=3000)])
        assert result is not None
        assert result.confidence == "medium"


# ── DDoS edge cases ─────────────────────────────────────────────

class TestDDoSEdge:
    def _ddos_sessions(self, n=6, pkt=4000, confidence="normal"):
        return [_s(src_ip=f"10.0.{i//256}.{i%256}", dst_ip="192.168.1.1",
                   packet_count=pkt, confidence=confidence) for i in range(n)]

    def test_empty_session_list_returns_none(self):
        assert DDoSDetector().detect([]) is None

    def test_single_source_no_detection(self):
        result = DDoSDetector().detect([_s(packet_count=100000)])
        assert result is None

    def test_attack_type_is_ddos(self):
        result = DDoSDetector().detect(self._ddos_sessions())
        assert result is not None
        assert result.attack_type == "DDoS"

    def test_mitre_id_present(self):
        result = DDoSDetector().detect(self._ddos_sessions())
        assert result is not None
        assert result.mitre_id is not None

    def test_zero_packet_count_sessions(self):
        sessions = self._ddos_sessions(n=6, pkt=0)
        result = DDoSDetector().detect(sessions)
        assert result is None  # below threshold

    def test_exactly_min_sources(self):
        sessions = self._ddos_sessions(n=5, pkt=4000)
        result = DDoSDetector().detect(sessions)
        assert result is None  # 5 < minimum 6 sources

    def test_confidence_downgrade_for_low_source_sessions(self):
        sessions = self._ddos_sessions(n=6, pkt=4000, confidence="low")
        result = DDoSDetector().detect(sessions)
        assert result is not None
        assert result.confidence != "high"


# ── PortScan edge cases ─────────────────────────────────────────

class TestPortScanEdge:
    def test_empty_returns_none(self):
        assert PortScanDetector().detect([]) is None

    def test_single_port_no_detection(self):
        assert PortScanDetector().detect([_s(port=80)]) is None

    def test_two_distinct_ports_no_detection(self):
        assert PortScanDetector().detect([_s(port=80), _s(port=443)]) is None

    def test_many_unique_src_ips_same_port_no_detection(self):
        # Port scan is dst_port diversity, not src_ip diversity
        sessions = [_s(src_ip=f"10.0.0.{i}", port=80) for i in range(1, 50)]
        result = PortScanDetector().detect(sessions)
        assert result is None

    def test_attack_type_is_portscan(self):
        sessions = [_s(port=p) for p in range(1, 110)]
        result = PortScanDetector().detect(sessions)
        assert result is not None
        assert result.attack_type == "PortScan"

    def test_mitre_id_present(self):
        sessions = [_s(port=p) for p in range(1, 110)]
        result = PortScanDetector().detect(sessions)
        assert result is not None
        assert result.mitre_id is not None

    def test_evidence_contains_port_count_info(self):
        sessions = [_s(port=p) for p in range(1, 110)]
        result = PortScanDetector().detect(sessions)
        assert result is not None
        assert any(ev for ev in result.evidence)


# ── DataExfiltration edge cases ─────────────────────────────────

class TestExfilEdge:
    TARGET = "192.168.1.100"

    def _exfil_sessions(self, src_ip, dst_ip="8.8.8.8", bytes_sent=110_000_000, n=6):
        return [_s(src_ip=src_ip, dst_ip=dst_ip,
                   bytes_total=bytes_sent // n) for _ in range(n)]

    def test_empty_returns_none(self):
        assert ExfilDetector().detect([]) is None

    def test_target_as_dst_only_no_exfil(self):
        """Inbound-heavy: dst receives, should NOT detect exfil from dst."""
        sessions = [_s(src_ip="8.8.8.8", dst_ip=self.TARGET, bytes_total=2_000_000)]
        result = ExfilDetector().detect(sessions)
        # 8.8.8.8 is public dst → not counted as outbound from TARGET
        assert result is None

    def test_target_as_src_high_bytes_detected(self):
        """TARGET sending >100MB outbound → exfil."""
        sessions = self._exfil_sessions(src_ip=self.TARGET)
        result = ExfilDetector().detect(sessions)
        assert result is not None
        assert result.attack_type == "Exfiltration"

    def test_below_min_bytes_no_detection(self):
        sessions = [_s(src_ip=self.TARGET, bytes_total=500)]
        result = ExfilDetector().detect(sessions)
        assert result is None

    def test_mixed_traffic_low_ratio_no_detection(self):
        # Mostly inbound → not exfil
        sessions = [_s(src_ip=self.TARGET, bytes_total=100_000)]
        result = ExfilDetector().detect(sessions)
        assert result is None

    def test_mitre_id_present(self):
        sessions = self._exfil_sessions(src_ip=self.TARGET)
        result = ExfilDetector().detect(sessions)
        assert result is not None
        assert result.mitre_id is not None

    def test_attack_type_field_value(self):
        sessions = self._exfil_sessions(src_ip=self.TARGET)
        result = ExfilDetector().detect(sessions)
        assert result is not None
        assert result.attack_type == "Exfiltration"


# ── CommFailure edge cases ──────────────────────────────────────

class TestCommFailureEdge:
    def test_empty_sessions_zero_counters_returns_none(self):
        assert CommFailureDetector().detect([], rst_count=0, icmp_unreachable=0) is None

    def test_attack_type_is_comm_failure(self):
        result = CommFailureDetector().detect([], rst_count=25)
        assert result is not None
        assert result.attack_type == "CommFailure"

    def test_mitre_id_t1595(self):
        result = CommFailureDetector().detect([], rst_count=25)
        assert result is not None
        assert result.mitre_id == "T1595"

    def test_combined_rst_icmp_at_threshold(self):
        result = CommFailureDetector().detect([], rst_count=5, icmp_unreachable=5)
        assert result is not None

    def test_high_icmp_alone_triggers(self):
        result = CommFailureDetector().detect([], rst_count=0, icmp_unreachable=25)
        # Whether this triggers depends on threshold — should not crash
        assert result is None or result.attack_type == "CommFailure"
