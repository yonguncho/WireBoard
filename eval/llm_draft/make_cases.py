"""평가용 대표 분석 결과(facts JSON) 생성기.

실제 파이프라인 함수(build_summary → build_facts)로 만든다 — 손으로 쓴 JSON 이
제품 스키마와 어긋나는 일을 막기 위해서. 공격 dict 의 description 은 각 탐지기가
실제로 쓰는 문자열 형식을 그대로 따른다. IP 는 사설/문서용 대역만 사용.

실행: python eval/llm_draft/make_cases.py   (WireBoard 루트에서)
"""
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from services.narrative.llm_draft import build_facts, template_paragraphs  # noqa: E402
from services.narrative.summary_builder import build_summary  # noqa: E402

OUT = Path(__file__).resolve().parent / "cases"
T0 = 1793235723.0  # 2026-10-29 01:02:03 UTC


def sess(src, dst, dport, b, t, proto="TCP", n=1, spacing=1.0):
    return [{
        "session_id": str(uuid.UUID(int=hash((src, dst, dport, t, i)) & ((1 << 128) - 1), version=4)),
        "src_ip": src, "dst_ip": dst, "src_port": 40000 + i, "dst_port": dport, "protocol": proto,
        "start_ts": T0 + t + i * spacing, "end_ts": T0 + t + i * spacing + 0.5,
        "bytes_sent": b // 2, "bytes_recv": b - b // 2, "packet_count": 6, "payload_length": b,
    } for i in range(n)]


def normal_web():
    return (sess("10.0.0.21", "198.51.100.10", 443, 48000, 0, n=40, spacing=7)
            + sess("10.0.0.22", "198.51.100.11", 443, 9000, 3, n=25, spacing=11)
            + sess("10.0.0.21", "192.0.2.53", 53, 180, 1, "UDP", n=30, spacing=9))


def atk(t, sev, mitre, src, desc):
    return {"attack_type": t, "severity": sev, "mitre_id": mitre, "src_ip": src, "description": desc}


HEALTH_DEGRADED = {
    "total_sessions": 60, "overall_score": 52, "healthy": 31, "warning": 11, "critical": 18,
    "failure_summary": {"connection_refused": 9, "no_response": 9},
    "top_issues": [{"issue": "High retransmit rate", "count": 7}],
    "capture_quality": {"warnings": []},
}

CASES = {
    "01_normal_web": ([], normal_web(), None),
    "02_normal_small": ([], sess("10.0.0.5", "198.51.100.40", 443, 5200, 0, n=6), None),
    "03_normal_degraded_network": ([], normal_web(), HEALTH_DEGRADED),
    "04_beacon_single": ([atk("Beacon", "high", "T1071", "10.0.0.31",
                              "10.0.0.31 → 203.0.113.77: CV=3.2%, 48 connections (48 bursts)")],
                         normal_web() + sess("10.0.0.31", "203.0.113.77", 8443, 900, 0, n=48, spacing=60), None),
    "05_beacon_two_hosts": ([atk("Beacon", "high", "T1071", "10.0.0.31",
                                 "10.0.0.31 → 203.0.113.77: CV=3.2%, 48 connections (48 bursts)"),
                             atk("Beacon", "medium", "T1071", "10.0.0.44",
                                 "10.0.0.44 → 203.0.113.90: CV=11.8%, 20 connections (20 bursts)")],
                            normal_web() + sess("10.0.0.31", "203.0.113.77", 8443, 900, 0, n=48, spacing=60)
                            + sess("10.0.0.44", "203.0.113.90", 443, 1400, 5, n=20, spacing=300), None),
    "06_portscan_external": ([atk("PortScan", "high", "T1046", "203.0.113.200",
                                  "203.0.113.200 → 10.0.0.10: scanned 512 ports")],
                             normal_web() + [s for p in range(1, 120) for s in sess("203.0.113.200", "10.0.0.10", p, 60, p * 0.01)], None),
    "07_portscan_internal_lateral": ([atk("PortScan", "medium", "T1046", "10.0.0.66",
                                          "10.0.0.66 → 10.0.0.12: scanned 35 ports")],
                                     normal_web() + [s for p in (22, 135, 139, 445, 3389, 5985) for s in sess("10.0.0.66", "10.0.0.12", p, 120, p * 0.1)], None),
    "08_bruteforce_ssh": ([atk("BruteForce", "high", "T1110", "198.51.100.66",
                               "198.51.100.66 → 10.0.0.15:22: 340 attempts, 97% failure rate")],
                          normal_web() + sess("198.51.100.66", "10.0.0.15", 22, 2400, 0, n=80, spacing=2), None),
    "09_ddos_inbound": ([atk("DDoS", "high", "T1498", "",
                             "→ 10.0.0.80: 18432 pps, 212 sources")],
                        normal_web() + sess("203.0.113.5", "10.0.0.80", 80, 64000, 0, n=50, spacing=0.1), None),
    "10_exfiltration": ([atk("Exfiltration", "high", "T1041", "10.0.0.51",
                             "10.0.0.51: 14 external connections, 820 MB sent (outbound 96%)")],
                        normal_web() + sess("10.0.0.51", "198.51.100.99", 443, 60_000_000, 0, n=14, spacing=40), None),
    "11_mixed_scan_then_bruteforce": ([atk("PortScan", "high", "T1046", "203.0.113.200",
                                           "203.0.113.200 → 10.0.0.15: scanned 1024 ports"),
                                       atk("BruteForce", "high", "T1110", "203.0.113.200",
                                           "203.0.113.200 → 10.0.0.15:22: 512 attempts, 99% failure rate")],
                                      normal_web() + sess("203.0.113.200", "10.0.0.15", 22, 2400, 30, n=60, spacing=1), None),
    "12_mixed_beacon_exfil_degraded": ([atk("Beacon", "high", "T1071", "10.0.0.31",
                                            "10.0.0.31 → 203.0.113.77: CV=2.1%, 96 connections (96 bursts)"),
                                        atk("Exfiltration", "medium", "T1041", "10.0.0.31",
                                            "10.0.0.31: 6 external connections, 140 MB sent (outbound 91%)"),
                                        atk("CommFailure", "low", "T1499", "10.0.0.9",
                                            "RST flood: 45/sec detected")],
                                       normal_web() + sess("10.0.0.31", "203.0.113.77", 8443, 900, 0, n=96, spacing=30)
                                       + sess("10.0.0.31", "203.0.113.77", 443, 23_000_000, 10, n=6, spacing=120), HEALTH_DEGRADED),
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (attacks, sessions, health) in CASES.items():
        nr = build_summary(attacks, sessions, health=health)
        facts = build_facts(attacks, sessions, nr)
        (OUT / f"{name}.json").write_text(json.dumps({
            "name": name, "facts": facts, "templates": template_paragraphs(nr),
        }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{len(CASES)} cases -> {OUT}")


if __name__ == "__main__":
    main()
