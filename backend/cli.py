"""헤드리스 CLI 모드 — 서버/브라우저 없이 캡처를 분석해 JSON/PDF로 출력.

자동화·SOC 파이프라인·배치 처리용. 사용:
    WireBoard.exe analyze <capture> [--json out.json] [--pdf out.pdf] [--target IP]
"""
from __future__ import annotations

import json
import os
import sys

from services.parser.pcap_parser import PcapParser
from services.parser.har_parser import HarParser
from services.parser.fortigate_parser import FortigateParser
from services.parser.tcpdump_parser import TcpdumpParser
from services.normalizer import SessionNormalizer
from store.session_store import ParsedCapture
from services.narrative.capture_summary import summarize_capture
from utils.constants import APP_VERSION


def _source_type(parser) -> str:
    n = type(parser).__name__.lower()
    return ("har" if "har" in n else "fortigate" if "forti" in n
            else "tcpdump" if "tcpdump" in n else "pcap")


def _parse_capture(path: str, warnings: list):
    with open(path, "rb") as f:
        head = f.read(4)
    p = PcapParser()
    if p.detect(head):
        with open(path, "rb") as f:
            sessions, pkt_map = p.parse_stream(f, parse_warnings=warnings, size=os.path.getsize(path))
        return sessions, pkt_map, list(p.icmp_events), "pcap"
    with open(path, "rb") as f:
        data = f.read()
    for parser in (HarParser(), FortigateParser(), TcpdumpParser()):
        if parser.detect(data):
            res = parser.parse(data, parse_warnings=warnings)
            sessions, pm = res if isinstance(res, tuple) else (res, {})
            if not pm:
                pm = getattr(parser, "packet_map", {}) or {}
            return sessions, pm, list(getattr(parser, "icmp_events", [])), _source_type(parser)
    raise ValueError("Unsupported or unrecognized capture format")


def analyze_file(path: str, target: str | None = None):
    warnings: list = []
    sessions, pkt_map, icmp, stype = _parse_capture(path, warnings)
    sessions, pkt_map = SessionNormalizer().normalize(sessions, pkt_map)
    if not sessions:
        raise ValueError("No sessions parsed from capture")

    from routers.analyze import _DETECTORS, _auto_detect_target_ip
    tgt = target or _auto_detect_target_ip(sessions)
    target_sessions = [s for s in sessions if s.src_ip == tgt or s.dst_ip == tgt] or sessions
    attacks = []
    for d in _DETECTORS:
        try:
            r = d.detect(target_sessions)
            if r:
                attacks.append({"attack_type": r.attack_type, "severity": r.severity,
                                "mitre_id": r.mitre_id, "description": r.description,
                                "src_ip": getattr(r, "src_ip", "")})
        except Exception:
            pass

    cap = ParsedCapture(sessions=sessions, source_type=stype, packet_map=pkt_map,
                        icmp_events=icmp, attacks=attacks, target_ip=tgt or "")
    sr = summarize_capture(cap)
    return cap, sr, warnings


def _usage() -> str:
    return ("WireBoard CLI\n"
            "  WireBoard analyze <capture> [--json <out.json>] [--pdf <out.pdf>] [--target <IP>]\n"
            "  WireBoard --version\n")


def run_cli(argv: list[str]) -> int:
    """argv: 프로그램명 제외한 인자. 반환: 종료 코드."""
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage())
        return 0
    if argv[0] in ("-V", "--version"):
        print(f"WireBoard {APP_VERSION}")
        return 0
    if argv[0] != "analyze":
        print(_usage(), file=sys.stderr)
        return 2

    rest = argv[1:]
    if not rest:
        print("error: analyze requires a capture file path", file=sys.stderr)
        return 2
    capture_path = rest[0]
    opts = rest[1:]
    json_out = pdf_out = target = None
    i = 0
    while i < len(opts):
        o = opts[i]
        if o == "--json" and i + 1 < len(opts):
            json_out = opts[i + 1]; i += 2
        elif o == "--pdf" and i + 1 < len(opts):
            pdf_out = opts[i + 1]; i += 2
        elif o == "--target" and i + 1 < len(opts):
            target = opts[i + 1]; i += 2
        else:
            print(f"error: unknown option {o!r}", file=sys.stderr)
            return 2

    if not os.path.isfile(capture_path):
        print(f"error: file not found: {capture_path}", file=sys.stderr)
        return 2

    try:
        cap, sr, warnings = analyze_file(capture_path, target)
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    # 진단 payload (verdict/expert/dns/app) 재사용
    try:
        from routers.export import _report_payload
        _risk, diagnostics = _report_payload(cap)
    except Exception:
        diagnostics = None

    result = {
        "version": APP_VERSION,
        "file": os.path.basename(capture_path),
        "source_type": cap.source_type,
        "target_ip": cap.target_ip,
        "session_count": len(cap.sessions),
        "risk_level": sr.risk_level,
        "risk_score": sr.risk_score,
        "headline": sr.headline,
        "attacks": cap.attacks,
        "diagnosis": sr.diagnosis,
        "recommendations": sr.recommendations,
        "diagnostics": diagnostics,
        "parse_warnings": warnings,
    }

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"JSON written: {json_out}")
    else:
        # stdout 요약 (사람이 읽기용)
        print(f"WireBoard {APP_VERSION} — {result['file']} ({cap.source_type})")
        print(f"  Sessions: {result['session_count']}   Risk: {sr.risk_level} ({sr.risk_score}/100)")
        print(f"  {sr.headline}")
        if cap.attacks:
            for a in cap.attacks:
                print(f"   [attack] {a['attack_type']} ({a['severity']}) {a['mitre_id']}")
        for d in sr.diagnosis[:6]:
            print(f"   - {d}")

    if pdf_out:
        try:
            from services.report.pdf_exporter import PdfExporter
            from pathlib import Path
            annotations: list = []
            analysis_result = {
                "target_ip": cap.target_ip or "unknown",
                "sessions": cap.sessions, "attacks": cap.attacks,
                "annotations": annotations,
                "risk": {"risk_level": sr.risk_level, "risk_score": sr.risk_score,
                         "headline": sr.headline, "risk_factors": sr.risk_factors,
                         "diagnosis": sr.diagnosis, "recommendations": sr.recommendations},
                "diagnostics": diagnostics,
                "summary": {"total_sessions": len(cap.sessions),
                            "total_bytes": sum(s.bytes_sent + s.bytes_recv for s in cap.sessions)},
            }
            PdfExporter().generate(analysis_result, output_path=Path(pdf_out))
            print(f"PDF written: {pdf_out}")
        except Exception as exc:
            print(f"error: PDF generation failed: {exc}", file=sys.stderr)
            return 1

    return 0
