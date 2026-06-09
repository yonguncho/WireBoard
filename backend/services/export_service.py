"""ExportService — PCAP 분석 결과를 다양한 형식으로 내보내기."""
import csv
import io
import json
from typing import List

from models.attack import AttackDetectionResult
from models.session import SessionModel


class ExportService:
    def export(
        self,
        sessions: List[SessionModel],
        attacks: List[AttackDetectionResult],
        fmt: str,
    ) -> bytes:
        if fmt == "csv":
            return self._to_csv(sessions)
        elif fmt == "json":
            return self._to_json(sessions)
        elif fmt == "excel":
            return self._to_excel(sessions, attacks)
        elif fmt == "pdf":
            return self._to_pdf(sessions)
        elif fmt == "suricata":
            return self._to_suricata(sessions, attacks)
        elif fmt == "snort":
            return self._to_snort(sessions, attacks)
        else:
            raise ValueError(f"Unsupported export format: {fmt!r}")

    def _to_csv(self, sessions: List[SessionModel]) -> bytes:
        buf = io.StringIO()
        fieldnames = [
            "session_id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "bytes_sent", "bytes_recv", "bytes_total",
            "packet_count", "start_ts", "end_ts",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for s in sessions:
            writer.writerow({
                "session_id": s.session_id,
                "src_ip": s.src_ip,
                "dst_ip": s.dst_ip,
                "src_port": s.src_port,
                "dst_port": s.dst_port,
                "protocol": s.protocol,
                "bytes_sent": s.bytes_sent,
                "bytes_recv": s.bytes_recv,
                "bytes_total": s.bytes_sent + s.bytes_recv,
                "packet_count": s.packet_count,
                "start_ts": s.start_ts,
                "end_ts": s.end_ts,
            })
        return buf.getvalue().encode("utf-8")

    def _to_json(self, sessions: List[SessionModel]) -> bytes:
        data = []
        for s in sessions:
            d = s.model_dump()
            d["bytes_total"] = d["bytes_sent"] + d["bytes_recv"]
            data.append(d)
        return json.dumps(data, ensure_ascii=False).encode("utf-8")

    def _to_excel(
        self,
        sessions: List[SessionModel],
        attacks: List[AttackDetectionResult],
    ) -> bytes:
        import openpyxl
        wb = openpyxl.Workbook()
        ws_s = wb.active
        ws_s.title = "Sessions"
        ws_s.append([
            "session_id", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "bytes_sent", "bytes_recv", "packet_count",
        ])
        for s in sessions:
            ws_s.append([
                s.session_id, s.src_ip, s.dst_ip, s.src_port, s.dst_port,
                s.protocol, s.bytes_sent, s.bytes_recv, s.packet_count,
            ])
        ws_a = wb.create_sheet("Attacks")
        ws_a.append(["attack_type", "severity", "mitre_id", "confidence"])
        for a in attacks:
            ws_a.append([a.attack_type, a.severity, a.mitre_id or "", a.confidence])
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    def _to_pdf(self, sessions: List[SessionModel]) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Table, TableStyle

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = [Paragraph("WireBoard Report", styles["Title"])]
        data = [["src_ip", "dst_ip", "protocol", "bytes_sent", "bytes_recv"]]
        for s in sessions[:50]:
            data.append([
                s.src_ip, s.dst_ip, s.protocol,
                str(s.bytes_sent), str(s.bytes_recv),
            ])
        t = Table(data)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        elements.append(t)
        doc.build(elements)
        return buf.getvalue()

    def _to_suricata(
        self,
        sessions: List[SessionModel],
        attacks: List[AttackDetectionResult],
    ) -> bytes:
        if not attacks:
            return b""
        lines = []
        for i, a in enumerate(attacks):
            sid = 9_000_001 + i
            src = sessions[0].src_ip if sessions else "any"
            dst = sessions[0].dst_ip if sessions else "any"
            proto = _proto(sessions[0].protocol if sessions else "TCP")
            msg = a.attack_type.replace('"', '\\"')
            ref = a.mitre_id or "T0000"
            lines.append(
                f'alert {proto} {src} any -> {dst} any '
                f'(msg:"{msg}"; reference:url,attack.mitre.org/techniques/{ref}; '
                f'sid:{sid}; rev:1;)'
            )
        return "\n".join(lines).encode("utf-8")

    def _to_snort(
        self,
        sessions: List[SessionModel],
        attacks: List[AttackDetectionResult],
    ) -> bytes:
        if not attacks:
            return b""
        lines = []
        for i, a in enumerate(attacks):
            sid = 1_000_001 + i
            src = sessions[0].src_ip if sessions else "any"
            dst = sessions[0].dst_ip if sessions else "any"
            proto = _proto(sessions[0].protocol if sessions else "TCP")
            msg = a.attack_type.replace('"', '\\"')
            lines.append(
                f'alert {proto} {src} any -> {dst} any '
                f'(msg:"{msg}"; sid:{sid}; rev:1;)'
            )
        return "\n".join(lines).encode("utf-8")


def _proto(protocol: str) -> str:
    p = protocol.upper()
    if p in ("TCP", "UDP", "ICMP"):
        return p.lower()
    return "ip"
