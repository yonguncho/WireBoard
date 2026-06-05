"""PdfExporter — 분석 결과 PDF 리포트 생성 (외부 라이브러리 없음)."""
import tempfile
import time
import unicodedata
from pathlib import Path

_UNICODE_ASCII_MAP = {
    "→": "->", "←": "<-", "↑": "^", "↓": "v", "⇒": "=>", "⇐": "<=",
    "…": "...", "–": "-", "—": "--", "•": "*", "·": ".", "×": "x",
}


def _pdf_escape(text: str) -> str:
    for k, v in _UNICODE_ASCII_MAP.items():
        text = text.replace(k, v)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_pdf(lines: list[str]) -> bytes:
    """최소한의 유효한 PDF (PDF 1.4, Type1 Helvetica 폰트) 를 생성한다."""
    text_ops = []
    y = 750
    for line in lines:
        safe = _pdf_escape(line[:100])
        text_ops.append(f"BT /F1 10 Tf 50 {y} Td ({safe}) Tj ET")
        y -= 14
        if y < 50:
            break

    stream_content = "\n".join(text_ops)
    stream_bytes = stream_content.encode("latin-1", errors="replace")

    objects: list[bytes] = []

    # obj 1: Catalog
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    # obj 2: Pages
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    # obj 3: Page
    objects.append(
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        b"   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\n"
        b"endobj\n"
    )
    # obj 4: Content stream
    objects.append(
        b"4 0 obj\n<< /Length "
        + str(len(stream_bytes)).encode()
        + b" >>\nstream\n"
        + stream_bytes
        + b"\nendstream\nendobj\n"
    )
    # obj 5: Font
    objects.append(
        b"5 0 obj\n"
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
        b"endobj\n"
    )

    header = b"%PDF-1.4\n"
    body = b""
    offsets: list[int] = []
    pos = len(header)
    for obj in objects:
        offsets.append(pos)
        body += obj
        pos += len(obj)

    xref_pos = len(header) + len(body)
    xref = b"xref\n"
    xref += f"0 {len(objects) + 1}\n".encode()
    xref += b"0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()

    trailer = (
        b"trailer\n"
        b"<< /Size "
        + str(len(objects) + 1).encode()
        + b" /Root 1 0 R >>\n"
        b"startxref\n"
        + str(xref_pos).encode()
        + b"\n%%EOF\n"
    )

    return header + body + xref + trailer


def _build_narrative(target_ip: str, sessions: list, attacks: list, annotations: list) -> list[str]:
    """룰 기반 자동 내러티브 문장 생성 (LLM 없음)."""
    lines = []

    # 분석 기간
    ts_list = [s.get("start_ts", 0) if isinstance(s, dict) else getattr(s, "start_ts", 0) for s in sessions]
    if ts_list:
        t_start = min(ts_list)
        t_end = max(ts_list)
        duration_s = max(int(t_end - t_start), 1)
        start_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t_start))
        lines += [
            f"Analysis Period: {start_str}  (duration: {duration_s}s)",
            f"Target IP: {target_ip}",
            f"Total Sessions: {len(sessions)}",
        ]
    else:
        lines += [f"Target IP: {target_ip}", f"Total Sessions: {len(sessions)}"]

    # 트래픽 요약 — 상위 통신 쌍
    pair_bytes: dict[tuple, int] = {}
    for s in sessions:
        src = s.get("src_ip") if isinstance(s, dict) else getattr(s, "src_ip", "?")
        dst = s.get("dst_ip") if isinstance(s, dict) else getattr(s, "dst_ip", "?")
        byt = (s.get("bytes_sent", 0) + s.get("bytes_recv", 0)) if isinstance(s, dict) else (getattr(s, "bytes_sent", 0) + getattr(s, "bytes_recv", 0))
        pair_bytes[(src, dst)] = pair_bytes.get((src, dst), 0) + byt
    if pair_bytes:
        top_pair = max(pair_bytes, key=lambda k: pair_bytes[k])
        top_bytes = pair_bytes[top_pair]
        lines.append(f"Top Flow: {top_pair[0]} -> {top_pair[1]}  ({top_bytes:,} bytes)")

    # 공격 탐지 내러티브
    lines += ["", "=== THREAT ASSESSMENT ==="]
    if not attacks:
        lines.append("No attack patterns detected.")
    else:
        for atk in attacks:
            atype = atk.get("attack_type", atk.get("type", "Unknown"))
            sev = atk.get("severity", "?").upper()
            mitre = atk.get("mitre_id", "")
            desc = atk.get("description", "")
            lines.append(f"[{sev}] {atype} ({mitre})")
            if desc:
                lines.append(f"  Detail: {desc[:120]}")

    # 마커/코멘트 (있으면)
    if annotations:
        lines += ["", "=== TIMELINE EVENTS ==="]
        for ann in annotations:
            t0 = ann.get("start_ts", 0)
            t1 = ann.get("end_ts", 0)
            comment = ann.get("comment", "")
            t0_str = time.strftime("%H:%M:%S", time.gmtime(t0))
            t1_str = time.strftime("%H:%M:%S", time.gmtime(t1))
            lines.append(f"  [{t0_str} - {t1_str}] {comment}")

    return lines


class PdfExporter:
    def generate(self, analysis_result: dict, output_path: Path | None = None) -> Path:
        target_ip = analysis_result.get("target_ip", "unknown")
        sessions = analysis_result.get("sessions", [])
        attacks = analysis_result.get("attacks", [])
        annotations = analysis_result.get("annotations", [])

        # Executive Summary — 자동 내러티브
        lines = [
            "WireBoard v5.0 — Analysis Report",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "=" * 60,
            "",
            "=== EXECUTIVE SUMMARY ===",
        ]
        lines += _build_narrative(target_ip, sessions, attacks, annotations)

        # 기술 상세 — 세션 TOP 10
        lines += ["", "=== TOP 10 SESSIONS (by bytes) ==="]
        sorted_sessions = sorted(
            sessions,
            key=lambda s: (s.get("bytes_sent", 0) + s.get("bytes_recv", 0)) if isinstance(s, dict)
                          else (getattr(s, "bytes_sent", 0) + getattr(s, "bytes_recv", 0)),
            reverse=True,
        )[:10]
        for s in sorted_sessions:
            src = s.get("src_ip") if isinstance(s, dict) else getattr(s, "src_ip", "?")
            dst = s.get("dst_ip") if isinstance(s, dict) else getattr(s, "dst_ip", "?")
            dport = s.get("dst_port") if isinstance(s, dict) else getattr(s, "dst_port", 0)
            proto = s.get("protocol") if isinstance(s, dict) else getattr(s, "protocol", "?")
            byt = (s.get("bytes_sent", 0) + s.get("bytes_recv", 0)) if isinstance(s, dict) else (getattr(s, "bytes_sent", 0) + getattr(s, "bytes_recv", 0))
            lines.append(f"  {src} -> {dst}:{dport} [{proto}]  {byt:,} bytes")

        pdf_bytes = _build_pdf(lines)

        if output_path is None:
            tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
            output_path = Path(tmp.name)
            tmp.close()

        output_path = Path(output_path)
        output_path.write_bytes(pdf_bytes)
        return output_path
