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


class PdfExporter:
    def generate(self, analysis_result: dict, output_path: Path | None = None) -> Path:
        target_ip = analysis_result.get("target_ip", "unknown")
        sessions = analysis_result.get("sessions", [])
        attacks = analysis_result.get("attacks", [])
        summary = analysis_result.get("summary", {})

        lines = [
            "WireBoard Analysis Report",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "",
            f"Target IP: {target_ip}",
            f"Total Sessions: {summary.get('total_sessions', len(sessions))}",
            f"Total Bytes: {summary.get('total_bytes', 0)}",
            "",
            "--- Attack Detection ---",
        ]
        if attacks:
            for atk in attacks:
                lines.append(
                    f"  [{atk.get('severity', '?').upper()}] "
                    f"{atk.get('type', atk.get('attack_type', '?'))} "
                    f"({atk.get('mitre_id', '')})"
                )
        else:
            lines.append("  No attacks detected.")

        lines += [
            "",
            "--- Session Summary ---",
            f"  Sessions analysed: {len(sessions)}",
        ]

        pdf_bytes = _build_pdf(lines)

        if output_path is None:
            tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
            output_path = Path(tmp.name)
            tmp.close()

        output_path = Path(output_path)
        output_path.write_bytes(pdf_bytes)
        return output_path
