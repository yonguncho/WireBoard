"""PdfExporter — 분석 결과 PDF 리포트 생성 (외부 라이브러리 없음)."""
import tempfile
import time
import unicodedata
from pathlib import Path

from utils.constants import APP_VERSION

_UNICODE_ASCII_MAP = {
    "→": "->", "←": "<-", "↑": "^", "↓": "v", "⇒": "=>", "⇐": "<=",
    "…": "...", "–": "-", "—": "--", "•": "*", "·": ".", "×": "x",
}


def _pdf_escape(text: str) -> str:
    for k, v in _UNICODE_ASCII_MAP.items():
        text = text.replace(k, v)
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


_LINES_PER_PAGE = 50  # y: 750 → 50, 14pt 간격
_MAX_PAGES = 20       # 안전 상한 (세션 수천 개 덤프 방지)


def _build_pdf(lines: list[str]) -> tuple[bytes, bool]:
    """최소한의 유효한 PDF (PDF 1.4, Type1 Helvetica) — 멀티페이지 지원.

    Returns (pdf_bytes, truncated) — truncated=True 이면 _MAX_PAGES 초과로 잘렸음.
    (기존 단일 페이지 51줄 절단 → 페이지네이션으로 교체: 위험 요약 블록이
    THREAT ASSESSMENT / TOP 10 SESSIONS 를 밀어내지 않는다.)
    """
    # 줄들을 페이지 단위로 분할
    pages_lines = [lines[i:i + _LINES_PER_PAGE]
                   for i in range(0, max(len(lines), 1), _LINES_PER_PAGE)]
    truncated = len(pages_lines) > _MAX_PAGES
    pages_lines = pages_lines[:_MAX_PAGES]

    # 오브젝트 번호: 1=Catalog, 2=Pages, 3=Font, 이후 페이지당 (Page, Contents) 쌍
    n_pages = len(pages_lines)
    page_ids = [4 + 2 * i for i in range(n_pages)]

    objects: list[bytes] = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects.append(
        f"2 0 obj\n<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>\nendobj\n".encode()
    )
    objects.append(
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    )

    for i, page in enumerate(pages_lines):
        pid = page_ids[i]
        cid = pid + 1
        text_ops = []
        y = 750
        for line in page:
            safe = _pdf_escape(line[:100])
            text_ops.append(f"BT /F1 10 Tf 50 {y} Td ({safe}) Tj ET")
            y -= 14
        stream_bytes = "\n".join(text_ops).encode("latin-1", errors="replace")
        objects.append(
            (f"{pid} 0 obj\n"
             f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
             f"   /Contents {cid} 0 R /Resources << /Font << /F1 3 0 R >> >> >>\n"
             f"endobj\n").encode()
        )
        objects.append(
            f"{cid} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode()
            + stream_bytes
            + b"\nendstream\nendobj\n"
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

    return header + body + xref + trailer, truncated


def _build_narrative(target_ip: str, sessions: list, attacks: list, annotations: list) -> list[str]:
    """룰 기반 자동 내러티브 문장 생성 (LLM 없음)."""
    lines = []

    # 분석 기간
    start_ts_list = [s.get("start_ts", 0) if isinstance(s, dict) else getattr(s, "start_ts", 0) for s in sessions]
    end_ts_list = [s.get("end_ts", 0) if isinstance(s, dict) else getattr(s, "end_ts", 0) for s in sessions]
    if start_ts_list:
        t_start = min(start_ts_list)
        t_end = max(end_ts_list)
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
    def generate(self, analysis_result: dict, output_path: Path | None = None) -> tuple[Path, bool]:
        target_ip = analysis_result.get("target_ip", "unknown")
        sessions = analysis_result.get("sessions", [])
        attacks = analysis_result.get("attacks", [])
        annotations = analysis_result.get("annotations", [])

        risk = analysis_result.get("risk") or {}

        # Executive Summary — 자동 내러티브
        lines = [
            f"WireBoard {APP_VERSION} - Analysis Report",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "=" * 60,
            "",
            "=== EXECUTIVE SUMMARY ===",
        ]

        # Risk grade block (English) — driven by the summary builder when available
        if risk:
            grade = risk.get("risk_level", "UNKNOWN")
            score = risk.get("risk_score", 0)
            lines.append(f"Risk Grade: {grade}  (score {score}/100)")
            headline = risk.get("headline", "")
            if headline:
                lines.append(f"Verdict: {headline}")
            factors = risk.get("risk_factors", [])
            if factors:
                lines.append("Why this grade:")
                for f in factors[:6]:
                    lines.append(f"  - {f.get('factor', '')} (+{f.get('points', 0)}): {f.get('detail', '')}")
            diagnosis = risk.get("diagnosis", [])
            if diagnosis:
                lines.append("Connectivity diagnosis:")
                for d in diagnosis[:8]:
                    lines.append(f"  - {d}")
            recs = risk.get("recommendations", [])
            if recs:
                lines.append("Recommended actions:")
                for rec in recs[:6]:
                    lines.append(f"  - {rec}")
            lines.append("")

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

        pdf_bytes, truncated = _build_pdf(lines)

        if output_path is None:
            tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
            tmp_path = Path(tmp.name)
            tmp.close()
            try:
                tmp_path.write_bytes(pdf_bytes)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
            return tmp_path, truncated

        output_path = Path(output_path)
        output_path.write_bytes(pdf_bytes)
        return output_path, truncated
