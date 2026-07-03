"""TCP Expert Info — Wireshark식 흐름 분석 (재전송·dup-ack·zero-window 등).

dpkt가 넘겨준 per-flow PacketRecord 리스트를 방향별 상태머신으로 훑어
Wireshark의 "TCP analysis" 플래그를 재현한다. 각 패킷에 태그를 달고
흐름·전체 단위 요약을 만든다.

한계(솔직히): 캡처 유실 vs 실제 손실은 완벽히 구분 불가하고, window scale
옵션을 파서가 아직 저장하지 않으므로 zero-window는 raw window==0 기준이다.
그래도 NOC 트리아지의 핵심 신호(손실·수신정체·순서역전)는 잡는다.
"""
from __future__ import annotations

from collections import defaultdict

# Expert 태그 → (severity, 설명). severity: error > warn > note > chat
_TAG_META = {
    "retransmission":     ("note", "Retransmission — segment with a previously-seen sequence number"),
    "out_of_order":       ("warn", "Out-of-order segment — sequence number lower than already seen"),
    "lost_segment":       ("warn", "Previous segment not captured — sequence gap detected"),
    "duplicate_ack":      ("note", "Duplicate ACK — same ACK number repeated with no new data"),
    "zero_window":        ("warn", "Zero window — receiver advertised window 0 (receive buffer full)"),
    "window_full":        ("note", "Window update after zero window"),
    "keep_alive":         ("note", "Keep-alive probe"),
    "reset":              ("warn", "Connection reset (RST)"),
}

_SEV_RANK = {"error": 3, "warn": 2, "note": 1, "chat": 0}

_DUP_ACK_MIN = 1  # 같은 ACK가 이 횟수만큼 '추가로' 반복되면 dup-ack


def _has(flags: str, name: str) -> bool:
    return name in (flags or "").upper()


def analyze_flow(packets: list) -> dict:
    """한 flow(세션)의 패킷들에 Expert 태그를 부여하고 요약을 만든다.

    Returns {
      "events": [ {index, tags:[...], top: str} ... ]  # 패킷 순서와 1:1
      "summary": { tag: count, ... }
      "worst": "error|warn|note|none"
    }
    """
    events: list[dict] = [{"index": i, "tags": [], "top": ""} for i in range(len(packets))]
    summary: dict = defaultdict(int)

    # 방향별 상태
    max_seq_end: dict[str, int] = {}          # 방향별 지금까지 본 최대 (seq+payload)
    seen_seq: dict[str, set] = defaultdict(set)  # 방향별 (payload>0) seq 집합
    last_ack: dict[str, int] = {}             # 방향별 직전 ACK 값
    dup_ack_run: dict[str, int] = defaultdict(int)
    zero_win_open: dict[str, bool] = defaultdict(bool)

    for i, p in enumerate(packets):
        tags: list[str] = []
        d = p.direction
        proto = getattr(p, "proto", "")
        flags = getattr(p, "flags", "")

        if _has(flags, "RST"):
            tags.append("reset")

        if proto == "TCP":
            payload = getattr(p, "payload_len", 0)
            seq = getattr(p, "seq", 0)
            ack = getattr(p, "ack", 0)
            win = getattr(p, "window", 0)

            # zero window (수신 버퍼 포화) — SYN 제외(초기 win 협상)
            if win == 0 and not _has(flags, "SYN") and not _has(flags, "RST"):
                tags.append("zero_window")
                zero_win_open[d] = True
            elif zero_win_open.get(d) and win > 0:
                tags.append("window_full")
                zero_win_open[d] = False

            if payload > 0:
                seq_end = seq + payload
                prev_max = max_seq_end.get(d)
                if seq in seen_seq[d]:
                    tags.append("retransmission")
                elif prev_max is not None and seq < prev_max:
                    tags.append("out_of_order")
                elif prev_max is not None and seq > prev_max:
                    # 기대 seq보다 앞선 데이터 → 이전 세그먼트 미포착
                    tags.append("lost_segment")
                seen_seq[d].add(seq)
                if prev_max is None or seq_end > prev_max:
                    max_seq_end[d] = seq_end
            else:
                # 순수 ACK (payload 0) — dup-ack / keep-alive 판정
                if _has(flags, "ACK") and not _has(flags, "SYN") and not _has(flags, "FIN"):
                    if last_ack.get(d) == ack and ack != 0:
                        dup_ack_run[d] += 1
                        if dup_ack_run[d] >= _DUP_ACK_MIN:
                            tags.append("duplicate_ack")
                    else:
                        dup_ack_run[d] = 0
                    last_ack[d] = ack

        for t in tags:
            summary[t] += 1
        # 대표 태그(가장 심각한 것)
        top = ""
        if tags:
            top = max(tags, key=lambda t: _SEV_RANK.get(_TAG_META.get(t, ("chat",))[0], 0))
        events[i]["tags"] = tags
        events[i]["top"] = top

    worst = "none"
    worst_rank = -1
    for t in summary:
        sev = _TAG_META.get(t, ("chat",))[0]
        if _SEV_RANK.get(sev, 0) > worst_rank:
            worst_rank = _SEV_RANK.get(sev, 0)
            worst = sev
    return {"events": events, "summary": dict(summary), "worst": worst}


def aggregate(packet_map: dict) -> dict:
    """전체 캡처의 Expert Info 요약 (Wireshark Expert Information 카드 재현)."""
    totals: dict = defaultdict(int)
    flows_with_issue = 0
    for pkts in packet_map.values():
        r = analyze_flow(pkts)
        if r["summary"]:
            flows_with_issue += 1
        for t, c in r["summary"].items():
            totals[t] += c

    # severity 버킷으로 묶어서 반환
    by_severity: dict = {"error": [], "warn": [], "note": [], "chat": []}
    for t, c in sorted(totals.items(), key=lambda x: -x[1]):
        sev, desc = _TAG_META.get(t, ("chat", t))
        by_severity[sev].append({"tag": t, "count": c, "description": desc})

    return {
        "totals": dict(totals),
        "by_severity": by_severity,
        "flows_with_issues": flows_with_issue,
        "retransmission": totals.get("retransmission", 0),
        "duplicate_ack": totals.get("duplicate_ack", 0),
        "zero_window": totals.get("zero_window", 0),
        "out_of_order": totals.get("out_of_order", 0),
        "lost_segment": totals.get("lost_segment", 0),
    }
