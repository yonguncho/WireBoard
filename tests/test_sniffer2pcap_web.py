"""sniffer2pcap 웹 변환기 검증 (pytest 형식).

픽스처: tests/fixtures/sniffer2pcap/ (gen_fixtures.py 로 재생성 가능)
- 픽스처마다 node cli.mjs 로 변환 → tshark 로 열어 패킷 수·시각·주소·링크타입·캡처길이 대조
- tshark 가 malformed 로 표시한 패킷 0개
- 기존 WireBoard 변환기(raw_pcap_converter.py)와 IP 계층 바이트·시각 동일성 비교
실행: python -m pytest tests/test_sniffer2pcap_web.py -q   (node 없으면 skip, tshark 없으면 해당 테스트 skip)
"""
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "web" / "sniffer2pcap"
CASES = Path(__file__).resolve().parent / "fixtures" / "sniffer2pcap"
TSHARK = shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"
NODE = shutil.which("node")

sys.path.insert(0, str(ROOT / "backend"))

pytestmark = pytest.mark.skipif(not NODE, reason="node not installed")
CASE_NAMES = sorted(p.stem for p in CASES.glob("*.txt"))


def convert(case: str, tmp: Path) -> dict:
    out = tmp / case
    r = subprocess.run([NODE, str(TOOL / "cli.mjs"), str(CASES / f"{case}.txt"), str(out)],
                       capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    res = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    res["dir"] = out
    return res


def read_pcap(path: Path):
    """(linktype, [(sec, usec, caplen, wirelen, data)])"""
    b = path.read_bytes()
    magic, _, _, _, _, _, lt = struct.unpack_from("<IHHiIII", b, 0)
    assert magic == 0xA1B2C3D4
    recs, o = [], 24
    while o < len(b):
        sec, usec, cap, wire = struct.unpack_from("<IIII", b, o)
        o += 16
        recs.append((sec, usec, cap, wire, b[o:o + cap]))
        o += cap
    return lt, recs


def tshark_fields(path: Path):
    if not Path(TSHARK).exists():
        pytest.skip("tshark not installed")
    r = subprocess.run([TSHARK, "-r", str(path), "-T", "fields", "-E", "separator=|",
                        "-e", "frame.time_epoch", "-e", "frame.cap_len", "-e", "frame.len",
                        "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst",
                        "-e", "frame.protocols", "-e", "_ws.malformed", "-e", "_ws.expert.message"],
                       capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    rows = []
    for line in r.stdout.splitlines():
        t, cap, ln, s4, d4, s6, d6, protos, malformed, expert = (line.split("|") + [""] * 10)[:10]
        rows.append({"time": t, "cap": int(cap), "len": int(ln), "src": s4 or s6 or None,
                     "dst": d4 or d6 or None, "protos": protos, "malformed": bool(malformed), "expert": expert})
    return rows


def ip_bytes(lt: int, data: bytes) -> bytes:
    if lt == 101:
        return data
    o = 12
    et = int.from_bytes(data[12:14], "big")
    while et in (0x8100, 0x88A8):
        o += 4
        et = int.from_bytes(data[o:o + 2], "big")
    return data[o + 2:] if et in (0x0800, 0x86DD) else b""


@pytest.mark.parametrize("case", CASE_NAMES)
def test_packets_match_expected_in_tshark(case, tmp_path):
    exp = json.loads((CASES / f"{case}.expected.json").read_text(encoding="utf-8"))
    res = convert(case, tmp_path)
    s = res["summary"]

    if not exp["packets"]:
        assert s["packets"] == 0 and res["files"] == []
        assert exp["expect_message"] in s["message"]
        return

    assert s["packets"] == len(exp["packets"])
    assert [i["name"] for i in s["interfaces"]] == exp["interfaces"]
    if "truncated" in exp:
        assert s["truncatedPackets"] == exp["truncated"]
    if "min_failed_lines" in exp:
        assert s["failedLines"] >= exp["min_failed_lines"]
    else:
        assert s["failedLines"] == 0, s["failureExamples"]

    combined = res["files"][0]
    assert combined["iface"] is None and combined["linktype"] == exp["linktype"]
    assert combined["dropped"] == exp.get("combined_dropped", 0)

    rows = tshark_fields(res["dir"] / combined["name"])
    want = [p for p in exp["packets"] if exp["linktype"] == 1 or p["is_ip"]]
    assert len(rows) == len(want)
    for row, p in zip(rows, want):
        assert abs(float(row["time"]) - float(p["time"])) < 1e-6, (row, p)
        if p["is_ip"]:
            assert (row["src"], row["dst"]) == (p["src"], p["dst"])
            assert "ip" in row["protos"].split(":") or "ipv6" in row["protos"].split(":")
        if exp["linktype"] == 1:
            assert row["protos"].startswith("eth:")
            if p.get("cap_len"):
                assert row["cap"] == p["cap_len"]
        else:
            assert row["protos"].startswith("raw:")
        if p.get("truncated"):
            assert row["len"] > row["cap"]
        else:
            assert row["len"] == row["cap"]
            assert not row["malformed"], row

    for iface, lt in exp.get("iface_linktypes", {}).items():
        f = next(f for f in res["files"] if f["iface"] == iface)
        assert f["linktype"] == lt
        assert f["packets"] == sum(1 for p in exp["packets"] if p["iface"] == iface)
        rows = tshark_fields(res["dir"] / f["name"])
        assert len(rows) == f["packets"]
        assert all(not r["malformed"] for r in rows)


@pytest.mark.parametrize("case", [c for c in CASE_NAMES
                                  if json.loads((CASES / f"{c}.expected.json").read_text(encoding="utf-8")).get("compare_legacy")])
def test_same_ip_payload_and_time_as_legacy_converter(case, tmp_path):
    from services.parser.raw_pcap_converter import convert_raw_log_to_pcap

    res = convert(case, tmp_path)
    legacy = convert_raw_log_to_pcap((CASES / f"{case}.txt").read_bytes())
    assert legacy is not None
    leg_path = tmp_path / "legacy.pcap"
    leg_path.write_bytes(legacy[0])
    l_lt, l_recs = read_pcap(leg_path)
    n_lt, n_recs = read_pcap(res["dir"] / res["files"][0]["name"])

    legacy_ip = [((s, u), ip_bytes(l_lt, d)) for s, u, _, _, d in l_recs]
    new_ip = [((s, u), ip_bytes(n_lt, d)) for s, u, _, _, d in n_recs]
    # 비IP(ARP)는 비교 대상에서 제외 (RAW 출력엔 들어갈 수 없음)
    legacy_ip = [x for x in legacy_ip if x[1]]
    new_ip = [x for x in new_ip if x[1]]
    assert new_ip == legacy_ip


def _convert_text(tmp_path, text: str, name="t", newline="\n"):
    p = tmp_path / f"{name}.txt"
    p.write_bytes(text.replace("\n", newline).encode())
    out = tmp_path / f"out_{name}"
    r = subprocess.run([NODE, str(TOOL / "cli.mjs"), str(p), str(out)], capture_output=True, text=True,
                       encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads((out / "summary.json").read_text(encoding="utf-8")), out


def test_cr_only_line_endings(tmp_path):
    src = (CASES / "v6_abs.txt").read_text(encoding="utf-8")
    s, _ = _convert_text(tmp_path, src, "cr", "\r")
    assert s["summary"]["packets"] == json.loads((CASES / "v6_abs.expected.json").read_text())["packets"].__len__()


def test_tabs_collapsed_to_single_space_do_not_add_phantom_bytes(tmp_path):
    # 마지막 줄 3그룹(6바이트) 뒤 ASCII 열이 공백 1칸으로 붙은 경우: "ab cd" 를 바이트로 읽으면 안 됨
    text = ("2026-10-29 01:02:03.000000 port1 in 10.0.0.1.1 -> 10.0.0.2.2: syn 1\n"
            "0x0000 0009 0f09 0b02 0050 56a5 6e3f 0800 4500 .......PV.n?..E.\n"
            "0x0010 0028 0001 0000 4006 66c1 0a00 0001 0a00 .(....@.f.......\n"
            "0x0020 0002 04d2 0050 0000 0000 0000 0000 5002 .....P........P.\n"
            "0x0030 2000 8b9f 0000 ab cd\n")
    s, out = _convert_text(tmp_path, text, "phantom")
    _, recs = read_pcap(out / s["files"][0]["name"])
    assert recs[0][2] == 54


def test_raw_ip_with_ethertype_lookalike_without_command_line(tmp_path):
    # verbose 5 로그를 명령줄 없이 붙여넣음 + src 8.0.69.1 (bytes 12-13 = 0x0800)
    from scapy.all import IP, TCP
    def block(src, t):
        b = bytes(IP(src=src, dst="10.0.0.2", id=1) / TCP(sport=1234, dport=80, flags="S"))
        lines = [f"2026-10-29 01:02:0{t}.000000 port1 in {src}.1234 -> 10.0.0.2.80: syn 0"]
        for off in range(0, len(b), 16):
            ch = b[off:off + 16]
            lines.append(f"0x{off:04x}\t " + " ".join(ch[i:i + 2].hex() for i in range(0, len(ch), 2)) + "\t.")
        return "\n".join(lines)
    text = "\n".join([block("10.0.0.1", 1), block("8.0.69.1", 2), block("10.0.0.3", 3)]) + "\n"
    s, out = _convert_text(tmp_path, text, "lookalike")
    assert s["files"][0]["linktype"] == 101
    rows = tshark_fields(out / s["files"][0]["name"])
    assert [r["src"] for r in rows] == ["10.0.0.1", "8.0.69.1", "10.0.0.3"]


def test_relative_timestamps_with_base_time(tmp_path):
    out = tmp_path / "rel"
    r = subprocess.run([NODE, str(TOOL / "cli.mjs"), str(CASES / "v6_rel.txt"), str(out), "--base-time", "1793235723"],
                       capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    res = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    _, recs = read_pcap(out / res["files"][0]["name"])
    assert recs[0][0] == 1793235723 and recs[0][1] == 0
    assert recs[-1][0] - recs[0][0] == 1  # 마지막 패킷 +1.38s

