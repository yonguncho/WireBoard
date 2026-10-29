"""FortiGate sniffer 출력 형식 테스트 픽스처 생성기.

실장비 로그가 아니라, scapy 로 만든 실제 패킷 바이트(체크섬 유효)를
FortiOS `diagnose sniffer packet` 출력 형식 그대로 렌더링한 것이다.
IP 는 문서용 대역(RFC 5737 / 3849)과 사설 대역만 쓴다 = 마스킹 불필요.

각 픽스처마다 <name>.expected.json 에 정답(패킷 수·시각·주소·링크타입)을 같이 쓴다.

실행: python -I tests/fixtures/sniffer2pcap/gen_fixtures.py   (인자 없으면 이 폴더에 다시 생성)
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Dot1Q, Ether, Raw

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
T0 = datetime(2026, 10, 29, 1, 2, 3, tzinfo=timezone.utc).timestamp()

MAC_FGT = "00:09:0f:09:0b:02"
MAC_PC = "00:50:56:a5:6e:3f"
MAC_GW = "e8:b5:d0:fb:c0:38"


def conversation():
    """(상대시각, iface, dir, 이더넷 프레임, 헤더 설명) 목록."""
    pc, srv, dns = "10.1.1.10", "198.51.100.20", "192.0.2.53"
    pkts = []
    t = 0.0

    def add(dt, iface, d, frame, desc):
        nonlocal t
        t += dt
        pkts.append((round(t, 6), iface, d, frame, desc))

    add(0.000000, "port1", "in", Ether(src=MAC_PC, dst=MAC_FGT) / ARP(op=1, psrc=pc, pdst="10.1.1.1"),
        "arp who-has 10.1.1.1 tell 10.1.1.10")
    add(0.000112, "port1", "in", Ether(src=MAC_PC, dst=MAC_FGT) / IP(src=pc, dst=dns, id=1) / UDP(sport=53001, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        f"{pc}.53001 -> {dns}.53: udp 29")
    add(0.000420, "port2", "out", Ether(src=MAC_FGT, dst=MAC_GW) / IP(src="203.0.113.5", dst=dns, id=2) / UDP(sport=53001, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        f"203.0.113.5.53001 -> {dns}.53: udp 29")
    seq_c, seq_s = 1000, 5000
    add(0.010100, "port1", "in", Ether(src=MAC_PC, dst=MAC_FGT) / IP(src=pc, dst=srv, id=3) / TCP(sport=51000, dport=443, flags="S", seq=seq_c, options=[("MSS", 1460)]),
        f"{pc}.51000 -> {srv}.443: syn {seq_c}")
    add(0.000050, "port2", "out", Ether(src=MAC_FGT, dst=MAC_GW) / IP(src="203.0.113.5", dst=srv, id=4) / TCP(sport=51000, dport=443, flags="S", seq=seq_c, options=[("MSS", 1460)]),
        f"203.0.113.5.51000 -> {srv}.443: syn {seq_c}")
    add(0.020300, "port2", "in", Ether(src=MAC_GW, dst=MAC_FGT) / IP(src=srv, dst="203.0.113.5", id=5) / TCP(sport=443, dport=51000, flags="SA", seq=seq_s, ack=seq_c + 1),
        f"{srv}.443 -> 203.0.113.5.51000: syn {seq_s} ack {seq_c + 1}")
    add(0.000040, "port1", "out", Ether(src=MAC_FGT, dst=MAC_PC) / IP(src=srv, dst=pc, id=6) / TCP(sport=443, dport=51000, flags="SA", seq=seq_s, ack=seq_c + 1),
        f"{srv}.443 -> {pc}.51000: syn {seq_s} ack {seq_c + 1}")
    add(0.000300, "port1", "in", Ether(src=MAC_PC, dst=MAC_FGT) / IP(src=pc, dst=srv, id=7) / TCP(sport=51000, dport=443, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(b"\x16\x03\x01" + bytes(range(64))),
        f"{pc}.51000 -> {srv}.443: psh {seq_c + 1} ack {seq_s + 1}")
    add(0.100000, "port1", "in", Ether(src=MAC_PC, dst=MAC_FGT) / Dot1Q(vlan=20) / IP(src="10.20.0.7", dst=pc, id=8) / ICMP(type=8, id=1, seq=1) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi"),
        "10.20.0.7 -> 10.1.1.10: icmp: echo request")
    add(0.000600, "port1", "out", Ether(src=MAC_FGT, dst=MAC_PC) / IPv6(src="2001:db8::10", dst="2001:db8::1") / UDP(sport=546, dport=547) / Raw(b"\x01" * 12),
        "2001:db8::10.546 -> 2001:db8::1.547: udp 12")
    add(1.250000, "port1", "in", Ether(src=MAC_PC, dst=MAC_FGT) / IP(src=pc, dst=srv, id=9) / TCP(sport=51000, dport=443, flags="FA", seq=seq_c + 68, ack=seq_s + 1),
        f"{pc}.51000 -> {srv}.443: fin {seq_c + 68} ack {seq_s + 1}")
    return pkts


def hex_lines(data: bytes, style: str) -> list[str]:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        groups = " ".join(chunk[i:i + 2].hex() for i in range(0, len(chunk), 2))
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        if style == "tab":
            lines.append(f"0x{off:04x}\t {groups:<39}\t{asc}")
        else:
            lines.append(f"0x{off:04x}   {groups:<39}        {asc}")
    return lines


def ts_str(rel: float, mode: str) -> str:
    if mode == "rel":
        return f"{rel:.6f}"
    dt = datetime.fromtimestamp(T0 + rel, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def _exp(rel, mode, iface, frame, cap_len):
    base = T0 if mode == "abs" else 0.0
    ip = frame[IP] if frame.haslayer(IP) else frame[IPv6] if frame.haslayer(IPv6) else None
    return {
        "time": f"{base + rel:.6f}",
        "iface": iface,
        "src": ip.src if ip is not None else None,
        "dst": ip.dst if ip is not None else None,
        "cap_len": cap_len,
        "is_ip": ip is not None,
    }


def render(pkts, *, verbose: int, mode: str, style: str = "tab"):
    """FortiGate 출력 줄 목록과 정답 레코드 목록을 만든다."""
    lines, expected = [], []
    with_iface = verbose >= 4
    ip_only = verbose in (2, 5)
    for rel, iface, d, frame, desc in pkts:
        prefix = f"{ts_str(rel, mode)} " + (f"{iface} {d} " if with_iface else "")
        lines.append(prefix + desc)
        if verbose in (1, 4):
            continue
        raw = bytes(frame)
        if ip_only:
            if not (frame.haslayer(IP) or frame.haslayer(IPv6)):
                continue  # verbose 2/5 는 비IP(ARP)를 hex 없이 헤더만 찍는다고 가정
            raw = bytes(frame[IP] if frame.haslayer(IP) else frame[IPv6])
        lines += hex_lines(raw, style)
        expected.append(_exp(rel, mode, iface if with_iface else None, frame, len(raw)))
    return lines, expected


def write(name, lines, expected, linktype, extra=None, *, crlf=False, encoding="utf-8"):
    OUT.mkdir(parents=True, exist_ok=True)
    nl = "\r\n" if crlf else "\n"
    data = nl.join(lines) + nl
    blob = b"\xff\xfe" + data.encode("utf-16-le") if encoding == "utf-16" else data.encode(encoding)
    (OUT / f"{name}.txt").write_bytes(blob)
    exp = {"linktype": linktype, "packets": expected}
    exp.update(extra or {})
    (OUT / f"{name}.expected.json").write_text(json.dumps(exp, indent=2), encoding="utf-8")


def footer(n):
    return ["", f"{n} packets received by filter", "0 packets dropped by kernel"]


def main():
    pkts = conversation()

    body, exp = render(pkts, verbose=6, mode="abs", style="spaces")
    write("v6_abs", ["FGT60F # diagnose sniffer packet any 'net 10.1.1.0/24 or host 198.51.100.20' 6 0 a",
                     "interfaces=[any]", "filters=[net 10.1.1.0/24 or host 198.51.100.20]"] + body + footer(len(exp)),
          exp, 1, {"interfaces": ["port1", "port2"], "compare_legacy": True})

    body, exp = render(pkts, verbose=6, mode="rel", style="tab")
    write("v6_rel", ["FGT60F # diag sniffer packet any none 6 0", "interfaces=[any]", "filters=[none]"] + body + footer(len(exp)),
          exp, 1, {"interfaces": ["port1", "port2"]})

    body, exp = render(pkts, verbose=3, mode="abs", style="tab")
    write("v3_abs", ["FGT60F # diagnose sniffer packet any none 3 0 a"] + body + footer(len(exp)),
          exp, 1, {"interfaces": [], "compare_legacy": True})

    body, exp = render(pkts, verbose=5, mode="abs", style="tab")
    write("v5_ip_abs", ["FGT60F # diagnose sniffer packet any none 5 0 a"] + body + footer(len(exp)),
          exp, 101, {"interfaces": ["port1", "port2"], "compare_legacy": True})

    body, _ = render(pkts, verbose=4, mode="abs")
    write("v4_headers_only", ["FGT60F # diagnose sniffer packet any none 4 0 a"] + body + footer(len(pkts)),
          [], None, {"expect_message": "verbose level 4"})

    # 이더넷 포트 + IPsec 터널(이더넷 헤더 없음) 혼재
    items = list(pkts[:6]) + [(rel + 0.000001, "vpn_hq", d, f, desc) for rel, iface, d, f, desc in pkts if iface == "port2"]
    mixed_body, mixed_exp = [], []
    for item in sorted(items, key=lambda x: x[0]):
        rel, iface, d, frame, desc = item
        if iface == "vpn_hq":
            ipb = bytes(frame[IP])
            mixed_body.append(f"{ts_str(rel, 'abs')} {iface} {d} {desc}")
            mixed_body += hex_lines(ipb, "tab")
            mixed_exp.append(_exp(rel, "abs", iface, frame, len(ipb)))
        else:
            l, e = render([item], verbose=6, mode="abs")
            mixed_body += l
            mixed_exp += e
    write("v6_mixed_tunnel", ["FGT60F # diagnose sniffer packet any none 6 0 a"] + mixed_body + footer(len(mixed_exp)),
          mixed_exp, 101, {"interfaces": ["port1", "port2", "vpn_hq"],
                           "iface_linktypes": {"port1": 1, "port2": 1, "vpn_hq": 101},
                           "combined_dropped": 1})  # ARP 는 RAW IP 통합 파일에 못 들어감

    # 터미널 로그 잡음: PuTTY 헤더, CRLF, ANSI, SecureCRT 줄 타임스탬프, 중간에 시작, 줄 유실, 끝 잘림
    body, exp = render(pkts, verbose=6, mode="abs", style="tab")
    noisy = ["=~=~=~=~=~=~=~=~=~=~=~= PuTTY log 2026.10.29 10:02:00 =~=~=~=~=~=~=~=~=~=~=~=",
             "0x0020\t 50a3 dcb5 3e1e fce1 dd8f 0000 0000 8002\tP...>...........",  # 이전 패킷 꼬리
             "0x0030\t faf0 1dd9 0000 0204 05b4 0103 0308 0101\t................",
             "\x1b[1mFGT60F # \x1b[0mdiagnose sniffer packet any 'host 10.1.1.10' 6 0 a",
             "interfaces=[any]", "filters=[host 10.1.1.10]"]
    blocks, cur = [], []
    for ln in body:
        if not ln.startswith("0x") and cur:
            blocks.append(cur)
            cur = []
        cur.append(ln)
    blocks.append(cur)
    kept = []
    for i, blk in enumerate(blocks):
        if i == 4:      # 중간 hex 줄 유실 → 이 패킷은 버려져야 함
            noisy += blk[:2] + blk[3:] + [""]
            continue
        if i == 6:      # 블록 안 알 수 없는 줄(ASCII 열 줄바꿈 잔해)
            blk = blk[:2] + ["..E.....@.@....."] + blk[2:]
        if i % 3 == 1:  # SecureCRT 줄 타임스탬프
            blk = [f"[10/29/2026 10:02:{i:02d}] {x}" for x in blk]
        noisy += blk + [""]
        kept.append(exp[i])
    # 끝 패킷 잘림: 마지막 hex 줄을 홀수 자리에서 자른다
    noisy.pop()
    last = noisy.pop()
    noisy.append(last[:last.index("0x") + 16])
    kept[-1] = dict(kept[-1], cap_len=None, truncated=True)
    noisy += ["--More--", "FGT60F # "]
    write("noisy_terminal_log", noisy, kept, 1,
          {"interfaces": ["port1", "port2"], "min_failed_lines": 3, "truncated": 1}, crlf=True)

    # PowerShell 트랜스크립트(UTF-16LE + BOM)
    body, exp = render(pkts[:4], verbose=6, mode="abs")
    write("v6_utf16", ["**********************", "PS C:\\> ssh admin@fgt", "FGT60F # diagnose sniffer packet any none 6 4 a"] + body + footer(4),
          exp, 1, {"interfaces": ["port1", "port2"]}, encoding="utf-16")

    print(f"fixtures written to {OUT}")


if __name__ == "__main__":
    main()
