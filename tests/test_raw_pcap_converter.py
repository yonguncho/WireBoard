"""raw_pcap_converter 테스트 — FortiGate/tcpdump verbose hex 덤프 → pcap 변환.

대상: backend/services/parser/raw_pcap_converter.py

검증 항목:
- FortiGate verbose 6 (이더넷 hex) → 패킷 수·세션 복원, 실제 바이트 채워짐
- tcpdump -X (raw IP hex) → 합성 이더넷으로 감싸 PcapParser 재파싱 가능
- 16진수 덤프 없는 요약 전용 로그 → None
- 빈/비텍스트 입력 → None
- 생성된 pcap은 항상 LINKTYPE_ETHERNET(1)
"""
import struct

from services.parser.raw_pcap_converter import convert_raw_log_to_pcap
from services.parser.pcap_parser import PcapParser


_FORTI_ETH = (
    "2026-03-18 13:41:51.308714 internal2 in 3.3.3.1.56501 -> 10.90.80.163.15902: syn 4242660751\n"
    "0x0000\t 0000 0000 0001 e8b5 d0fb c038 0800 4500\t...........8..E.\n"
    "0x0010\t 0034 db1d 4000 8006 bea5 0303 0301 0a5a\t.4..@..........Z\n"
    "0x0020\t 50a3 dcb5 3e1e fce1 dd8f 0000 0000 8002\tP...>...........\n"
    "0x0030\t faf0 1dd9 0000 0204 05b4 0103 0308 0101\t................\n"
    "0x0040\t 0402                                   \t..\n"
)

# tcpdump -X: raw IP (이더넷 헤더 없음) TCP SYN
_TCPDUMP_RAW = (
    "12:34:56.789012 IP 10.0.0.1.1234 > 10.0.0.2.80: Flags [S], seq 0, length 0\n"
    "\t0x0000:  4500 0028 0001 0000 4006 66c1 0a00 0001  E..(....@.f.....\n"
    "\t0x0010:  0a00 0002 04d2 0050 0000 0000 0000 0000  .......P........\n"
    "\t0x0020:  5002 2000 8b9f 0000                      P.......\n"
)


def _linktype(pcap: bytes) -> int:
    return struct.unpack_from("<I", pcap, 20)[0]


def test_fortigate_ethernet_conversion():
    res = convert_raw_log_to_pcap(_FORTI_ETH.encode())
    assert res is not None
    pcap, n = res
    assert n == 1
    assert _linktype(pcap) == 1  # LINKTYPE_ETHERNET
    sessions, _ = PcapParser().parse(pcap)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.src_ip == "3.3.3.1" and s.dst_ip == "10.90.80.163"
    assert s.src_port == 56501 and s.dst_port == 15902
    assert s.protocol == "TCP"
    assert (s.bytes_sent + s.bytes_recv) > 0  # 실제 바이트 채워짐


def test_tcpdump_raw_ip_wrapped_to_ethernet():
    res = convert_raw_log_to_pcap(_TCPDUMP_RAW.encode())
    assert res is not None
    pcap, n = res
    assert n == 1
    assert _linktype(pcap) == 1  # raw IP 도 이더넷으로 감싸 출력
    sessions, _ = PcapParser().parse(pcap)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.src_ip == "10.0.0.1" and s.dst_ip == "10.0.0.2"
    assert s.src_port == 1234 and s.dst_port == 80


def test_summary_only_log_returns_none():
    # verbose 3: 16진수 덤프 없음
    summary_only = (
        "2026-03-18 13:41:51.308714 internal2 in 3.3.3.1.56501 -> 10.90.80.163.15902: syn 0\n"
        "2026-03-18 13:41:51.308754 internal1 out 3.3.3.1.56501 -> 10.90.80.163.15902: syn 0\n"
    )
    assert convert_raw_log_to_pcap(summary_only.encode()) is None


def test_empty_input_returns_none():
    assert convert_raw_log_to_pcap(b"") is None
    assert convert_raw_log_to_pcap(b"\xff\xfe\x00garbage") is None


def test_upload_exposes_pcap_download(api_client):
    """FortiGate hex 로그 업로드 → pcap_available=True, 다운로드 엔드포인트 동작."""
    import io
    up = api_client.post(
        "/api/upload",
        files={"file": ("fw.log", io.BytesIO(_FORTI_ETH.encode()), "text/plain")},
    )
    assert up.status_code == 200, up.text
    body = up.json()
    assert body["source_type"] == "fortigate"
    assert body["pcap_available"] is True
    uid, tok = body["upload_id"], body["capture_token"]

    dl = api_client.get(f"/api/upload/{uid}/pcap", headers={"X-Upload-Token": tok})
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert dl.content[:4] == b"\xd4\xc3\xb2\xa1"  # libpcap LE magic
    assert _linktype(dl.content) == 1
