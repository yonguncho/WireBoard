Large captures + modern protocols (QUIC / HTTP/2).

**Large-capture streaming**
- File size limit raised from 50 MB to 2 GB (pcap/pcapng). Uploads are spooled to disk
  and parsed streaming from the file handle, so memory stays bounded regardless of file
  size — real multi-hundred-MB / GB captures now open.
- Configurable via WIREBOARD_MAX_PCAP_MB / WIREBOARD_MAX_TEXT_MB.

**QUIC & HTTP/2**
- QUIC long-header identification (v1/v2/draft/gQUIC + packet type) and SNI decrypted
  from the QUIC Initial packet (RFC 9001) — see which service an encrypted QUIC/UDP-443
  connection targets.
- HTTP/2 detection via TLS ALPN (h2) and cleartext h2c preface.
- Detected application protocols shown in the Protocol panel and flow header.

**Integrity**
- WireBoard.exe SHA-256: `1d1208ae428421e43802c9b22ff8fdbb4ea8e8037f25bf0cb886ba6471c3aa5f`
- 885 tests passed.
