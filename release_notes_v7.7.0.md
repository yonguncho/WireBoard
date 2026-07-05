TLS failure diagnosis + time-based error overlay.

**New**
- TLS Alert decode + handshake stages: the flow's TLS tab shows the handshake result
  (Completed / FAILED on a fatal alert / Incomplete), the stages seen
  (ClientHello -> ServerHello -> ...), and any Alert messages decoded by name
  (handshake_failure, certificate_expired, unknown_ca, protocol_version, ...) — the
  classic "TCP connects but TLS drops" pattern is now visible.
- Timeline error overlay: the traffic timeline overlays a red per-bucket error series
  (RST + no-reply) on a second axis, answering "when did errors spike?".

**Integrity**
- WireBoard.exe SHA-256: `e6d0ab2e68deb10abefdde948bb62a0bc63c8df8a80a9619ad02feda175d275d`
- 838 tests passed.
