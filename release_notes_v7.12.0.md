Launch prep — licensing infrastructure, onboarding, legal clean-up.

**New**
- Demo capture onboarding: a "Try a demo capture" button loads a bundled sample (web
  flow with a retransmit + DNS + a 120-port scan) so first-time users see the
  5-minute triage immediately.
- License verification infrastructure (OFF by default — nothing is gated): offline
  Ed25519-signed license files (no internet needed) + optional Lemon Squeezy online
  validation. `GET /api/license/status`, `POST /api/license/activate`. Enable gating
  later with WIREBOARD_LICENSE_ENFORCE=1.
- Upload hint updated to real limits (2 GB pcap / 300 MB text).

**Legal / docs**
- Confirmed no MaxMind GeoIP database is bundled (legally clean); documented licensing,
  GeoIP, and privacy in docs/LICENSING_AND_LEGAL.md.

**Integrity**
- WireBoard.exe SHA-256: `9637e4f8ceb5bc6a88acd39af6167a8fb581bd09dc51c825d1a2d403811cb913`
- 909 tests passed.
