# WireBoard — Licensing & Legal (launch prep)

## Licensing infrastructure (implemented, OFF by default)

WireBoard ships a license-verification layer that is **non-gating by default** — with
no configuration, nothing is restricted (freemium-friendly; current behavior unchanged).

### Two verification paths
1. **Offline signed license (privacy-preserving, no internet)**
   - Token format: `WB1.<base64url(payload)>.<base64url(ed25519_sig)>`
   - Payload: `{email, expires (YYYY-MM-DD | null), seats, issued}`
   - Verified against the Ed25519 public key embedded in
     `backend/services/licensing.py` (`_LICENSE_PUBKEY_HEX`).
   - The product owner issues tokens with the **private key** (kept in
     `C:\AI_WORKPLACE\secrets\wireboard_license_ed25519.key`, never committed/shipped):
     ```
     python tools/sign_license.py --email buyer@example.com --expires 2027-12-31 --seats 1
     ```
   - Buyer activates via the app (`POST /api/license/activate`) or by dropping the token
     into `license.dat` next to the EXE, or the `WIREBOARD_LICENSE` env var.

2. **Online (Lemon Squeezy)** — `licensing.verify_online()` calls the LS
   `/v1/licenses/validate` endpoint. Use when a per-activation online check is acceptable.

### Turning on gating (when you decide the model)
- Set `WIREBOARD_LICENSE_ENFORCE=1`. Then `licensing.should_gate()` returns `True` for
  unlicensed users. Wire that into whatever you choose to gate (recommended per research:
  **watermark the PDF/export while keeping analysis free** — maximizes trial value).
- Endpoint: `GET /api/license/status` → `{state, enforced, email, expires, method}`.

### Remaining owner decisions (not code)
- Pricing / seats (research rec: personal one-time ~$99, MSP multi-seat $299–499).
- Gating model (watermark vs feature-limit vs time trial).
- Whether to use LS online activation, offline signed files, or both.

---

## GeoIP — legally clean (no MaxMind bundled)

- **No GeoLite2/GeoIP2 `.mmdb` is bundled** in the repo or the EXE (verified).
- `GeoIpAnalyzer` loads a user-supplied `GeoLite2-Country.mmdb` **if present** next to the
  EXE (the user accepts MaxMind's license directly), otherwise falls back to a small,
  **hand-curated 7 KB CIDR→country table** (`geoip_fallback.json`, not derived from
  MaxMind data). This avoids MaxMind's commercial-redistribution license entirely.
- **Action:** state in the EULA/README that GeoIP is coarse by default and users may add
  their own MaxMind DB under MaxMind's terms. Label the built-in result as
  "approximate (offline)" in the UI.

## Privacy / data handling (a selling point — write it into the EULA)
- Analysis is 100% local (binds `127.0.0.1`); packet data is never transmitted.
- Optional external reputation lookups are opt-in and can be disabled
  (`ENABLE_EXTERNAL_REPUTATION=0`).
- No crash/usage telemetry is collected. Consider stating "no telemetry" explicitly.
