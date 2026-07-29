# WireBoard — External Enrichment Review (internet-connected mode)

Goal: when internet IS available, enrich analysis with external data — **at zero
additional API cost to the operator**. "Zero cost" means free, no paid plan, and
no per-query billing. Keyless bulk lists are preferred because they are both free
AND privacy-preserving (we download a list and match locally instead of sending
the customer's IPs to a third party).

## Cost model of current sources

| Source | What it adds | Key required? | Cost | Privacy |
|--------|--------------|---------------|------|---------|
| **ip-api.com** | Country + ASN/org for an IP | No | Free (45 req/min) | ⚠️ sends the queried IP out |
| **Feodo Tracker (abuse.ch)** | Known botnet C2 IP blocklist | No | Free (bulk JSON) | ✅ bulk download, no IP sent |
| **URLhaus (abuse.ch)** | Malware-distribution host check | No | Free | ⚠️ sends the queried host/IP out |
| **AbuseIPDB** | Crowd abuse confidence score | **Yes (operator key)** | Free tier exists, but it's the operator's key/quota | ⚠️ per-query |

**Conclusion:** Default operation already costs **$0** — ip-api, Feodo, and URLhaus
are free and keyless. AbuseIPDB is the only source that needs a key and it is
already **opt-in**: with no `ABUSEIPDB_API_KEY` set, that lookup is skipped
gracefully (`reputation_service._lookup_abuseipdb`). So no accidental cost.

Controls:
- **Offline is the default.** External lookups are opt-in: set
  `ENABLE_EXTERNAL_REPUTATION` to `1`/`true`/`yes`/`on` to enable them. Any other
  value — including unset, empty, or a typo — leaves them disabled (fail-closed).
- The switch covers **all four** sources: ip-api, URLhaus and AbuseIPDB (per-IP
  lookups that send the queried IP out) and Feodo (a bulk download that sends no
  IP, but is still an outbound connection). Note that AbuseIPDB was previously
  gated only by `ABUSEIPDB_API_KEY`, so it ignored this switch entirely.
- The Feodo gate sits *below* the cache lookup, so an already-downloaded
  blocklist keeps answering after the switch is turned off.
- `ABUSEIPDB_API_KEY` unset → AbuseIPDB skipped. This is the default.

## Recommended free, keyless additions (bulk = privacy-safe, no per-query cost)

Ordered by value/effort. All are free bulk lists matched locally, mirroring the
existing Feodo pattern (download + cache + local membership test):

1. **Tor exit node list** — `https://check.torproject.org/torbulkexitlist`
   Flags peers that are Tor exit nodes. High value for a network engineer triaging
   "who is this external IP." Bulk text list, refreshed hourly. Zero cost, no key.

2. **Spamhaus DROP / EDROP** — `https://www.spamhaus.org/drop/drop.txt`
   Hijacked / criminal netblocks (CIDR). Match session IPs against the ranges.
   Free for non-commercial bulk use; verify license for commercial redistribution.

3. **abuse.ch SSLBL (JA3/SSL blacklist)** — pairs with the existing TLS/JA4 panel:
   flag known-malicious TLS fingerprints. Free, keyless.

4. **CINSscore / FireHOL Level 1 IP set** — aggregated bad-IP lists (bulk, free).

5. **MaxMind GeoLite2** (already supported): ship/allow the free `.mmdb` for
   offline, no-network geo/ASN — removes the ip-api per-query privacy concern
   entirely. This is the best "internet-optional" enrichment.

## Non-reputation enrichment ideas (free)

- **OUI / MAC vendor lookup** — bundle the IEEE OUI file offline; label device
  vendors in L2 views. Zero network, zero cost.
- **Service/port name annotation** — bundle IANA port list offline for friendly
  port labels ("443 → HTTPS"). Zero network.
- **CVE hinting from banners** — map detected server banners (HTTP Server:,
  SSH version) to known-vulnerable versions using a bundled offline dataset.

## Guardrails to keep it cost-free and safe

- Never introduce a source that requires a paid plan or bills per call as a
  default. Any keyed source stays opt-in and skips silently without a key.
- Prefer **bulk lists matched locally** over per-IP APIs: cheaper, faster, and
  they don't leak the customer's capture IPs to third parties.
- Cache bulk lists (Feodo already uses a 1h TTL) so one download serves the whole
  session; surface the list's age in the UI so results aren't trusted blindly.
- Keep the "offline" default (`ENABLE_EXTERNAL_REPUTATION` unset) prominent for
  air-gapped / regulated environments.
