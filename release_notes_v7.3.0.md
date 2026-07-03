NOC triage release — trustworthy risk grading and "network vs application" verdicts.

**New**
- Network vs Application verdict: compares network RTT (SYN/SYN-ACK) against server response delay per TCP session — tells you which team to escalate to
- Evidence-based risk grade: 0-100 score with an explicit "Why this grade" factor breakdown
- Failure diagnosis without an attack: refused/timed-out captures are no longer labeled "normal traffic"
- Capture-quality warnings (pre-capture connections, summary-only logs, truncated flows)
- Conversations panel: RST / no-reply columns + sort by issue rate
- Two-capture compare verdict: DEGRADED / IMPROVED / SIMILAR with per-conversation change types
- English multi-page PDF report with risk grade, evidence, and diagnosis

**Fixed**
- False DEGRADED verdicts on healthy captures (normal RST teardown, one-way UDP)
- False MEDIUM/HIGH risk on broadcast-heavy LANs and summary-only text logs
- Detector crashes no longer surface as attack findings

**Integrity**
- WireBoard.exe SHA-256: `d6828918b91e404d770d9cb2053dd552f6233749b3b1e96b44e4ff3c4099047d`
- 809 tests passed
