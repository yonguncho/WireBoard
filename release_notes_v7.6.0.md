DNS triage — query<->response matching with latency and failure analysis.

**New**
- DNS query<->response matching by transaction ID with per-query response time.
  The DNS panel now leads with the signals NOC checks first: no-response count,
  SERVFAIL/NXDOMAIN/REFUSED errors, and response-time p50/p95/max — plus a table
  of unanswered queries and the slowest lookups (color-coded).
- Works entirely from the existing captured DNS payloads (UDP/53).

**Integrity**
- WireBoard.exe SHA-256: `991db9e83a13d04c98ac8c2487dd048135ace889eb2d16567521d730fcfdbe56`
- 831 tests passed.
