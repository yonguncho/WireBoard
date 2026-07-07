Live capture — record packets directly on the PC (optional).

**New**
- Live Capture (beta): pick a network interface (shown with its IP), optionally enter
  a source IP / destination IP / port / host filter, and capture packets straight into
  the analysis pipeline — no external tool needed. Capture is 100% local (never leaves
  the PC), auto-stops at a packet or time limit, and the result flows into the normal
  analysis views. The captured file is also downloadable.
- Filters compile to a BPF (e.g. `src host ... and dst host ... and port ...`); inputs
  are validated as IPs/ports.

**Requirements**
- Live capture needs the Npcap driver (npcap.com) and the app must run as Administrator.
  When either is missing, the UI explains it; offline pcap analysis is unaffected.

**Integrity**
- WireBoard.exe SHA-256: `3fe6ac99e891414a8e82edc411b084ae9b1f4e413089cb125a7434ab592180bc`
- 861 tests passed.
