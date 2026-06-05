# WireBoard Frontend

React + TypeScript + Vite dashboard for WireBoard v5.x.

## Overview

The frontend provides a 10-panel network analysis dashboard that communicates with the WireBoard backend API running at `http://127.0.0.1:8000`.

## Panels

| Panel | Description |
|-------|-------------|
| Panel 1 | IP Summary — top talkers, bytes in/out |
| Panel 2 | Protocol Distribution — TCP/UDP/ICMP breakdown |
| Panel 3 | Flow Timeline — session activity over time |
| Panel 4 | HTTP Status — response code distribution |
| Panel 5 | Anomalies — RST storms, retransmissions |
| Panel 6 | IP Ranking — top hosts by flow count |
| Panel 7 | TLS — cipher suites, certificate info |
| Panel 8 | DNS — query types, top domains |
| Panel 9 | Conversations — top flow pairs |
| Panel 10 | Attacks — PortScan / Beacon / BruteForce / DDoS |

## Development

```bash
npm install
npm run dev      # http://localhost:5173 (backend must be running)
npm run build    # production build → dist/
npm run lint     # ESLint check
```

## Environment

No `.env` configuration required. The frontend communicates with the backend via the relative `/api/*` path when served from the same origin (embedded in WireBoard.exe), or directly to `http://127.0.0.1:8000/api/*` in dev mode.

## Production Build

The Vite build output (`dist/`) is bundled into WireBoard.exe via PyInstaller. The backend serves the static files from the embedded `frontend/dist` directory.

## Tech Stack

- React 18 + TypeScript
- Vite 6
- Plotly.js for charts
- Tailwind CSS
