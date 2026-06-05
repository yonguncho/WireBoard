# WireBoard v5.0

Network packet capture analysis tool — FastAPI backend with multi-format parser support.

## Supported Formats

| Format | Description |
|--------|-------------|
| `.pcap` / `.cap` | Wireshark/tcpdump packet captures |
| `.har` | Browser HTTP Archive |
| FortiGate sniffer | Verbose 3 / Verbose 6 text output |
| tcpdump text | Human-readable tcpdump output |

## Features

- Upload and parse network captures via REST API
- Automatic format detection
- Flow extraction and attack detection (port scan, beacon, brute-force, DDoS)
- Session-based storage with 15-minute TTL
- 50 MB file size limit with pre-check

## Quick Start (Standalone EXE)

```
WireBoard.exe
```

Opens the API server at `http://127.0.0.1:8000`.

## Quick Start (Python)

```bash
pip install -r requirements.txt
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/upload` | Upload a capture file |
| `GET` | `/api/analyze/{session_id}` | Analyze uploaded capture |

## Requirements

- Python 3.10+
- See `requirements.txt`

## Build EXE

```
build.bat
```

Output: `dist\WireBoard.exe`

## Test

```
pytest tests/ -v
```

78 tests — unit, integration, and edge cases.
