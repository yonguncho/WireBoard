# WireBoard v5.4.0

오프라인 PCAP 네트워크 공격/방어 분석 도구. 외부 API 호출 없이 Windows에서 단독 실행.

## 특징

- **완전 오프라인**: 인터넷 연결 없이 동작. 민감한 캡처 파일을 외부로 전송하지 않음.
- **단일 EXE**: PyInstaller 패키징, Python 설치 불필요.
- **6종 공격 자동 탐지** + YARA 서명 기반 페이로드 탐지 (10개 내장 룰)
- **GeoIP 시각화**: 공격자 IP → 국가 코로플레스 지도 (오프라인 CIDR 폴백 내장)

## 지원 포맷

| 포맷 | 설명 |
|------|------|
| `.pcap` / `.pcapng` | Wireshark / tcpdump 캡처 (dpkt → scapy → struct 3단계 폴백) |
| `.har` | 브라우저 HTTP Archive |
| `.log` | FortiGate sniffer verbose 3 / verbose 6 출력 |
| `.txt` / `.tcpdump` | 사람이 읽을 수 있는 tcpdump 텍스트 출력 |

## 주요 기능

### 공격 탐지

| 탐지기 | MITRE ATT&CK | 기준 |
|--------|-------------|------|
| PortScan | T1046 | 1분 내 단일 src → 다수 dst_port |
| Beacon | T1071 | CV 기반 주기적 통신 패턴 |
| BruteForce | T1110 | RST 기반 로그인 실패 집계 |
| DDoS | T1498 | PPS + 다수 src 패턴 |
| Exfiltration | T1041 | outbound 바이트 비율 |
| CommFailure | T1499 | 연결 실패 패턴 |
| YARA | 복수 | 10개 내장 룰 (ShellShock, Log4Shell, SQLi, XSS, C2, Mirai, ...) |

### 분석 패널 (10개)

1. **IP 순위** — Top src/dst IP 집계
2. **프로토콜 분포** — TCP/UDP/ICMP/애플리케이션 계층 비율
3. **타임라인** — 시간대별 트래픽 버킷 + 어노테이션
4. **HTTP 상태** — 상태코드 분포 (2xx/3xx/4xx/5xx)
5. **이상 징후** — RST/Malformed/Retransmit 집계
6. **IP 드릴다운** — 선택 IP의 세션 목록
7. **TLS/SNI** — JA4 핑거프린트 + TLS 버전
8. **DNS** — NXDOMAIN + 쿼리 Top 20
9. **대화 분석** — Top 20 IP 쌍 바이트 교환
10. **공격 목록** — 탐지된 공격 + MITRE ID + 설명

### 기타 기능

- **GeoIP 지도**: 공격자 IP → 국가 코로플레스 (Plotly choropleth). GeoLite2-Country.mmdb 배치 시 정확도 향상, 없으면 내장 CIDR 폴백 사용.
- **YARA 탐지**: yara-python 설치 시 패킷 페이로드 스캔. 미설치 시 graceful degrade.
- **FlowViewer**: 세션별 packet-by-packet (seq/ack/flags/hex) + HTTP 세션 재생 탭
- **PacketList**: Wireshark 스타일 전역 패킷 뷰어 (최대 50,000개, 필터 + 페이지네이션)
- **자연어 필터**: `ip 192.168.1.1`, `port 443`, `tcp syn` 등 → Wireshark 표현식 변환
- **비교 분석**: 두 캡처 파일 IP/포트/프로토콜/바이트 비교 (신규 IP/포트 감지)
- **내보내기**: JSON / PDF 리포트 / IOC CSV (공격자 IP·도메인)
- **어노테이션**: 타임라인 마커 + 코멘트 저장
- **테마**: 다크 / 라이트 모드 (localStorage 저장)

## 실행 방법

### EXE (Python 불필요)

```
WireBoard.exe
```

자동으로 `http://127.0.0.1:8765` 열림. 더블클릭 또는 터미널에서 실행.

### 소스에서 실행

```bash
pip install -r requirements.txt
python launcher.py
```

### GeoLite2 mmdb 배치 (선택, 정확도 향상)

MaxMind에서 `GeoLite2-Country.mmdb`를 무료 계정으로 다운로드 후 `WireBoard.exe`와 같은 디렉터리에 배치하면 자동 로드.

## API 엔드포인트

### 핵심 흐름

```
POST /api/upload  →  POST /api/analyze  →  GET /api/panels/{id}
```

### 전체 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| `POST` | `/api/upload` | 캡처 파일 업로드 (최대 50 MB) |
| `POST` | `/api/analyze` | 공격 탐지 + 분석 실행 (`upload_id`, `target_ip?`) |
| `GET` | `/api/panels/{upload_id}` | 10개 분석 패널 데이터 통합 반환 |
| `GET` | `/api/drilldown/{upload_id}?ip=` | IP별 세션 드릴다운 |
| `GET` | `/api/flow/{upload_id}?session_id=` | 세션 packet-by-packet (seq/ack/flags) |
| `GET` | `/api/packets/{upload_id}` | 전역 패킷 목록 (최대 50,000개, 필터·페이지네이션) |
| `POST` | `/api/filter` | 자연어 쿼리 세션 필터링 |
| `POST` | `/api/filter/translate` | 쿼리 → Wireshark 표현식 변환만 (세션 반환 없음) |
| `POST` | `/api/compare` | 두 캡처 비교 (`base_upload_id`, `current_upload_id`) |
| `GET` | `/api/annotations/{upload_id}` | 어노테이션 목록 조회 |
| `POST` | `/api/annotations` | 어노테이션 저장 |
| `GET` | `/api/summary/{upload_id}` | 자연어 요약 + 위험 등급 + 방어 권고 |
| `GET` | `/api/geoip/{upload_id}` | 공격자/외부 IP GeoIP 조회 결과 |
| `GET` | `/api/yara/{upload_id}` | YARA 서명 매칭 결과 |
| `GET` | `/api/export/{upload_id}` | JSON 내보내기 |
| `POST` | `/api/export/{upload_id}/pdf` | PDF 리포트 생성 |
| `GET` | `/api/export/{upload_id}/ioc` | IOC CSV (공격자 IP + 도메인) |

### 업로드 응답 예시

```json
{
  "upload_id": "550e8400-e29b-41d4-a716-446655440000",
  "source_type": "pcap",
  "session_count": 1247,
  "parse_warnings": []
}
```

### 분석 응답 스키마

```json
{
  "flows": [...],
  "sessions": [...],
  "attacks": [{"attack_type": "PortScan", "severity": "high", "mitre_id": "T1046", "src_ip": "..."}],
  "plotly_xs": [...],
  "plotly_ys": [...],
  "analysis_duration_ms": 342.1,
  "target_ip": "192.168.1.100",
  "partial_failure": false
}
```

## 아키텍처

```
launcher.py          ← uvicorn 데몬 + 포트 탐색 + 브라우저 자동 실행
backend/
  main.py            ← FastAPI 앱 + 미들웨어 + 라우터 등록
  routers/           ← 엔드포인트 (upload, analyze, panels, flow, ...)
  services/
    parser/          ← pcap / har / fortigate / tcpdump 파서
    analytics/       ← 10개 분석 서비스 (IP, TLS, DNS, GeoIP, ...)
    attack_detector/ ← 6종 탐지기 + YARA
    narrative/       ← 자연어 요약 빌더
  store/             ← SessionStore (LRU 10건, TTL 900초)
  models/            ← SessionModel (Pydantic v2 strict)
frontend/            ← React 18 + TypeScript + Vite (SPA)
```

## 빌드

```batch
build.bat
```

출력: `dist\WireBoard.exe` (약 38 MB, PyInstaller onefile)

## 테스트

```bash
# 전체 테스트 (499개)
pytest tests/ -q

# 특정 카테고리
pytest tests/test_analyze.py -v
pytest tests/test_yara_scan.py -v
pytest tests/test_geoip.py -v
```

## 의존성

| 패키지 | 버전 | 용도 |
|--------|------|------|
| fastapi | 0.115.0 | REST API 프레임워크 |
| uvicorn | 0.30.6 | ASGI 서버 |
| python-multipart | 0.0.9 | 파일 업로드 |
| httpx | 0.28.1 | 테스트 HTTP 클라이언트 |
| dpkt | ≥1.9.8 | PCAP 파싱 (primary) |
| scapy | ≥2.5.0 | PCAP 파싱 (fallback) |
| geoip2 | ≥4.8.0 | GeoIP mmdb 조회 (선택) |
| yara-python | ≥4.5.0 | YARA 룰 매칭 (선택) |
| reportlab | (내장) | PDF 리포트 생성 |

## 보안

- **바인딩**: `127.0.0.1:8765` — 로컬 전용, 외부 노출 없음
- **외부 API**: 0건 — 완전 오프라인 동작
- **파일 크기**: 50 MB 상한 (Content-Length 사전 검사 + 스트리밍 청크)
- **UUID 검증**: 전 엔드포인트 (400 반환, 422 아님)
- **TTL**: 세션 900초 / LRU 10건 자동 삭제
- **EDR**: Windows Defender PASS

## 라이선스

의존성 라이선스 상세: `licenses.txt`
