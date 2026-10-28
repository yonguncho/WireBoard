# WireBoard v5.4.0

오프라인 PCAP 네트워크 공격/방어 분석 도구. 외부 API 호출 없이 Windows에서 단독 실행.

## 특징

- **완전 오프라인 (기본값)**: 인터넷 연결 없이 동작. 캡처 파일은 어떤 경우에도 외부로 전송하지 않음.
  외부 위협 인텔·지오로케이션 조회는 기본 비활성이며, `ENABLE_EXTERNAL_REPUTATION=1`로
  명시적으로 켠 경우에만 조회 대상 IP 한 개가 외부로 나감.
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

### 로컬 LLM 보고서 문단 초안 (선택, 기본 꺼짐)

PDF 보고서의 **요약 문단**과 **사건 경위 서술**을 사용자 PC의 로컬 LLM이 초안으로 써 줍니다.
외부 API를 쓰지 않으며(비용 0), 꺼져 있거나 모델이 없으면 보고서는 지금과 완전히 같습니다.
WireBoard 자체에는 아무것도 추가 설치되지 않습니다 — 이미 설치한 LLM 런타임에 `127.0.0.1`로 접속만 합니다.

- 모델에는 **원본 패킷을 넣지 않습니다.** WireBoard가 계산한 결과(탐지 항목·MITRE ID·상위 통신쌍·진단·수치)를
  `F1`/`H1`/`P1`/`S1` ID가 붙은 JSON으로 만들어 넣습니다.
- 생성 문단은 코드 규칙으로 즉시 검사합니다: 입력에 없는 IP·숫자·포트·시각·도메인·해시·MITRE ID,
  존재하지 않는 근거 ID, 단정 표현("definitely compromised" 등), 비영어 출력. **하나라도 걸리면 그 문단은 버리고 템플릿 문장을 씁니다.**
- 통과한 문단은 PDF에 `AI-generated draft - review required; based on F1, S1` 라벨과 함께 들어갑니다.
  수치 표·IOC 목록은 계속 코드가 만듭니다.
- 검사 결과(통과/대체 문단 수와 대체 사유)는 서버 로그 `services.narrative.llm_draft`에 남습니다.
- API: `GET /api/summary/{upload_id}/ai-draft` (X-Upload-Token 필요) — 꺼져 있으면 `{"available": false}`.

**1) 런타임 설치 (둘 중 하나)**

- [Ollama](https://ollama.com/download) 설치 후: `ollama pull llama3.1:8b`
- llama.cpp `llama-server` (OpenAI 호환 API): `llama-server -m <모델>.gguf --port 8080`

**2) WireBoard 실행 전 환경변수 설정 (PowerShell)**

```powershell
$env:WIREBOARD_LLM_ENABLED = "1"
$env:WIREBOARD_LLM_MODEL   = "llama3.1:8b"            # 기본값
# llama.cpp 서버를 쓰는 경우:
# $env:WIREBOARD_LLM_API = "openai"; $env:WIREBOARD_LLM_URL = "http://127.0.0.1:8080"
.\WireBoard.exe
```

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `WIREBOARD_LLM_ENABLED` | `0` | `1`/`true`/`yes`/`on` 이면 켬 |
| `WIREBOARD_LLM_API` | `ollama` | `ollama` 또는 `openai`(llama.cpp server 등 `/v1/chat/completions`) |
| `WIREBOARD_LLM_URL` | `http://127.0.0.1:11434` (openai면 `:8080`) | **loopback 주소만 허용** — 원격 주소면 기능이 꺼짐 |
| `WIREBOARD_LLM_MODEL` | `llama3.1:8b` | 런타임에 설치된 모델 이름 |
| `WIREBOARD_LLM_TIMEOUT` | `180` | 초. 초과 시 템플릿 보고서로 진행 |

**권장 사양 (추정치 — 이 저장소에서 실측 전)**

| 모델 | 메모리 | CPU 전용 PC (8코어급) 예상 | GPU (VRAM 8GB+) |
|------|--------|---------------------------|-----------------|
| 7~8B instruct, Q4 (`llama3.1:8b`, `qwen2.5:7b`) — **권장** | RAM 8GB 이상 여유 | 생성 약 5~10 토큰/초 → 보고서 1건(문단 2개) 약 40~120초 | 수 초 |
| 3B instruct (`llama3.2:3b`) | RAM 4GB | 약 2~3배 빠름, 검사 탈락률 높을 수 있음 | 수 초 |

PDF 내보내기 버튼을 누를 때만 생성하며(요약 화면 로딩은 기다리지 않음), 같은 결과는 메모리에 캐시합니다.
모델·프롬프트를 바꿀 때는 `eval/llm_draft/` 평가로 통과율·문단당 시간·템플릿 대체율을 비교하세요:

```powershell
python eval\llm_draft\run_eval.py --model llama3.1:8b
python eval\llm_draft\run_eval.py --table
```

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
- **외부 API**: 기본 0건 — 외부 조회는 `ENABLE_EXTERNAL_REPUTATION=1` 옵트인 시에만 동작하며,
  이때 ip-api·URLhaus·AbuseIPDB로 조회 대상 IP가, Feodo 블록리스트 다운로드가 발생함
- **파일 크기**: 50 MB 상한 (Content-Length 사전 검사 + 스트리밍 청크)
- **UUID 검증**: 전 엔드포인트 (400 반환, 422 아님)
- **TTL**: 세션 900초 / LRU 10건 자동 삭제
- **EDR**: Windows Defender PASS

## 라이선스

의존성 라이선스 상세: `licenses.txt`
