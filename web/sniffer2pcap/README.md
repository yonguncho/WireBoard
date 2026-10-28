# FortiGate sniffer → PCAP 웹 도구 (sniffer2pcap)

FortiGate `diagnose sniffer packet` 텍스트 출력을 libpcap(.pcap)로 바꾸는 **정적 웹 페이지**.
변환은 100% 브라우저(Web Worker) 안에서 일어나고, 페이지 CSP `connect-src 'none'` 때문에
브라우저가 네트워크 요청 자체를 차단한다. 서버 코드·빌드 단계·외부 라이브러리 없음.

## 파일

| 파일 | 역할 |
|------|------|
| `index.html` | 페이지 본문 (도구 + 사용법 + FAQ + 소개 + 상표 고지), CSP·SEO 메타·JSON-LD |
| `style.css` | 스타일 (라이트/다크) |
| `app.js` | UI: 입력 수집 → Worker 호출 → 요약·다운로드 표시 |
| `worker.js` | Web Worker: 파일 디코딩·변환·pcap Blob 생성 |
| `converter.js` | 변환 코어 (DOM 없음 — 브라우저와 Node 공용) |
| `sample.js` | "Try a sample" 버튼용 예시 출력 (합성 패킷) |
| `cli.mjs` | 같은 코어를 쓰는 Node CLI (`node cli.mjs in.txt outdir [--base-time epoch]`) — 테스트용 |

## 변환 규칙

- 패킷 경계 = hex 오프셋 `0x0000` 줄. 헤더 줄은 시각·인터페이스만 제공.
- 오프셋이 끊기면(줄 유실) 그 패킷은 **버리고** 실패로 집계. 추측으로 메우지 않음.
- 링크타입은 패킷 바이트로 판정(VLAN 태그 포함). 전부 이더넷 → `LINKTYPE_ETHERNET(1)`,
  하나라도 이더넷 헤더가 없으면 → `LINKTYPE_RAW(101)` (이더넷 헤더는 벗기고, ARP 등 비IP는 제외·집계).
  **가짜 MAC 생성 없음.** 인터페이스가 2개 이상이면 인터페이스별 파일도 제공(각자 링크타입 판정).
- 시간: 절대(`a`/`l`) 그대로 UTC로 기록, 상대시간은 0(또는 사용자가 지정한 시작시각) 기준.
- 잘린 마지막 패킷은 유지하고 `orig_len`을 IP 길이로 기록 → Wireshark가 truncated 표시.
- 잡음 무시: 프롬프트, 명령줄, `interfaces=`/`filters=`, `--More--`, ANSI 색 코드, 백스페이스,
  SecureCRT 줄 타임스탬프 `[..]`, CRLF, UTF-16(PowerShell 트랜스크립트).
- 마지막 `N packets received by filter` 와 변환 수가 다르면 경고.

> 참고: Fortinet 문서상 verbose 3 은 "IP부터"가 아니라 **"이더넷부터(가능한 경우)"**, IP부터는 2/5 다.
> 그래서 레벨이 아니라 바이트로 판정한다.

## 기존 WireBoard 변환기(`backend/services/parser/raw_pcap_converter.py`) 대비

| 항목 | 기존 | 웹 도구 |
|------|------|---------|
| 상대시간 로그 | 패킷 0개 (None) | 지원 |
| UTF-16 로그 | 패킷 0개 (None) | 지원 |
| 이더넷 없는 패킷 | 00:00:00:00:00:00 가짜 MAC 래핑 | RAW IP(101) |
| hex 줄 유실 | 이어붙여 깨진 패킷 생성 | 패킷 제외 + 실패 집계 |
| 잘린 패킷 | orig_len=캡처 길이 | orig_len=IP 길이 (truncated 표시) |
| 인터페이스별 분리 / 요약 | 없음 | 있음 |

깨끗한 절대시간 로그(v3/v5/v6)에서는 IP 계층 바이트와 타임스탬프가 기존 변환기와 **동일**함을 검증했다.

## 검증

검증 스크립트·픽스처는 보호 경로(`tests/`) 정책 때문에 아직 저장소 밖(세션 scratchpad)에 있다.
승인 후 `tests/test_sniffer2pcap_web.py` + `tests/fixtures/sniffer2pcap/` 로 옮길 예정.
- tshark 4.0.14로 패킷 수·시각(µs)·주소·링크타입·캡처길이·malformed 0 대조 (픽스처 8종)
- 기존 변환기와 IP 바이트·시각 동일성 비교 (3종)
- Playwright E2E: 업로드→다운로드, 40MB(100,936패킷) 3.3초, 변환 중 메인스레드 응답 ≤5ms,
  로드 후 네트워크 요청 0건, 콘솔 에러 0, 375px 가로 스크롤 없음

## 배포 (호스팅 위치는 미정 — 결정 필요)

정적 파일 7개를 그대로 올리면 된다. `.js` 가 `text/javascript` MIME으로 서빙되기만 하면 된다.

**CSP 는 HTTP 헤더로도 보낼 것.** `<meta>` CSP 는 문서에만 적용되고, 변환이 실제로 일어나는
module Worker(`worker.js`)는 자기 응답 헤더의 CSP 를 따른다. 그래서 서버(또는 Cloudflare Transform Rule)에서
`index.html`·`worker.js` 둘 다에 아래 헤더를 붙인다. 붙이기 전까지 페이지 문구는 "코드에 전송 로직이 없고
CSP 가 fetch/XHR 을 막는다" 수준으로만 주장한다(현재 문구).

```
Content-Security-Policy: default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'
```

| 선택지 | 장점 | 단점 |
|--------|------|------|
| **A. choiceguidelab.com 하위 경로** (예: `/tools/fortigate-sniffer-to-pcap/`, wp-content 밖 정적 폴더) | 기존 도메인 권위·내부링크(APO 글) 효과, 별도 비용 0, APO 유입 동선 짧음 | WordPress/캐시 플러그인이 헤더·HTML을 건드릴 수 있음, Cloudflare 캐시 갱신 관리 필요 |
| **B. 별도 도메인** (예: sniffer2pcap 류 키워드 도메인) | 키워드 도메인, 사이트 장애·플러그인과 무관, 도구 자체 브랜딩 | 도메인 권위 0에서 시작, 연 1~2만원 비용, APO로의 유입은 링크 1개뿐 |
| **C. GitHub Pages / Cloudflare Pages** (+ 나중에 커스텀 도메인) | 무료, 배포 = git push, HTTPS 자동, 소스 공개로 "업로드 안 함" 신뢰 증명 | `*.github.io` 하위면 SEO 약함 → 결국 A나 B 도메인 연결 필요 |

추천: **A (choiceguidelab 하위 경로)** — 목적이 APO 유입이라 같은 도메인에 두는 게 가장 직접적이다.
배포 시 `index.html` 에 `<link rel="canonical">` 을 최종 URL로 추가할 것(현재는 URL 미정이라 비워둠).
분석 도구를 붙인다면 쿠키 없는 방식(Cloudflare Web Analytics 등)으로, 이 경우 CSP의
`script-src`/`connect-src` 를 그 도메인 하나만 허용하도록 바꾸고 FAQ 문구("요청 0건")도 함께 고쳐야 한다.
입력 내용은 Worker 안에만 있으므로 분석 스크립트가 읽을 경로는 없다.
