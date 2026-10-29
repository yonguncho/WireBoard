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

- `tests/test_sniffer2pcap_web.py` + `tests/fixtures/sniffer2pcap/` (픽스처 8종, `gen_fixtures.py` 로 재생성)
- tshark 4.0.14로 패킷 수·시각(µs)·주소·링크타입·캡처길이·malformed 0 대조
- WireBoard 본체 변환기(`raw_pcap_converter.export_pcap`)와 **바이트 단위 동일** (픽스처 8종)
- `tools/e2e_sniffer2pcap_browser.py` (Playwright): 업로드→다운로드, 40MB(100,936패킷) 약 5초,
  변환 중 메인스레드 응답 ≤21ms, 로드 후 네트워크 요청 0건, 콘솔 에러 0, 375px 가로 스크롤 없음

## 배포 — https://choiceguidelab.com/tools/fortigate-sniffer-to-pcap/ (2026-10-30 게시)

배포 스크립트: `C:\AI_WORKPLACE\choiceguidelab-migration-git\deploy_sniffer2pcap.py`
(`--probe` 는 서버 상태만 확인). WP 루트 아래 실제 폴더 `tools/fortigate-sniffer-to-pcap/` 에
정적 파일 6개(`index.html style.css app.js worker.js converter.js sample.js`)와 `.htaccess` 를 올린다.
WordPress 재작성 규칙(`!-d/!-f`)상 실제 폴더가 우선이라 WP 가 가로채지 않는다.

`.htaccess` 가 하는 일:
- **CSP 를 HTTP 헤더로** 보낸다 — `<meta>` CSP 는 module Worker 에 적용되지 않으므로 필수.
  라이브 확인: `index.html`·`worker.js`·`converter.js` 모두 헤더 CSP 수신.
- **`Cache-Control: no-transform`** — 이게 없으면 Cloudflare 가 Web Analytics 비콘과
  이메일 난독화 스크립트를 페이지에 끼워 넣는다(실제로 발견됨: `ssh admin@192.0.2.1` 이
  이메일 보호 링크로 바뀌어 깨져 보였음). "분석 없음·외부 스크립트 없음" 약속을 지키기 위해 필수.
- JS MIME `text/javascript`, 디렉터리 목록 금지.

주의: Cloudflare 엣지가 JS/CSS 를 최대 4시간 캐시한다. `converter.js` 등을 바꿔 재배포하면
최대 4시간 동안 구버전 JS 가 섞일 수 있다(HTML 은 5분). 급하면 파일명을 바꾸거나 기다릴 것.

분석 도구를 붙인다면 쿠키 없는 방식으로, CSP 의 `script-src`/`connect-src` 를 그 도메인 하나만
허용하도록 바꾸고 `no-transform` 정책과 FAQ 문구("요청 0건")도 함께 고쳐야 한다.
입력 내용은 Worker 안에만 있으므로 분석 스크립트가 읽을 경로는 없다.