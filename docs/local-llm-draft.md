# 로컬 LLM 보고서 문단 초안 (실험적 고급 기능)

> **상태: 실험적 · 기본 꺼짐 · 홍보하지 않음 (2026-10-30 결정)**
> 사용자가 Ollama 등 로컬 LLM 런타임을 직접 설치해야 하고, CPU PC 에서 보고서 1건에 약 70초가 걸리며,
> 문단 약 21% 는 검사에서 탈락해 템플릿 문장으로 대체된다. 일반 사용자에게 설치 부담 대비 가치가 작아
> 고급 사용자(IR 담당자 등)용으로만 둔다. 다운로드 페이지·홍보 문구에 넣지 않는다.
> 확장안(앱 안 '켜기' 버튼 → 모델 자동 다운로드 + 내장 엔진, Ollama 불필요)은 사용자 반응을 보고 재검토.

PDF 보고서의 **요약 문단**과 **사건 경위 서술**을 사용자 PC의 로컬 LLM이 초안으로 써 줍니다.

> **동작 범위:** WireBoard 를 실행하는 **그 PC** 의 `127.0.0.1` 에서 돌고 있는 LLM 에만 접속합니다. 개발자 PC 나 어떤 서버의 모델도 쓰지 않으므로, 다른 사용자가 이 기능을 쓰려면 **자기 PC 에 Ollama 와 모델을 직접 설치**해야 합니다. 설치하지 않은 사용자에게는 기능이 꺼진 상태(기존 보고서)로 동작합니다. 무료 웹 도구(`web/sniffer2pcap`)는 LLM 과 무관합니다.

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

- [Ollama](https://ollama.com/download) 설치 후: `ollama pull llama3.2:3b`
- llama.cpp `llama-server` (OpenAI 호환 API): `llama-server -m <모델>.gguf --port 8080`

**2) WireBoard 실행 전 환경변수 설정 (PowerShell)**

```powershell
$env:WIREBOARD_LLM_ENABLED = "1"
$env:WIREBOARD_LLM_MODEL   = "llama3.2:3b"            # 기본값
# llama.cpp 서버를 쓰는 경우:
# $env:WIREBOARD_LLM_API = "openai"; $env:WIREBOARD_LLM_URL = "http://127.0.0.1:8080"
.\WireBoard.exe
```

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `WIREBOARD_LLM_ENABLED` | `0` | `1`/`true`/`yes`/`on` 이면 켬 |
| `WIREBOARD_LLM_API` | `ollama` | `ollama` 또는 `openai`(llama.cpp server 등 `/v1/chat/completions`) |
| `WIREBOARD_LLM_URL` | `http://127.0.0.1:11434` (openai면 `:8080`) | **loopback 주소만 허용** — 원격 주소면 기능이 꺼짐 |
| `WIREBOARD_LLM_MODEL` | `llama3.2:3b` | 런타임에 설치된 모델 이름 |
| `WIREBOARD_LLM_TIMEOUT` | `300` | 초. 초과 시 템플릿 보고서로 진행 |

**권장 사양 — 실측 (2026-10-30, CPU 전용 노트북: Intel UHD 620, GPU 미사용, Ollama 0.40.13, 평가 케이스 12종·문단 24개)**

| 모델 | 메모리(모델 적재) | 문단당 생성 시간 | 보고서 1건(문단 2개) | 최종 검사 통과율 |
|------|------------------|-----------------|---------------------|-----------------|
| `llama3.2:3b` (Q4_K_M) — **기본값·권장** | 약 2.6 GB | 34.9초 | 약 70초 | 79% |
| `hermes3:8b` (Q4_0, Llama 3.1 8B 계열) | 약 5.3 GB | 71.0초 | 약 140초 | 79% |

- 통과하지 못한 문단(약 21%)은 자동으로 템플릿 문장으로 대체됩니다. GPU 가 있으면 수 초 수준으로 빨라집니다(미측정).
- **검사의 한계 (실측에서 확인):** 입력에 있는 숫자를 엉뚱한 의미로 쓰는 경우(예: 출발지 4개를 "beacon 호스트 4대"로)나
  주어·방향이 바뀐 문장은 코드 규칙으로 완전히 잡을 수 없습니다. 그래서 모든 AI 문단에 "review required" 라벨이 붙습니다.
- 실측에서 모델이 실제로 낸 환각과 그에 대한 차단 규칙·회귀 테스트는 `tests/test_llm_draft.py`, 원문은 `eval/llm_draft/runs/`.
PDF 내보내기 버튼을 누를 때만 생성하며(요약 화면 로딩은 기다리지 않음), 같은 결과는 메모리에 캐시합니다.
모델·프롬프트를 바꿀 때는 `eval/llm_draft/` 평가로 통과율·문단당 시간·템플릿 대체율을 비교하세요:

```powershell
python eval\llm_draft\run_eval.py --model llama3.2:3b
python eval\llm_draft\run_eval.py --rescore eval\llm_draft\runs\<파일>.json   # 검사 규칙만 바꿨을 때 (모델 호출 없음)
python eval\llm_draft\run_eval.py --table
```
