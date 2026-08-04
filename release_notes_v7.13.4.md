# WireBoard v7.13.4

Traffic 화면 레이아웃 문제를 실제로 해결한 릴리스입니다.

## Traffic 탭 IP Ranking / Top Conversations 가 좁게 표시되던 문제

Investigate › Traffic 화면에서 IP Ranking과 Top Conversations 카드가 화면
폭의 19%(약 360px)만 차지하고, 그 옆으로 1,000px이 넘는 공간이 빈 채로
남아 있었습니다. 카드가 좁다 보니 드릴다운 상세 테이블의 컬럼
(Destination / Port / Protocol / Bytes / Start / RST / Flow)이 잘려 보였습니다.

**v7.13.3에서 시도한 수정은 이 문제를 해결하지 못했습니다.** 카드 배치
그리드의 열 계산 방식만 바꿨는데, 상단의 Traffic Timeline 카드가 전체 폭을
차지하도록 되어 있어 그 방식이 동작할 수 없는 구조였습니다. v7.13.4에서는
두 카드를 전용 2단 행으로 묶어 남는 폭을 실제로 나눠 갖도록 했습니다.

브라우저에서 직접 측정한 결과(1920px 화면 기준):

| | v7.13.3 이전 | v7.13.4 |
|---|---|---|
| IP Ranking | 362px (19%) | **928px (50%)** |
| Top Conversations | 362px (19%) | **928px (50%)** |
| 빈 공간 | 1,086px | **0px** |

화면이 좁아지면 두 카드가 자동으로 위아래 1단으로 접힙니다
(1920 / 1366 / 1100px에서 2단, 820px에서 1단 확인).

Protocol 탭에서도 카드 폭이 362px에서 456px로 넓어졌습니다.

## 검증

- `pytest` **980 passed**, 5 skipped, 2 xfailed — 회귀 0건
- 패키징된 EXE에서 레이아웃 실측 및 보안 동작 확인:
  DNS 리바인딩 차단(400), 교차 출처 요청 차단(403) — v7.13.1/v7.13.2 보안 수정 유지
