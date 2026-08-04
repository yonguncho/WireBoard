# WireBoard v7.13.3

Traffic 화면의 레이아웃 문제를 수정한 소규모 릴리스입니다.

## 수정 내역

**Traffic 탭에서 IP Ranking / Top Conversations가 좁게 표시되던 문제**

Investigate › Traffic 화면에서 IP Ranking과 Top Conversations 카드가 화면 폭을
다 쓰지 못하고 고정된 좁은 폭(약 360px)으로 표시되어, 드릴다운 상세 테이블의
여러 컬럼(Destination / Port / Protocol / Bytes / Start / RST / Flow)이
잘려 보이는 문제가 있었습니다. 동시에 그 옆으로 사용되지 않는 빈 공간이
남았습니다.

카드 배치 그리드가 화면 폭에 맞춰 열 개수를 미리 계산해 고정하던 방식이
원인이었습니다. 실제 카드 개수에 맞춰 남은 공간을 나눠 채우도록 변경해,
카드가 화면 폭의 절반 이상을 채우도록 넓어졌습니다. Overview 탭 하단
카드들과 동일한 방식으로 통일했습니다.

## 검증

- `pytest` **980 passed**, 5 skipped, 2 xfailed — 회귀 0건
- 패키징된 EXE 스모크 테스트: DNS 리바인딩 차단(400), 교차 출처 요청 차단(403),
  업로드→분석(122 세션) 정상 — v7.13.1/v7.13.2 보안 수정 유지 확인
