<#
  WireBoard 워치독 — 제품 자체 자가복구 (2026-07-11 도입).
  기존엔 외부 에이전트 의존 → 그 에이전트 죽으면 방치. EveryFive 워치독 패턴 이식.

  동작(작업 스케줄러 5분 간격 권장):
    1. /health 폴링 (무상태 liveness)
    2. 응답 없으면 → 포트 8764 점유 프로세스 확인 → 죽었으면 재시작
    3. 명령줄 기반 생존확인(PID 재사용 오탐 방지)
    4. 상태를 wireboard_status.json에 기록
    5. 연속 실패 상한(5회) → halt 기록(무한 재시작 루프 방지)

  등록:
    schtasks /create /tn "WireBoard_Watchdog" /tr "powershell -NoProfile -File C:\AI_WORKPLACE\WireBoard\watchdog.ps1" /sc minute /mo 5 /f
#>
$ErrorActionPreference = "SilentlyContinue"
$WB        = "C:\AI_WORKPLACE\WireBoard"
$HealthUrl = "http://127.0.0.1:8764/health"
$StatusFile= Join-Path $WB "wireboard_status.json"
$Launcher  = Join-Path $WB "launcher.py"
$ExePath   = Join-Path $WB "dist\WireBoard.exe"
$MaxFail   = 5
$utf8      = New-Object System.Text.UTF8Encoding($false)

# 커널 고착 프로세스는 권한이 있어도 종료되지 않고, Stop-Process 가 그 자리에서 무한 대기한다.
# (2026-08-31 PID 23440 사례: 상승권한 워치독이 9분간 멈춰 작업이 Running 고착 → 5분 감시 자체가 정지.
#  MultipleInstances=IgnoreNew + ExecutionTimeLimit 72h 라 최대 사흘간 감시 공백이 될 수 있었다.)
# 그래서 종료는 반드시 외부 taskkill 을 제한시간만 기다리는 방식으로 한다 — 워치독은 절대 블로킹되지 않는다.
$UnkillFile = Join-Path $WB "watchdog_unkillable.json"

function Stop-ProcessBounded([int]$ProcId, [int]$TimeoutSec = 5) {
  try {
    $k = Start-Process -FilePath "taskkill.exe" -ArgumentList "/F","/PID",$ProcId `
                       -WindowStyle Hidden -PassThru -ErrorAction Stop
    if ($k.WaitForExit($TimeoutSec * 1000)) { return ($k.ExitCode -eq 0) }
    return $false   # 제한시간 초과 → 종료 불가. taskkill 프로세스는 버리고 즉시 진행한다
  } catch { return $false }
}

# 종료 불가로 판명된 프로세스 목록(PID + 기동시각으로 키 구성 — PID 재사용 오탐 방지).
# 매 5분마다 재시도하면 그때마다 taskkill 이 하나씩 새는 셈이라, 한 번 실패하면 기록해 두고 건너뛴다.
function Get-Unkillable {
  if (Test-Path $UnkillFile) { try { return @(Get-Content $UnkillFile -Raw | ConvertFrom-Json) } catch { return @() } }
  return @()
}
function Add-Unkillable([string]$key) {
  $cur = @(Get-Unkillable)
  if ($key -notin $cur) {
    $cur += $key
    [System.IO.File]::WriteAllText($UnkillFile, (ConvertTo-Json @($cur)), $utf8)
  }
}
function Get-ProcKey($proc) { "$($proc.ProcessId)_$($proc.CreationDate.ToString('yyyyMMddHHmmss'))" }

function Write-Status([string]$status, [string]$detail) {
  $obj = [PSCustomObject]@{
    status     = $status          # healthy | down | restarted | halted
    port_8764  = (Get-NetTCPConnection -LocalPort 8764 -State Listen -ErrorAction SilentlyContinue) -ne $null
    detail     = $detail
    checked_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  }
  [System.IO.File]::WriteAllText($StatusFile, ($obj | ConvertTo-Json), $utf8)
}

# 연속 실패 카운터(상태파일에서 로드)
$failCount = 0
if (Test-Path $StatusFile) {
  try { $prev = Get-Content $StatusFile -Raw | ConvertFrom-Json; if ($prev.fail_count) { $failCount = [int]$prev.fail_count } } catch {}
}

# ── 1) 헬스 폴링 ──
$alive = $false
try {
  $r = Invoke-WebRequest -Uri $HealthUrl -TimeoutSec 5 -UseBasicParsing
  if ($r.StatusCode -eq 200 -and $r.Content -match '"status"\s*:\s*"healthy"') { $alive = $true }
} catch { $alive = $false }

if ($alive) {
  # 정상 경로에서는 프로세스를 열거하지 않는다 — 의도적 결정이다.
  # 2026-08-31 에 고아 스텁 청소를 여기 넣었다가 워치독이 두 번 통째로 멈췄다.
  # 원인은 kill 이 아니라 `Get-CimInstance Win32_Process` 전수 열거였다: 상승권한(RunLevel=Highest)
  # 에서는 WMI 가 각 프로세스의 PEB(CommandLine 등)를 읽으려 하는데, 커널 고착 프로세스(PID 23440)
  # 에서 그대로 블로킹됐다. 비상승 세션은 권한 검사에서 빨리 실패해 안 걸리므로 재현이 어렵다.
  # 작업 설정이 MultipleInstances=IgnoreNew + ExecutionTimeLimit=PT72H 라, 한 번 멈추면
  # 최대 사흘간 감시가 통째로 공백이 된다. 고아 스텁(수 MB, 포트 미점유)은 그 위험을 감수할 값어치가 없다.
  # 정상 경로는 헬스 폴링만으로 끝낸다. 청소는 아래 down 경로에서만 — 그땐 어차피 재기동이 필요하고,
  # 거기서도 Stop-ProcessBounded 로 블로킹을 막는다.
  Write-Status "healthy" "health 200"
  exit 0
}

# ── 2) 연속 실패 상한 확인 ──
$failCount++
if ($failCount -gt $MaxFail) {
  Write-Status "halted" "연속 실패 ${failCount}회 — 자동 재시작 중단(수동 확인 필요)"
  exit 1
}

# ── 3) 실제 프로세스 생존 확인 ──
# WireBoard.exe 는 이름만으로 판정한다(제품 전용 이름이라 오탐 없음).
# 과거엔 CommandLine 매칭을 요구했는데, 행(hang) 상태의 스텁은 PEB를 읽을 수 없어
# CommandLine 이 빈 문자열로 나온다 → kill 대상에서 빠져 고아 프로세스가 계속 쌓였다
# (2026-08-29 PID 23440/21408 사례). python.exe 는 무관한 프로세스를 죽이면 안 되므로
# launcher.py 명령줄 매칭을 그대로 요구한다.
# 남은 위험(미해결): 이 WMI 전수 열거는 상승권한에서 커널 고착 프로세스를 만나면 블로킹될 수 있다
# (위 정상 경로 주석 참조). down 경로는 프로세스 목록 없이는 일을 못 하므로 감수한다.
# 대신 작업 설정의 ExecutionTimeLimit 을 짧게(예: PT4M) 걸어 두는 것이 안전망이다 — 현재 PT72H, 변경에 상승권한 필요.
$running = Get-CimInstance Win32_Process -Filter "Name='WireBoard.exe' OR Name='python.exe'" |
  Where-Object { ($_.Name -eq 'WireBoard.exe') -or ($null -ne $_.CommandLine -and $_.CommandLine -match "launcher\.py") }
$killLeft = ""
if ($running) {
  # 프로세스는 있으나 헬스 무응답 → 좀비/행. 종료 후 재기동.
  # 여기서 블로킹되면 복구 자체가 영영 안 일어나므로 반드시 제한시간 종료를 쓴다.
  foreach ($p in $running) { Stop-ProcessBounded $p.ProcessId | Out-Null }
  Start-Sleep -Seconds 2
  # 종료 검증 — 살아남은 게 있으면 상태에 남겨 다음 점검에서 눈에 띄게 한다
  $survived = Get-CimInstance Win32_Process -Filter "Name='WireBoard.exe'" |
    Where-Object { $_.ProcessId -in $running.ProcessId }
  if ($survived) {
    $killLeft = " / 종료실패 PID=" + (($survived.ProcessId) -join ',')
    foreach ($s in $survived) { Add-Unkillable (Get-ProcKey $s) }
  }
}

# ── 4) 재시작 (exe 우선, 없으면 launcher.py) ──
$detail = ""
if (Test-Path $ExePath) {
  Start-Process $ExePath -WorkingDirectory $WB -WindowStyle Hidden
  $detail = "exe 재시작"
} elseif (Test-Path $Launcher) {
  Start-Process "python" -ArgumentList $Launcher -WorkingDirectory $WB -WindowStyle Hidden
  $detail = "launcher.py 재시작"
} else {
  Write-Status "down" "실행 파일 없음(exe/launcher 모두 부재)"
  exit 1
}

# 재기동 후 헬스 재확인
Start-Sleep -Seconds 8
$recovered = $false
try { $r2 = Invoke-WebRequest -Uri $HealthUrl -TimeoutSec 5 -UseBasicParsing; if ($r2.StatusCode -eq 200) { $recovered = $true } } catch {}

$obj = [PSCustomObject]@{
  status     = if ($recovered) { "restarted" } else { "down" }
  port_8764  = (Get-NetTCPConnection -LocalPort 8764 -State Listen -ErrorAction SilentlyContinue) -ne $null
  detail     = "$detail / 회복=$recovered$killLeft"
  fail_count = if ($recovered) { 0 } else { $failCount }
  checked_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
[System.IO.File]::WriteAllText($StatusFile, ($obj | ConvertTo-Json), $utf8)
exit $(if ($recovered) { 0 } else { 1 })
