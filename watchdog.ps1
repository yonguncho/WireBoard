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
  Write-Status "healthy" "health 200"
  exit 0
}

# ── 2) 연속 실패 상한 확인 ──
$failCount++
if ($failCount -gt $MaxFail) {
  Write-Status "halted" "연속 실패 ${failCount}회 — 자동 재시작 중단(수동 확인 필요)"
  exit 1
}

# ── 3) 실제 프로세스 생존 확인(명령줄 기반, PID 재사용 오탐 방지) ──
$running = Get-CimInstance Win32_Process -Filter "Name='WireBoard.exe' OR Name='python.exe'" |
  Where-Object { $null -ne $_.CommandLine -and ($_.CommandLine -match "WireBoard" -or $_.CommandLine -match "launcher\.py") }
if ($running) {
  # 프로세스는 있으나 헬스 무응답 → 좀비/행. 종료 후 재기동.
  foreach ($p in $running) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
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
  detail     = "$detail / 회복=$recovered"
  fail_count = if ($recovered) { 0 } else { $failCount }
  checked_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
[System.IO.File]::WriteAllText($StatusFile, ($obj | ConvertTo-Json), $utf8)
exit $(if ($recovered) { 0 } else { 1 })
