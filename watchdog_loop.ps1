<#
  WireBoard 워치독 상주 루프 — 재부팅 전까지 쓰는 임시 대체물 (2026-08-31 도입).

  배경: 이 PC의 작업 스케줄러가 띄우는 powershell.exe 가 시작 지점에서 멈춘다.
        (RunLevel 무관. AgentKeepalive·ClaudeTokenRefresh 도 2026-08-25부터 Running 고착.
         Adobe·Firefox 등 비-PowerShell 작업은 rc=0 정상 완료 → 스케줄러 서비스 자체는 정상.)
        따라서 WireBoard_Watchdog 예약작업이 죽어 있어 5분 감시가 통째로 공백이었다.
        재부팅으로 스케줄러 경로가 복구되면 예약작업으로 돌아가고 이 루프는 필요 없다.

  실행(사용자 세션에서, 상승권한 불필요):
    Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',
      'C:\AI_WORKPLACE\WireBoard\watchdog_loop.ps1' -WindowStyle Hidden

  중지: Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
          ? { $_.CommandLine -match 'watchdog_loop' } | % { Stop-Process -Id $_.ProcessId -Force }
#>
$ErrorActionPreference = "SilentlyContinue"
$Watchdog  = "C:\AI_WORKPLACE\WireBoard\watchdog.ps1"
$LoopLog   = "C:\AI_WORKPLACE\WireBoard\watchdog_loop.log"
$IntervalS = 300

function Write-Loop([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
  Add-Content -Path $LoopLog -Value $line -Encoding UTF8
}

Write-Loop "루프 시작 (PID $PID, 간격 ${IntervalS}s)"
while ($true) {
  try {
    # 워치독 본체를 자식 프로세스로 돌린다 — 본체가 멈춰도 루프는 살아남게.
    $p = Start-Process powershell -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$Watchdog `
                       -WindowStyle Hidden -PassThru
    if ($p.WaitForExit(120000)) {
      if ($p.ExitCode -ne 0) { Write-Loop "워치독 exit=$($p.ExitCode)" }
    } else {
      Write-Loop "워치독 120초 초과 — 종료 시도 (PID $($p.Id))"
      try { $p.Kill() } catch { Write-Loop "종료 실패 PID $($p.Id) — 다음 주기 계속" }
    }
  } catch {
    Write-Loop "루프 오류: $($_.Exception.Message)"
  }
  Start-Sleep -Seconds $IntervalS
}
