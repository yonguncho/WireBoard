# verify_edr.ps1 - WireBoard.exe EDR/AV detection verification
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ExePath = Join-Path $ScriptDir "dist\WireBoard.exe"
$OutFile = Join-Path $ScriptDir "verify_edr_result.json"

$result = [ordered]@{
    exe                = $ExePath
    scanned_at         = (Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")
    defender_available = $false
    threat_found       = $false
    threat_detail      = $null
    status             = "UNKNOWN"
    error              = $null
}

if (-not (Test-Path $ExePath)) {
    $result.error  = "EXE not found: $ExePath"
    $result.status = "ERROR"
    $result | ConvertTo-Json -Depth 3 | Set-Content $OutFile -Encoding UTF8
    Write-Error $result.error
    exit 1
}

# Try Windows Defender MpCmdRun.exe
$mpCmd = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
if (-not (Test-Path $mpCmd)) {
    $pattern = "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    $candidates = Get-Item $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
    if ($candidates) { $mpCmd = $candidates[0].FullName } else { $mpCmd = $null }
}

# --- Code-signing check (Get-AuthenticodeSignature) ---
$sig = Get-AuthenticodeSignature -FilePath $ExePath
$result.signature_status = $sig.Status.ToString()
$result.signer_subject   = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
if ($sig.Status -eq 'Valid') {
    $result.code_signed = $true
} else {
    $result.code_signed = $false
    # NotSigned is acceptable for internal tooling; log as WARN, not FAIL
    if ($sig.Status -ne 'NotSigned') {
        $result.status = "WARN_SIGNATURE_INVALID"
    }
}

# --- SHA-256 hash via certutil for audit trail ---
$certutilOut = certutil -hashfile $ExePath SHA256 2>&1
$hashLine = ($certutilOut | Where-Object { $_ -match '^[0-9a-f]{64}$' })
$result.file_sha256  = if ($hashLine) { $hashLine.Trim() } else { (Get-FileHash $ExePath -Algorithm SHA256).Hash }
$result.file_size_mb = [math]::Round((Get-Item $ExePath).Length / 1MB, 2)

if ($mpCmd -and (Test-Path $mpCmd)) {
    $result.defender_available = $true
    $scanOut = & $mpCmd -Scan -ScanType 3 -File $ExePath 2>&1
    if ($LASTEXITCODE -eq 2) {
        $result.threat_found  = $true
        $result.threat_detail = ($scanOut -join "`n")
        $result.status        = "FAIL_THREAT_DETECTED"
    } elseif ($result.status -ne "WARN_SIGNATURE_INVALID") {
        $result.status = "PASS"
    }
} else {
    # Defender CLI not found - hash + signature check only
    $result.defender_available = $false
    if ($result.status -ne "WARN_SIGNATURE_INVALID") {
        $result.status = "PASS_NO_DEFENDER"
    }
    $result.note = "MpCmdRun.exe not found; file hash and signature status recorded."
}

$result | ConvertTo-Json -Depth 3 | Set-Content $OutFile -Encoding UTF8

if ($result.status -like "FAIL*") {
    Write-Error "EDR verification FAILED: $($result.threat_detail)"
    exit 1
}

Write-Host "EDR verification: $($result.status) - $ExePath"
exit 0
