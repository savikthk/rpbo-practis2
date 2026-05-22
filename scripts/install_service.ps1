# Install/reinstall RBPO Windows service. Run AS ADMINISTRATOR.
$ErrorActionPreference = 'Stop'

$svcName = 'RBPOService'
$svcDisp = 'RBPO Service'
$exePath = 'C:\Users\dimam\Desktop\rbpo-front\build\Release\rbpo-service.exe'

if (-not (Test-Path $exePath)) {
    Write-Error "Not found: $exePath. Build the project first."
    exit 1
}

# 1. Stop and remove old service if exists
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Stopping old service..."
    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "Removing old service..."
    & sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 2
}

# 2. Create new service
Write-Host "Creating service $svcName..."
& sc.exe create $svcName binPath= "`"$exePath`"" DisplayName= "`"$svcDisp`"" start= demand
if ($LASTEXITCODE -ne 0) { Write-Error "sc create failed: $LASTEXITCODE"; exit 1 }

# 3. Start
Write-Host "Starting service..."
& sc.exe start $svcName
if ($LASTEXITCODE -ne 0) { Write-Error "sc start failed: $LASTEXITCODE"; exit 1 }

# 4. Wait for RUNNING
for ($i = 0; $i -lt 20; $i++) {
    $s = Get-Service -Name $svcName
    if ($s.Status -eq 'Running') { break }
    Start-Sleep -Milliseconds 500
}

$s = Get-Service -Name $svcName
Write-Host "---"
Write-Host "Status: $($s.Status)"
Write-Host "Service log: C:\Users\dimam\Desktop\rbpo-front\build\Release\rbpo-service.log"

if ($s.Status -ne 'Running') {
    Write-Warning "Service is not RUNNING. Check the log."
    exit 1
}

Write-Host ""
Write-Host "Done. Service is running. The GUI should appear in the tray." -ForegroundColor Green
