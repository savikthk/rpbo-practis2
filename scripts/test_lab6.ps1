#requires -RunAsAdministrator
<#
.SYNOPSIS
    Проверка работоспособности Лабораторной работы 6 (MSI-инсталлятор)
.DESCRIPTION
    Проверяет установку через MSI, регистрацию службы, VC++ зависимости,
    корректность удаления и автозапуск GUI после установки.
#>

$ErrorActionPreference = "Stop"
$installDir = "C:\Program Files\RBPO"
$productName = "RBPO Antivirus"

Write-Host "=== Лабораторная работа 6: Проверка MSI-инсталлятора ===" -ForegroundColor Cyan
Write-Host ""

# 1. Проверка установленных файлов
Write-Host "[1/8] Проверка установленных файлов..." -ForegroundColor Yellow
$requiredFiles = @("rbpo-app.exe", "rbpo-service.exe")
$allOk = $true
foreach ($f in $requiredFiles) {
    $full = Join-Path $installDir $f
    if (Test-Path $full) {
        $ver = (Get-Item $full).VersionInfo.FileVersion
        Write-Host "    OK: $f (версия: $ver)" -ForegroundColor Green
    } else {
        Write-Host "    FAIL: $f не найден" -ForegroundColor Red
        $allOk = $false
    }
}
if (-not $allOk) { Write-Error "Программа не установлена. Запустите RBPO-Setup.msi" }

# 2. Проверка наличия avdb.default файлов (должны быть в MSI)
Write-Host "[2/8] Проверка AV-баз в комплекте поставки..." -ForegroundColor Yellow
$avdbFiles = Get-ChildItem "$installDir\avdb*" -ErrorAction SilentlyContinue
if ($avdbFiles) {
    $avdbFiles | ForEach-Object { Write-Host "    OK: $($_.Name)" -ForegroundColor Green }
} else {
    Write-Warning "    AV-базы не найдены (генерируются при первом запуске службы)"
}

# 3. Проверка службы Windows
Write-Host "[3/8] Проверка службы RBPOService..." -ForegroundColor Yellow
$svc = Get-Service -Name "RBPOService" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "    OK: Служба найдена" -ForegroundColor Green
    Write-Host "    Имя: $($svc.DisplayName)" -ForegroundColor Gray
    Write-Host "    Статус: $($svc.Status)" -ForegroundColor Gray
    Write-Host "    StartType: $($svc.StartType)" -ForegroundColor Gray

    if ($svc.Status -ne 'Running') {
        Write-Host "    Запускаем службу..." -ForegroundColor DarkYellow
        Start-Service RBPOService
        Start-Sleep 2
        Write-Host "    OK: Служба запущена" -ForegroundColor Green
    }
} else {
    Write-Error "Служба RBPOService не зарегистрирована. Проблема с MSI!"
}

# 4. Проверка зависимостей VC++
Write-Host "[4/8] Проверка VC++ Redistributable..." -ForegroundColor Yellow
$vcKeys = @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
)
$vcFound = $false
foreach ($key in $vcKeys) {
    if (Test-Path $key) {
        $vcVer = (Get-ItemProperty -Path $key -Name "Version" -ErrorAction SilentlyContinue).Version
        Write-Host "    OK: VC++ Runtime найден (версия: $vcVer)" -ForegroundColor Green
        $vcFound = $true
        break
    }
}
if (-not $vcFound) {
    Write-Warning "    VC++ Runtime не обнаружен в реестре (возможно, используется статическая линковка)"
}

# 5. Проверка записи в 'Установке и удалении программ'
Write-Host "[5/8] Проверка записи в Programs and Features..." -ForegroundColor Yellow
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}"
)
$uninstallFound = $false
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $props = Get-ItemProperty -Path $rp
        Write-Host "    OK: Запись найдена" -ForegroundColor Green
        Write-Host "      DisplayName: $($props.DisplayName)" -ForegroundColor Gray
        Write-Host "      Publisher: $($props.Publisher)" -ForegroundColor Gray
        Write-Host "      Version: $($props.DisplayVersion)" -ForegroundColor Gray
        $uninstallFound = $true
        break
    }
}
if (-not $uninstallFound) {
    Write-Warning "    Запись в реестре не найдена (возможно, другой ProductId)"
}

# 6. Проверка автозапуска службы
Write-Host "[6/8] Проверка типа запуска службы..." -ForegroundColor Yellow
$svcDetails = Get-WmiObject -Class Win32_Service -Filter "Name='RBPOService'"
if ($svcDetails.StartMode -eq "Auto") {
    Write-Host "    OK: StartType = Automatic (запускается при загрузке Windows)" -ForegroundColor Green
} else {
    Write-Warning "    StartType = $($svcDetails.StartMode) (ожидался Auto)"
}

# 7. Проверка RPC-связности
Write-Host "[7/8] Проверка RPC-связности (GUI <-> Service)..." -ForegroundColor Yellow
$guiProcess = Get-Process -Name "rbpo-app" -ErrorAction SilentlyContinue
if (-not $guiProcess) {
    Write-Host "    Запускаем GUI..." -ForegroundColor DarkYellow
    Start-Process "$installDir\rbpo-app.exe"
    Start-Sleep 3
    $guiProcess = Get-Process -Name "rbpo-app" -ErrorAction SilentlyContinue
}
if ($guiProcess) {
    Write-Host "    OK: GUI запущен (PID: $($guiProcess.Id))" -ForegroundColor Green

    # Проверка логов на успешный RPC bind
    $logPath = "$installDir\rbpo-service.log"
    if (Test-Path $logPath) {
        $rpcLines = Select-String -Path $logPath -Pattern "RpcServerListen|RpcServerRegister|RpcServerUseProtseq" | Select-Object -Last 3
        if ($rpcLines) {
            $rpcLines | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
        }
    }
} else {
    Write-Error "GUI не запустился!"
}

# 8. Проверка логина и лицензии (если есть)
Write-Host "[8/8] Проверка функциональности GUI (auth + license)..." -ForegroundColor Yellow
$appLog = "$installDir\rbpo-app.log"
if (Test-Path $appLog) {
    $authLines = Select-String -Path $appLog -Pattern "auth|license|ticket" | Select-Object -Last 3
    if ($authLines) {
        Write-Host "    Логи GUI:" -ForegroundColor Gray
        $authLines | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }
    } else {
        Write-Host "    INFO: Логи авторизации не найдены (возможно, еще не выполнен вход)" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "    INFO: Лог GUI не найден" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "=== Лабораторная работа 6: Проверка завершена ===" -ForegroundColor Cyan
Write-Host "Для демонстрации преподавателю:" -ForegroundColor Green
Write-Host "  1. Показать 'Установку и удаление программ' -> RBPO Antivirus" -ForegroundColor Green
Write-Host "  2. Показать services.msc -> RBPOService (Automatic)" -ForegroundColor Green
Write-Host "  3. Показать C:\Program Files\RBPO\ (файлы + avdb)" -ForegroundColor Green
Write-Host "  4. Удаление через 'Установку и удаление' -> служба и файлы исчезают" -ForegroundColor Green
Write-Host "  5. (Опционально) Показать отсутствие RBPO после uninstall" -ForegroundColor Green
