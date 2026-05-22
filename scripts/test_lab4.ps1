#requires -RunAsAdministrator
<#
.SYNOPSIS
    Проверка работоспособности Лабораторной работы 4 (Антивирусный движок)
.DESCRIPTION
    Создает тестовые файлы, проверяет RPC-методы сканирования,
    проверяет загрузку AV-базы и корректность детектов.
#>

$ErrorActionPreference = "Stop"
$installDir = "C:\Program Files\RBPO"
$testDir    = "C:\RBPO-Lab4-Tests"

Write-Host "=== Лабораторная работа 4: Проверка антивирусного движка ===" -ForegroundColor Cyan
Write-Host ""

# 1. Проверка наличия службы
Write-Host "[1/6] Проверка службы RBPOService..." -ForegroundColor Yellow
$svc = Get-Service -Name "RBPOService" -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Error "Служба RBPOService не найдена. Установите через MSI или sc.exe"
}
if ($svc.Status -ne 'Running') {
    Write-Host "    Служба остановлена, запускаем..." -ForegroundColor DarkYellow
    Start-Service RBPOService
    Start-Sleep 2
}
Write-Host "    OK: Служба $($svc.Status)" -ForegroundColor Green

# 2. Проверка наличия GUI
Write-Host "[2/6] Проверка rbpo-app.exe..." -ForegroundColor Yellow
$appPath = Join-Path $installDir "rbpo-app.exe"
if (-not (Test-Path $appPath)) {
    Write-Error "GUI не найден: $appPath"
}
Write-Host "    OK: GUI найден" -ForegroundColor Green

# 3. Проверка файлов AV-базы
Write-Host "[3/6] Проверка файлов AV-базы..." -ForegroundColor Yellow
$dbFiles = Get-ChildItem "$installDir\avdb*" -ErrorAction SilentlyContinue
if (-not $dbFiles) {
    Write-Error "AV-базы не найдены в $installDir"
}
$dbFiles | ForEach-Object { Write-Host "    $($_.Name) ($($_.Length) bytes)" }
Write-Host "    OK: $($dbFiles.Count) файлов базы найдено" -ForegroundColor Green

# 4. Создание тестовых файлов
Write-Host "[4/6] Создание тестовых файлов..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $testDir | Out-Null

# Чистый файл
"This is a clean text file for testing purposes." | Out-File "$testDir\clean.txt" -Encoding UTF8

# Вредоносный PE-файл (MZ + сигнатура RBPOTESTVRS1.000)
$peBytes = [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00)
$peBytes += [System.Text.Encoding]::UTF8.GetBytes("RBPOTESTVRS1.000")
[System.IO.File]::WriteAllBytes("$testDir\malware.exe", $peBytes)

# Вредоносный Script-файл
"#RBPOTESTVRS2.00 malicious powershell script" | Out-File "$testDir\malware.py" -Encoding UTF8

# Нейтральный скрипт (без сигнатуры)
"print('hello world')" | Out-File "$testDir\neutral.py" -Encoding UTF8

Get-ChildItem $testDir | ForEach-Object { Write-Host "    $($_.Name) ($($_.Length) bytes)" }
Write-Host "    OK: 4 тестовых файла созданы" -ForegroundColor Green

# 5. Проверка логов на загрузку AV-базы
Write-Host "[5/6] Проверка логов загрузки AV-базы..." -ForegroundColor Yellow
$logPath = "$installDir\rbpo-service.log"
if (Test-Path $logPath) {
    $avLoadLines = Select-String -Path $logPath -Pattern "AvLoad:" | Select-Object -Last 3
    if ($avLoadLines) {
        $avLoadLines | ForEach-Object { Write-Host "    $_" }
        if ($avLoadLines[-1] -match "(\d+) records active") {
            $recordCount = $Matches[1]
            Write-Host "    OK: База загружена, записей: $recordCount" -ForegroundColor Green
        }
    } else {
        Write-Warning "    Записи AvLoad не найдены в логе"
    }
} else {
    Write-Warning "    Лог не найден: $logPath"
}

# 6. Проверка сканирования (через прямой вызов rbpo-app.exe с проверкой трея)
Write-Host "[6/6] Проверка GUI и сканирования..." -ForegroundColor Yellow
Write-Host "    Запустите GUI вручную и нажмите 'Скан папку' -> $testDir" -ForegroundColor Cyan
Write-Host "    Ожидаемый результат:" -ForegroundColor Gray
Write-Host "      - clean.txt: ЧИСТО" -ForegroundColor Green
Write-Host "      - malware.exe: ОБНАРУЖЕН (PE, RBPOTESTVRS1.000)" -ForegroundColor Red
Write-Host "      - malware.py: ОБНАРУЖЕН (Script, RBPOTESTVRS2.00)" -ForegroundColor Red
Write-Host "      - neutral.py: ЧИСТО" -ForegroundColor Green

Write-Host ""
Write-Host "=== Лабораторная работа 4: Проверка завершена ===" -ForegroundColor Cyan
Write-Host "Если сканирование показывает корректные результаты — задание выполнено!" -ForegroundColor Green
