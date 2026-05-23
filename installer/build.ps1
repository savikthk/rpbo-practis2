param(
    [string]$SourceDir = "build\Release",
    [string]$VCRedistPath = "C:\Program Files (x86)\Common Files\Merge Modules\Microsoft_VC143_CRT_x64.msm",
    [string]$OutputMsi = "build\Release\RBPO-Setup.msi"
)

$candle = "C:\Program Files (x86)\WiX Toolset v3.11\bin\candle.exe"
$light  = "C:\Program Files (x86)\WiX Toolset v3.11\bin\light.exe"

if (-not (Test-Path $candle)) {
    Write-Error "candle.exe not found. Install WiX Toolset v3.11."
    exit 1
}
if (-not (Test-Path $light)) {
    Write-Error "light.exe not found. Install WiX Toolset v3.11."
    exit 1
}

& $candle -arch x64 -dSourceDir="$SourceDir" -dVCRedistPath="$VCRedistPath" -o "installer\Product.wixobj" "installer\Product.wxs"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $light -ext WixUIExtension -out "$OutputMsi" "installer\Product.wixobj"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Installer built successfully: $OutputMsi"
