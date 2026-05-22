param(
    [Parameter(Mandatory=$true)][string]$InputFile,
    [Parameter(Mandatory=$true)][string]$OutputFile
)

Add-Type -AssemblyName System.Drawing

$bmp  = New-Object System.Drawing.Bitmap($InputFile)
$icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
$fs   = [System.IO.File]::Create($OutputFile)
$icon.Save($fs)
$fs.Close()
$icon.Dispose()
$bmp.Dispose()

Write-Host "Icon converted: $InputFile -> $OutputFile"
