# Quick Start Local Threat Ingestion Script (PowerShell)
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Initializing local security log threat simulation..." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$GeneratorScript = Join-Path $ScriptDir "threat_generator.py"

python $GeneratorScript --attack-type all

Write-Host "`n[✓] Telemetry injected successfully." -ForegroundColor Green
Write-Host "[✓] Check your Alert Console at: http://localhost" -ForegroundColor Green
