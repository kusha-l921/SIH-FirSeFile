<#
.SYNOPSIS
    FirSeFile Forensic Recovery Pipeline — Windows Test Execution Script

.DESCRIPTION
    Runs forensic deleted-data and metadata recovery against forensic evidence disk images
    on Windows without requiring io_uring or filesystem kernel mounts.

.PARAMETER ImagePath
    Path to the forensic evidence disk image (.img / .dd / .raw / .bin).
    Default: tests/fixtures/xfs_deleted_synthetic.img

.PARAMETER Json
    If specified, outputs results in JSON format.

.PARAMETER OutputDir
    Optional directory to write recovered files.

.EXAMPLE
    .\tools\run_recovery.ps1
    .\tools\run_recovery.ps1 -ImagePath tests\fixtures\btrfs_deleted_synthetic.img
    .\tools\run_recovery.ps1 -ImagePath tests\fixtures\xfs_deleted_synthetic.img -OutputDir recovered\
#>

param(
    [string]$ImagePath = "tests/fixtures/xfs_deleted_synthetic.img",
    [switch]$Json,
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# Ensure in project root
Set-Location $ProjectRoot

# Generate fixtures if not present
if (-not (Test-Path "tests/fixtures/xfs_deleted_synthetic.img")) {
    Write-Host "Generating synthetic forensic fixtures..." -ForegroundColor Cyan
    python scripts/generate_synthetic_fixtures.py
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  FirSeFile Forensic Recovery Engine (Windows Mode)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Evidence Image: $ImagePath"
Write-Host "Platform Mode:  PortableImageAcquisition (Standard File I/O)"
Write-Host "High-Perf Mode: Linux io_uring unavailable on Windows (Portable Engine Active)" -ForegroundColor Yellow
Write-Host ""

$cmdArgs = @("tools/run_recovery.py", $ImagePath)
if ($Json) {
    $cmdArgs += "--json"
}
if ($OutputDir -ne "") {
    $cmdArgs += "--output-dir"
    $cmdArgs += $OutputDir
}

python @cmdArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host "Recovery completed successfully." -ForegroundColor Green
} else {
    Write-Host "Recovery failed with exit code $LASTEXITCODE." -ForegroundColor Red
}
