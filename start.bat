@echo off
title FirSeFile Forensic Recovery System
cd /d "%~dp0"

echo ========================================================================
echo   FirSeFile Forensic Recovery System Launcher (Windows)
echo ========================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python 3.10+ from https://www.python.org/
    pause
    exit /b 1
)

python run.py %*
if %errorlevel% neq 0 (
    pause
)
