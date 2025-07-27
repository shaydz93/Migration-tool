@echo off
:: Universal Migration Tool - Windows Launch Script
chcp 65001 > nul
title Migration Tool

echo.
echo Checking for Python...
python --version >nul 2>&1
if %errorlevel% equ 0 goto run

echo Python not found. Installing...
if not exist "Assets\python-installer.exe" (
    echo ❌ Python installer not found! Please download python-3.11.9.exe and save as Assets\python-installer.exe
    pause
    exit
)

echo Installing Python 3.11 (quiet mode)...
Assets\python-installer.exe /quiet InstallAllUsers=1 PrependPath=1
if %errorlevel% neq 0 (
    echo ❌ Python install failed. Try running as Administrator.
    pause
    exit
)

:: Wait for install to finish
timeout /t 5 >nul

:run
cd /d "%~dp0"
echo.
echo Starting migration tool...
python "%~dp0migrate.py"

if %errorlevel% neq 0 (
    echo ❌ Script failed. Is tkinter missing?
    echo    Install Python from python.org (includes Tk).
    pause
)

echo.
echo Migration tool closed.
pause