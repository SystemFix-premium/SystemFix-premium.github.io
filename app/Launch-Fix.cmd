@echo off
rem SystemFix Security - запуск с правами администратора
rem Сканирует уязвимости и предлагает исправления (каждое - с подтверждением).
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Запрашиваю права администратора...
    powershell -NoProfile -Command "Start-Process -FilePath 'powershell' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%~dp0Scan-Fix.ps1','-Fix' -Verb RunAs"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scan-Fix.ps1" -Fix
pause
