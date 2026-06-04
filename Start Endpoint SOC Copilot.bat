@echo off
setlocal
cd /d "%~dp0"

if not exist .venv\Scripts\python.exe (
    echo Run Install.bat first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
python launcher.py
