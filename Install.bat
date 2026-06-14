@echo off
setlocal
cd /d "%~dp0"

echo.
echo ========================================
echo  Arbiterion - First Time Setup
echo ========================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo Python is not installed.
    echo Install Python 3.11+ from https://www.python.org/downloads/
    echo Check "Add python.exe to PATH" during install.
    pause
    exit /b 1
)

python -m venv .venv
if errorlevel 1 (
    echo Failed to create virtual environment.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if not exist .env (
    copy .env.example .env >nul
    echo Created .env from template.
)

echo.
echo Setup complete.
echo Next: double-click "Start Arbiterion.bat"
echo.
pause
