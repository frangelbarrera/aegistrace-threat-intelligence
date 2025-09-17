@echo off
title AegisTrace Setup & Run
echo ============================================
echo   🛡️  AegisTrace - Threat Intelligence Tool
echo ============================================
echo.

REM 1. Create virtual environment if it does not exist
if not exist venv (
    echo [*] Creating virtual environment...
    python -m venv venv
) else (
    echo [*] Virtual environment already exists.
)

REM 2. Activate virtual environment
call venv\Scripts\activate

REM 3. Upgrade pip to the latest version
echo [*] Upgrading pip...
python -m pip install --upgrade pip

REM 4. Install dependencies from requirements.txt
echo [*] Installing dependencies...
pip install -r requirements.txt

REM 5. Download spaCy English model
echo [*] Downloading spaCy English model...
python -m spacy download en_core_web_sm

REM 6. Run AegisTrace
echo [*] Running AegisTrace...
python main.py

REM 7. Open dashboard in default browser if it exists
if exist dashboard.html (
    echo [*] Opening dashboard in browser...
    start dashboard.html
) else (
    echo [!] dashboard.html not found.
)

echo.
echo ============================================
echo   ✅ Process completed
echo ============================================
pause
