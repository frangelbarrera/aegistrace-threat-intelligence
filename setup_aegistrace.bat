@echo off
title AegisTrace Setup ^& Run
echo ============================================
echo   AegisTrace - Threat Intelligence Tool
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

REM 4. Install runtime dependencies
echo [*] Installing dependencies...
pip install -r requirements.txt

REM 5. Install the aegistrace package in editable mode
echo [*] Installing aegistrace package...
pip install -e .

REM 6. Download spaCy English model
echo [*] Downloading spaCy English model...
python -m spacy download en_core_web_sm

REM 7. Run AegisTrace
echo [*] Running AegisTrace...
python -m aegistrace

REM 8. Open dashboard in default browser if it exists
if exist dashboard.html (
    echo [*] Opening dashboard in browser...
    start dashboard.html
) else (
    echo [!] dashboard.html not found.
)

echo.
echo ============================================
echo   Process completed
echo ============================================
pause
