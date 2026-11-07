@echo off
setlocal enabledelayedexpansion

title Cybex Recon Engine

echo ===================================================
echo           CYBEX RECON ENGINE LAUNCHER
echo   DNS Intelligence - Assessment - Threat Analysis
echo ===================================================
echo.

cd /d "%~dp0"

IF EXIST ".venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment .venv...
    call .venv\Scripts\activate.bat
) ELSE IF EXIST "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment venv...
    call venv\Scripts\activate.bat
) ELSE (
    echo [INFO] Virtual environment not found. Creating .venv...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Python not found or failed to create virtual environment.
        pause
        exit /b 1
    )
    call .venv\Scripts\activate.bat
)

echo [INFO] Verifying dependencies...
pip install -r requirements.txt --quiet

echo.
echo ===================================================
echo [OK] Application Ready
echo [>] Landing Page:  http://localhost:5000
echo [>] Console App:   http://localhost:5000/dashboard
echo.
echo Launching local browser...
echo Press Ctrl+C to terminate the server.
echo ===================================================
echo.

:: Automatically launch the default browser after server initializes
start "" cmd /c "ping 127.0.0.1 -n 3 >nul & start http://localhost:5000"

python app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application terminated with an error code.
    pause
)
