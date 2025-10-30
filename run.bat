@echo off
echo Starting Siebel Log Analyzer...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check if tkinter is available
python -c "import tkinter" >nul 2>&1
if errorlevel 1 (
    echo ERROR: tkinter is not available
    echo tkinter should be included with Python on Windows
    echo Please reinstall Python or contact your administrator
    pause
    exit /b 1
)

echo Python environment verified successfully
echo Launching Siebel Log Analyzer...
echo.

REM Run the application
python start_app.py

REM Pause to see any error messages
if errorlevel 1 (
    echo.
    echo Application exited with an error
    pause
)