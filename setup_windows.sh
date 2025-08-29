@echo off
echo PST Email Extractor Setup Script for Windows
echo ============================================

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH.
    echo Please install Python 3.8+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo Python is installed: 
python --version

REM Check if readpst is available (unlikely on Windows)
readpst --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: readpst command not found.
    echo This tool requires libpst which is not easily available on Windows.
    echo Consider using WSL (Windows Subsystem for Linux) or a Linux VM.
    echo Alternatively, you can try installing libpst through Cygwin or MSYS2.
    echo.
    echo Press any key to continue with Python setup anyway...
    pause
)

REM Create virtual environment
echo Creating Python virtual environment...
python -m venv pst_extractor_env

REM Activate virtual environment
echo Activating virtual environment...
call pst_extractor_env\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install required Python packages
echo Installing required Python packages...
pip install PyPDF2 python-docx pandas pillow pytesseract openpyxl

echo.
echo ============================================
echo Setup completed!
echo ============================================
echo.
echo IMPORTANT: This application requires libpst (readpst command)
echo which is not easily available on Windows.
echo.
echo Recommended solutions:
echo 1. Use WSL (Windows Subsystem for Linux) and run the Linux version
echo 2. Use a Linux virtual machine
echo 3. Install libpst through Cygwin or MSYS2
echo.
echo To run the application (if libpst is available):
echo 1. Navigate to the project directory
echo 2. Activate the virtual environment:
echo    pst_extractor_env\Scripts\activate.bat
echo 3. Run the application:
echo    python email_extractor.py
echo.
echo To deactivate the virtual environment when done:
echo    deactivate
echo.
pause