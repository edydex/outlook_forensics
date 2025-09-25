@echo off
echo PST Email Extractor Setup Script for Windows
echo ============================================

REM Create project directory
set PROJECT_DIR=outlook_forensics
echo Creating project directory: %PROJECT_DIR%
mkdir "%PROJECT_DIR%" 2>nul
cd "%PROJECT_DIR%"

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
python -m venv forensics_app_env

REM Activate virtual environment
echo Activating virtual environment...
call forensics_app_env\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Download required files
echo Downloading application files...

REM Check if curl is available, fallback to PowerShell
curl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Using PowerShell to download files...
    powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/edydex/outlook_forensics/main/forensics_app.py' -OutFile 'forensics_app.py'"
    powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/edydex/outlook_forensics/main/favicon_512.png' -OutFile 'favicon_512.png'"
    powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/edydex/outlook_forensics/main/sample_keywords.csv' -OutFile 'sample_keywords.csv'"
) else (
    echo Using curl to download files...
    curl -O https://raw.githubusercontent.com/edydex/outlook_forensics/main/forensics_app.py
    curl -O https://raw.githubusercontent.com/edydex/outlook_forensics/main/favicon_512.png
    curl -O https://raw.githubusercontent.com/edydex/outlook_forensics/main/sample_keywords.csv
)

REM Install required Python packages
echo Installing required Python packages...
pip install PyPDF2==3.0.1 python-docx==0.8.11 pandas==2.1.3 pillow==10.1.0 pytesseract==0.3.10 openpyxl==3.1.2 xlrd==2.0.1 pytz==2023.3

echo.
echo ============================================
echo Setup completed!
echo ============================================
echo.
echo All files have been downloaded to: %cd%
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
echo 1. Navigate to the project directory (if not already there):
echo    cd %PROJECT_DIR%
echo 2. Activate the virtual environment:
echo    forensics_app_env\Scripts\activate.bat
echo 3. Run the application:
echo    python forensics_app.py
echo.
echo To deactivate the virtual environment when done:
echo    deactivate
echo.
pause