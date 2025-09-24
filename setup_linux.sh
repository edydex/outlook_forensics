#!/bin/bash

echo "PST Email Extractor Setup Script for Linux"
echo "==========================================="

# Detect Linux distribution
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="sudo apt-get update && sudo apt-get install -y"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    INSTALL_CMD="sudo yum install -y"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    INSTALL_CMD="sudo dnf install -y"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    INSTALL_CMD="sudo pacman -S --noconfirm"
else
    echo "Unsupported Linux distribution. Please install packages manually:"
    echo "- libpst (or pst-utils)"
    echo "- python3"
    echo "- python3-venv"
    echo "- python3-pip"
    echo "- tesseract-ocr (optional)"
    exit 1
fi

echo "Detected package manager: $PKG_MANAGER"

# Install system packages
echo "Installing system packages..."
case $PKG_MANAGER in
    "apt")
        $INSTALL_CMD libpst4 python3 python3-venv python3-pip tesseract-ocr
        ;;
    "yum"|"dnf")
        $INSTALL_CMD libpst python3 python3-pip tesseract
        # Install venv separately for older systems
        python3 -m pip install --user virtualenv
        ;;
    "pacman")
        $INSTALL_CMD libpst python python-pip tesseract
        ;;
esac

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv forensics_app_env

# Activate virtual environment
echo "Activating virtual environment..."
source forensics_app_env/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Download sample keywords file if not present
if [ ! -f "sample_keywords.csv" ]; then
    echo "Downloading sample keywords file..."
    curl -O https://raw.githubusercontent.com/edydex/outlook_forensics/main/sample_keywords.csv
fi

# Install required Python packages
echo "Installing required Python packages..."
pip install PyPDF2==3.0.1 python-docx==0.8.11 pandas==2.1.3 pillow==10.1.0 pytesseract==0.3.10 openpyxl==3.1.2 xlrd==2.0.1 pytz==2023.3

echo ""
echo "============================================"
echo "Setup completed successfully!"
echo "============================================"
echo ""
echo "To run the Forensics Application:"
echo "1. Navigate to the project directory"
echo "2. Activate the virtual environment:"
echo "   source forensics_app_env/bin/activate"
echo "3. Run the application:"
echo "   python3 forensics_app.py"
echo ""
echo "To deactivate the virtual environment when done:"
echo "   deactivate"
echo ""
echo "Note: You must activate the virtual environment each time"
echo "before running the application."