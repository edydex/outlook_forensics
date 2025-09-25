#!/bin/bash

echo "PST Email Extractor Setup Script for macOS"
echo "=========================================="

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "This script is designed for macOS. Please use the appropriate setup script for your platform."
    exit 1
fi

# Create project directory
PROJECT_DIR="outlook_forensics"
echo "Creating project directory: $PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for Apple Silicon Macs
    if [[ $(uname -m) == "arm64" ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
else
    echo "Homebrew is already installed."
fi

# Install libpst (for readpst command)
echo "Installing libpst (for PST file extraction)..."
brew install libpst

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 not found. Installing Python 3..."
    brew install python@3.11
else
    echo "Python 3 is already installed: $(python3 --version)"
fi

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Download required files
echo "Downloading application files..."

# Download main Python application
if [ ! -f "forensics_app.py" ]; then
    echo "Downloading forensics_app.py..."
    curl -O https://raw.githubusercontent.com/edydex/outlook_forensics/main/forensics_app.py
fi

# Download favicon
if [ ! -f "favicon_512.png" ]; then
    echo "Downloading favicon_512.png..."
    curl -O https://raw.githubusercontent.com/edydex/outlook_forensics/main/favicon_512.png
fi

# Download sample keywords file
if [ ! -f "sample_keywords.csv" ]; then
    echo "Downloading sample_keywords.csv..."
    curl -O https://raw.githubusercontent.com/edydex/outlook_forensics/main/sample_keywords.csv
fi

# Install required Python packages
echo "Installing required Python packages..."
pip install PyPDF2==3.0.1 python-docx==0.8.11 pandas==2.1.3 pillow==10.1.0 pytesseract==0.3.10 openpyxl==3.1.2 xlrd==2.0.1 pytz==2023.3

# Optional: Install Tesseract for OCR (if user wants to scan images)
echo "Installing Tesseract OCR (optional, for scanning images)..."
brew install tesseract

echo ""
echo "============================================"
echo "Setup completed successfully!"
echo "============================================"
echo ""
echo "All files have been downloaded to: $(pwd)"
echo ""
echo "To run the PST Email Extractor:"
echo "1. Navigate to the project directory (if not already there):"
echo "   cd $PROJECT_DIR"
echo "2. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo "3. Run the application:"
echo "   python3 forensics_app.py"
echo ""
echo "To deactivate the virtual environment when done:"
echo "   deactivate"
echo ""
echo "Note: You must activate the virtual environment each time"
echo "before running the application."