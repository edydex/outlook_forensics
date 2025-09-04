#!/bin/bash

echo "PST Email Extractor Setup Script for macOS"
echo "=========================================="

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "This script is designed for macOS. Please use the appropriate setup script for your platform."
    exit 1
fi

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
python3 -m venv pst_extractor_env

# Activate virtual environment
echo "Activating virtual environment..."
source pst_extractor_env/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install required Python packages
echo "Installing required Python packages..."
pip install PyPDF2 python-docx pandas pillow pytesseract openpyxl

# Optional: Install Tesseract for OCR (if user wants to scan images)
echo "Installing Tesseract OCR (optional, for scanning images)..."
brew install tesseract

echo ""
echo "============================================"
echo "Setup completed successfully!"
echo "============================================"
echo ""
echo "To run the PST Email Extractor:"
echo "1. Navigate to the project directory"
echo "2. Activate the virtual environment:"
echo "   source pst_extractor_env/bin/activate"
echo "3. Run the application:"
echo "   python3 email_extractor.py"
echo ""
echo "To deactivate the virtual environment when done:"
echo "   deactivate"
echo ""
echo "Note: You must activate the virtual environment each time"
echo "before running the application."