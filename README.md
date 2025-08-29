# PST Email Extractor with Keyword Scanner

A comprehensive tool for extracting specific emails from PST files and scanning them for sensitive keywords.

## Features

- Extract emails from PST files using Message IDs
- Keyword scanning across email bodies and attachments
- Support for multiple file types (PDF, Word, Excel, images with OCR)
- Interactive GUI with results browser
- HTML report generation for sharing results
- Cross-platform support (macOS, Linux, Windows*)

## Platform Requirements

### macOS (Recommended)
- macOS 10.14 or later
- Homebrew (will be installed automatically)
- Works natively on both Intel and Apple Silicon Macs

### Linux
- Most modern Linux distributions (Ubuntu, CentOS, Fedora, Arch)
- Package manager (apt, yum, dnf, or pacman)
- X11 or Wayland for GUI

### Windows*
- Windows 10 or later
- **Note: Limited support due to libpst availability**
- Consider using WSL or Linux VM for full functionality

## Quick Start

### macOS Setup
```bash
chmod +x setup.sh
./setup.sh
```

### Linux Setup
```bash
chmod +x setup_linux.sh
./setup_linux.sh
```

### Windows Setup
```batch
setup_windows.bat
```

## Running the Application

After setup, always run within the virtual environment:

### macOS/Linux
```bash
# Activate virtual environment
source pst_extractor_env/bin/activate

# Run the application
python3 email_extractor.py

# When done, deactivate
deactivate
```

### Windows
```batch
REM Activate virtual environment
pst_extractor_env\Scripts\activate.bat

REM Run the application
python email_extractor.py

REM When done, deactivate
deactivate
```

## Usage

1. **Select PST File**: Choose your Outlook PST file
2. **Select Output Directory**: Where extracted files will be saved
3. **Select Keywords File**: CSV/TXT file containing sensitive keywords
4. **Enter Email IDs**: Paste compromised Message-IDs (one per line)
5. **Click "Extract & Scan Emails"**: Process and analyze

## Output Files

- Individual email files (.eml)
- Attachment folders
- CSV summary report
- JSON detailed report
- Interactive HTML report

## Supported File Types for Keyword Scanning

- **Email bodies**: Plain text content
- **Attachments**: PDF, Word (.doc/.docx), Excel (.xls/.xlsx), Images (with OCR)
- **Text files**: .txt, .csv, .log

## Troubleshooting

### macOS Issues
- If Homebrew installation fails, install manually from https://brew.sh
- For Apple Silicon Macs, ensure Homebrew is in PATH

### Linux Issues
- If package installation fails, try updating package manager
- Some distributions may need additional repositories

### Windows Issues
- libpst is not easily available on Windows
- Consider using WSL: `wsl --install` then follow Linux instructions
- Alternative: Use VirtualBox with Ubuntu

## Dependencies

### System Dependencies
- libpst (readpst command)
- Python 3.8+
- Tesseract OCR (optional, for image scanning)

### Python Packages
- PyPDF2 (PDF processing)
- python-docx (Word document processing)
- pandas (Excel processing)
- Pillow (Image processing)
- pytesseract (OCR)
- openpyxl (Excel processing)

## Security Note

This tool processes potentially sensitive data. Ensure:
- Run on trusted systems only
- Secure disposal of temporary files
- Proper handling of extracted content
- Review output before sharing

## License

This project is provided as-is for educational and professional use.