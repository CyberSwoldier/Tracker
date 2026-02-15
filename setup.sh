#!/bin/bash
# Global Threat Intelligence Tracker - Setup Script

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║     Global Threat Intelligence Tracker - Installation        ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "[*] Checking Python version..."
python3_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "    Found: Python $python3_version"

if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Create directories
echo ""
echo "[*] Creating directory structure..."
mkdir -p data logs reports config
echo "    ✓ Directories created"

# Install dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages -q 2>&1 | grep -v "WARNING: The directory"
if [ $? -eq 0 ]; then
    echo "    ✓ Dependencies installed"
else
    echo "    ! Some warnings during installation (this is usually fine)"
fi

# Make scripts executable
echo ""
echo "[*] Making scripts executable..."
chmod +x threat_tracker.py query_threats.py demo.py
echo "    ✓ Scripts are now executable"

# Test installation
echo ""
echo "[*] Testing installation..."
if python3 -c "import requests, feedparser, colorama; print('OK')" 2>/dev/null | grep -q "OK"; then
    echo "    ✓ All dependencies loaded successfully"
else
    echo "    ! Warning: Some dependencies may not be properly installed"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Installation Complete!                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Quick Start:"
echo "  1. Run demo:        python3 demo.py"
echo "  2. Collect threats: python3 threat_tracker.py"
echo "  3. View help:       python3 threat_tracker.py --help"
echo ""
echo "Documentation:"
echo "  • README.md      - Full documentation"
echo "  • QUICKSTART.md  - Quick reference guide"
echo "  • OVERVIEW.md    - System architecture"
echo ""