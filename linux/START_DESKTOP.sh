#!/bin/bash
#
# ArkShield Linux Desktop Application Launcher
# Installs dependencies and runs the native application
#

echo "========================================"
echo "  ArkShield Desktop Application"
echo "  Linux Native Version"
echo "========================================"
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 not found"
    exit 1
fi

echo "[1/3] Checking dependencies..."

# Check if pywebview is installed
if ! python3 -c "import webview" 2>/dev/null; then
    echo "  Installing pywebview..."
    pip3 install --user pywebview
fi

# Check if GTK is available
if ! python3 -c "import gi" 2>/dev/null; then
    echo ""
    echo "⚠️  Warning: PyGObject (GTK bindings) not found"
    echo ""
    echo "Please install GTK dependencies:"
    echo ""
    echo "Ubuntu/Debian:"
    echo "  sudo apt-get install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.0"
    echo ""
    echo "Fedora:"
    echo "  sudo dnf install python3-gobject gtk3 webkit2gtk3"
    echo ""
    echo "Arch:"
    echo "  sudo pacman -S python-gobject gtk3 webkit2gtk"
    echo ""
    exit 1
fi

echo "[2/3] Checking backend dependencies..."
pip3 install --quiet --user fastapi uvicorn psutil pydantic 2>/dev/null

echo ""
echo "[3/3] Starting ArkShield Desktop..."
echo ""

python3 arkshield_app.py

if [ $? -ne 0 ]; then
    echo ""
    echo "========================================"
    echo "  ❌ Error: Failed to start application"
    echo "========================================"
    echo ""
    echo "Try running manually:"
    echo "  python3 arkshield_app.py"
    echo ""
    exit 1
fi

exit 0
