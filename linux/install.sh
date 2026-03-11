#!/bin/bash
#
# ArkShield Linux Installer
# Installs ArkShield as system application
#

set -e

echo "========================================"
echo "  ArkShield Linux Installer"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/arkshield"
BIN_LINK="/usr/local/bin/arkshield"
DESKTOP_FILE="/usr/share/applications/arkshield.desktop"

# Check Python version
echo "[1/5] Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "  Found Python $PYTHON_VERSION"

if ! python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
    echo "❌ Python 3.8+ required"
    exit 1
fi

# Install system dependencies
echo "[2/5] Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    # Debian/Ubuntu
    apt-get update
    apt-get install -y python3-pip python3-venv python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.0
elif command -v dnf &> /dev/null; then
    # Fedora
    dnf install -y python3-pip python3-gobject gtk3 webkit2gtk3
elif command -v pacman &> /dev/null; then
    # Arch Linux
    pacman -S --noconfirm python-pip python-gobject gtk3 webkit2gtk
else
    echo "⚠️  Warning: Unsupported package manager. Please install GTK3 and WebKit2 manually."
fi

# Create installation directory
echo "[3/5] Creating installation directory..."
mkdir -p "$INSTALL_DIR"
cp -r ../src "$INSTALL_DIR/"
cp arkshield_app.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

# Create virtual environment and install dependencies
echo "[4/5] Installing Python dependencies..."
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create launcher script
echo "[5/5] Creating launcher..."
cat > "$BIN_LINK" << EOF
#!/bin/bash
cd "$INSTALL_DIR"
source venv/bin/activate
python arkshield_app.py "\$@"
EOF
chmod +x "$BIN_LINK"

# Create desktop entry
cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=ArkShield Security Monitor
Comment=Real-time system security monitoring
Exec=$BIN_LINK
Icon=security-high
Terminal=false
Categories=System;Security;Monitor;
Keywords=security;monitor;threat;
StartupNotify=true
EOF

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database /usr/share/applications
fi

echo ""
echo "========================================"
echo "  ✅ Installation Complete!"
echo "========================================"
echo ""
echo "To run ArkShield:"
echo "  1. Command line: arkshield"
echo "  2. Application menu: Search for 'ArkShield'"
echo ""
echo "Installation location:"
echo "  $INSTALL_DIR"
echo ""
echo "To uninstall:"
echo "  sudo rm -rf $INSTALL_DIR"
echo "  sudo rm $BIN_LINK"
echo "  sudo rm $DESKTOP_FILE"
echo ""
