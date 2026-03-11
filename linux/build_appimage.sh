#!/bin/bash
#
# ArkShield AppImage Builder for Linux
# Creates portable executable for Linux distributions
#

set -e

echo "========================================"
echo "  Building ArkShield Linux AppImage"
echo "========================================"

# Configuration
APP_NAME="ArkShield"
APP_VERSION="1.0.0"
BUILD_DIR="$(pwd)/build"
DIST_DIR="$(pwd)/dist"
APPDIR="$BUILD_DIR/AppDir"

# Clean previous builds
echo "[1/6] Cleaning previous builds..."
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR" "$APPDIR"

# Create Python virtual environment
echo "[2/6] Creating virtual environment..."
python3 -m venv "$BUILD_DIR/venv"
source "$BUILD_DIR/venv/bin/activate"

# Install dependencies
echo "[3/6] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# Build with PyInstaller
echo "[4/6] Building with PyInstaller..."
pyinstaller \
    --name "$APP_NAME" \
    --onefile \
    --windowed \
    --clean \
    --distpath "$DIST_DIR" \
    --workpath "$BUILD_DIR" \
    --add-data "../src:src" \
    --add-data "../src/arkshield/api/dashboard.html:src/arkshield/api" \
    --add-data "../src/arkshield/config/ai_config.json:src/arkshield/config" \
    --hidden-import uvicorn \
    --hidden-import fastapi \
    --hidden-import webview \
    --hidden-import psutil \
    arkshield_app.py

# Create AppDir structure
echo "[5/6] Creating AppDir structure..."
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Copy executable
cp "$DIST_DIR/$APP_NAME" "$APPDIR/usr/bin/"

# Copy desktop file
cp arkshield.desktop "$APPDIR/usr/share/applications/"

# Create AppRun script
cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin/:${PATH}"
exec "${HERE}/usr/bin/ArkShield" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# Download appimagetool if not exists
echo "[6/6] Creating AppImage..."
APPIMAGETOOL="$BUILD_DIR/appimagetool-x86_64.AppImage"
if [ ! -f "$APPIMAGETOOL" ]; then
    echo "  Downloading appimagetool..."
    wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -O "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"
fi

# Build AppImage
ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "$DIST_DIR/$APP_NAME-$APP_VERSION-x86_64.AppImage"

echo ""
echo "========================================"
echo "  ✅ Build Complete!"
echo "========================================"
echo ""
echo "AppImage location:"
echo "  → $DIST_DIR/$APP_NAME-$APP_VERSION-x86_64.AppImage"
echo ""
echo "To run:"
echo "  chmod +x $DIST_DIR/$APP_NAME-$APP_VERSION-x86_64.AppImage"
echo "  ./$DIST_DIR/$APP_NAME-$APP_VERSION-x86_64.AppImage"
echo ""
echo "To install system-wide:"
echo "  sudo cp $DIST_DIR/$APP_NAME-$APP_VERSION-x86_64.AppImage /usr/local/bin/arkshield"
echo "  sudo cp arkshield.desktop /usr/share/applications/"
echo ""
