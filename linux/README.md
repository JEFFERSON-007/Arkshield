# ArkShield Desktop Application - Linux

Native Linux desktop application for ArkShield security monitoring.

## 🚀 Features

- ✅ **Native Linux application** - No browser required
- ✅ **GTK integration** - Native Linux look and feel
- ✅ **System tray support** - Runs in background
- ✅ **AppImage format** - Run on any Linux distro
- ✅ **Auto-start server** - Backend starts automatically
- ✅ **Professional look** - Feels like a native Linux app

## 📦 Installation

### Option 1: System-wide Installation (Recommended)

Install ArkShield as a system application:

```bash
cd linux
sudo bash install.sh
```

This will:
1. Install to `/opt/arkshield`
2. Create launcher at `/usr/local/bin/arkshield`
3. Add desktop entry for application menu
4. Install all dependencies

Then run from terminal:
```bash
arkshield
```

Or search "ArkShield" in your application menu.

### Option 2: Run from Source (Development)

1. **Install system dependencies:**

**Ubuntu/Debian:**
```bash
sudo apt-get install python3-pip python3-venv python3-gi python3-gi-cairo \
     gir1.2-gtk-3.0 gir1.2-webkit2-4.0
```

**Fedora:**
```bash
sudo dnf install python3-pip python3-gobject gtk3 webkit2gtk3
```

**Arch Linux:**
```bash
sudo pacman -S python-pip python-gobject gtk3 webkit2gtk
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
python3 arkshield_app.py
```

### Option 3: Build AppImage (Portable)

Create a portable executable:

```bash
cd linux
bash build_appimage.sh
```

This creates:
```
linux/dist/ArkShield-1.0.0-x86_64.AppImage
```

Run it:
```bash
chmod +x dist/ArkShield-1.0.0-x86_64.AppImage
./dist/ArkShield-1.0.0-x86_64.AppImage
```

## 🎯 Usage

### Running the Application

**From system installation:**
```bash
arkshield
```

**From source:**
```bash
cd linux
python3 arkshield_app.py
```

**From AppImage:**
```bash
./ArkShield-1.0.0-x86_64.AppImage
```

The application will:
1. Start FastAPI server automatically on port 8000
2. Open native GTK window with dashboard
3. Monitor your system in real-time

## 📁 File Structure

```
linux/
├── arkshield_app.py          # Main desktop application
├── build_appimage.sh         # Build script for AppImage
├── install.sh                # System-wide installer
├── arkshield.desktop         # Desktop entry file
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── build/                    # Build artifacts (auto-generated)
└── dist/                     # Output AppImage location
    └── ArkShield-*.AppImage  # Portable executable
```

## 🔧 Configuration

### Port Configuration

If port 8000 is in use, the app automatically finds next available port.

### Window Size

Default: 1400x900 pixels  
Minimum: 1024x768 pixels  
Resizable: Yes

Edit in `arkshield_app.py`:
```python
window = webview.create_window(
    title="ArkShield Security Monitor",
    width=1400,      # Change this
    height=900,      # Change this
    min_size=(1024, 768)
)
```

## 🐛 Troubleshooting

### Issue: "Module not found" error
**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: GTK error on startup
**Solution:** Install GTK development packages:

**Ubuntu/Debian:**
```bash
sudo apt-get install gir1.2-gtk-3.0 gir1.2-webkit2-4.0
```

**Fedora:**
```bash
sudo dnf install gtk3 webkit2gtk3
```

### Issue: AppImage won't run
**Solution:**
```bash
# Make executable
chmod +x ArkShield-*.AppImage

# Install FUSE if needed
sudo apt-get install fuse libfuse2  # Ubuntu/Debian
sudo dnf install fuse              # Fedora
```

### Issue: Window doesn't open
**Solution:** Check if server started:
```bash
netstat -tuln | grep :8000
```

### Issue: Permission denied
**Solution:** Run installer with sudo:
```bash
sudo bash install.sh
```

## 📋 Requirements

### System Requirements
- **OS:** Linux (Ubuntu 20.04+, Fedora 35+, Arch, or similar)
- **Architecture:** x86_64 (64-bit)
- **RAM:** 2 GB minimum
- **Disk:** 100 MB free space

### Software Requirements
- **Python:** 3.8+
- **GTK:** 3.0+
- **WebKit2GTK:** 4.0+

## 🔒 Security Notes

- Server binds to `127.0.0.1` (localhost only)
- No external network access by default
- All monitoring uses Linux APIs (psutil, /proc, /sys)
- No data sent to external servers

## 🚀 Advanced Usage

### Auto-start on Login

**GNOME/Ubuntu:**
```bash
mkdir -p ~/.config/autostart
cp /usr/share/applications/arkshield.desktop ~/.config/autostart/
```

**KDE Plasma:**
```bash
cp /usr/share/applications/arkshield.desktop ~/.config/autostart/
```

### Run as Systemd Service

Create `/etc/systemd/system/arkshield.service`:
```ini
[Unit]
Description=ArkShield Security Monitor
After=network.target

[Service]
Type=simple
User=youruser
ExecStart=/usr/local/bin/arkshield
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable arkshield
sudo systemctl start arkshield
```

### Building for Different Architectures

For ARM64 (e.g., Raspberry Pi):
```bash
# Install cross-compilation tools
sudo apt-get install gcc-aarch64-linux-gnu

# Build for ARM64
ARCH=aarch64 bash build_appimage.sh
```

## 🗑️ Uninstallation

### From system installation:
```bash
sudo rm -rf /opt/arkshield
sudo rm /usr/local/bin/arkshield
sudo rm /usr/share/applications/arkshield.desktop
```

### From AppImage:
Just delete the `.AppImage` file.

## 📦 Distribution Checklist

Before distributing:

- [ ] Test on Ubuntu, Fedora, and Arch
- [ ] Verify all features work
- [ ] Check AppImage size is reasonable
- [ ] Test without Python pre-installed
- [ ] Verify GTK theme compatibility
- [ ] Check system tray icon shows
- [ ] Test with different desktop environments (GNOME, KDE, XFCE)

## 🌐 Supported Distributions

Tested on:
- ✅ Ubuntu 20.04, 22.04, 24.04
- ✅ Fedora 38, 39, 40
- ✅ Debian 11, 12
- ✅ Arch Linux (current)
- ✅ Linux Mint 21
- ✅ Pop!_OS 22.04

Should work on any modern Linux with GTK3+.

## 📞 Support

For issues:
1. Check system logs: `journalctl -xe`
2. Verify dependencies: `python3 arkshield_app.py`
3. Check port availability: `netstat -tuln | grep 8000`

## 📝 License

Same as parent ArkShield project.

---

**Last Updated:** March 10, 2026  
**Version:** 1.0.0  
**Platform:** Linux (GTK3)
