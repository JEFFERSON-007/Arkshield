# ArkShield Desktop Application - Linux

Native Linux desktop application for ArkShield security monitoring.

## Features

- **Native Linux Application:** No browser required.
- **GTK Integration:** Native Linux look and feel.
- **System Tray Support:** Runs seamlessly in the background.
- **AppImage Format:** Portable execution across Linux distributions.
- **Auto-start Server:** Backend starts automatically upon launch.
- **Professional Interface:** Designed as a native Linux application.

## Installation

### Option 1: System-wide Installation (Recommended)

Install ArkShield as a system application:

```bash
cd linux
sudo bash install.sh
```

This script will:
1. Install the application to `/opt/arkshield`.
2. Create a launcher at `/usr/local/bin/arkshield`.
3. Add a desktop entry for the application menu.
4. Install all required dependencies.

Run from the terminal:
```bash
arkshield
```

Alternatively, search for "ArkShield" in your desktop application menu.

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

This creates the following artifact:
```
linux/dist/ArkShield-1.0.0-x86_64.AppImage
```

Run the executable:
```bash
chmod +x dist/ArkShield-1.0.0-x86_64.AppImage
./dist/ArkShield-1.0.0-x86_64.AppImage
```

## Usage

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

The application will automatically:
1. Start the FastAPI server on port 8000.
2. Open a native GTK window presenting the dashboard.
3. Begin real-time system monitoring.

## File Structure

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

## Configuration

### Port Configuration

If port 8000 is already in use, the application will automatically select the next available port.

### Window Size

Default: 1400x900 pixels  
Minimum: 1024x768 pixels  
Resizable: Yes

To modify the default window size, edit `arkshield_app.py`:
```python
window = webview.create_window(
    title="ArkShield Security Monitor",
    width=1400,      # Modify width
    height=900,      # Modify height
    min_size=(1024, 768)
)
```

## Troubleshooting

### Issue: "Module not found" error
**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: GTK error on startup
**Solution:** Install GTK development packages based on your distribution:

**Ubuntu/Debian:**
```bash
sudo apt-get install gir1.2-gtk-3.0 gir1.2-webkit2-4.0
```

**Fedora:**
```bash
sudo dnf install gtk3 webkit2gtk3
```

### Issue: AppImage fails to execute
**Solution:**
```bash
# Make the file executable
chmod +x ArkShield-*.AppImage

# Install FUSE if required by your distribution
sudo apt-get install fuse libfuse2  # Ubuntu/Debian
sudo dnf install fuse               # Fedora
```

### Issue: Application window does not open
**Solution:** Verify that the server has started successfully:
```bash
netstat -tuln | grep :8000
```

### Issue: Permission denied during installation
**Solution:** Run the installer with elevated privileges:
```bash
sudo bash install.sh
```

## Requirements

### System Requirements
- **Operating System:** Linux (Ubuntu 20.04+, Fedora 35+, Arch Linux, or equivalent)
- **Architecture:** x86_64 (64-bit)
- **Memory:** 2 GB RAM minimum
- **Storage:** 100 MB free space

### Software Requirements
- **Python:** 3.8 or higher
- **GTK:** 3.0 or higher
- **WebKit2GTK:** 4.0 or higher

## Security Considerations

- The server binds strictly to `127.0.0.1` (localhost only).
- External network access is disabled by default.
- System monitoring utilizes secure Linux APIs (`psutil`, `/proc`, `/sys`).
- No telemetry or operational data is transmitted to external servers.

## Advanced Usage

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

Create the service file `/etc/systemd/system/arkshield.service`:
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

Enable and start the service:
```bash
sudo systemctl enable arkshield
sudo systemctl start arkshield
```

### Building for Different Architectures

For ARM64 architectures (e.g., Raspberry Pi):
```bash
# Install cross-compilation tools
sudo apt-get install gcc-aarch64-linux-gnu

# Build for ARM64
ARCH=aarch64 bash build_appimage.sh
```

## Uninstallation

### From system installation:
```bash
sudo rm -rf /opt/arkshield
sudo rm /usr/local/bin/arkshield
sudo rm /usr/share/applications/arkshield.desktop
```

### From AppImage:
Simply delete the `.AppImage` file from your system.

## Distribution Checklist

Before releasing a new build, ensure the following checks are complete:

- [ ] Tested on Ubuntu, Fedora, and Arch Linux
- [ ] Verified functionality of all core features
- [ ] Confirmed AppImage size is optimal
- [ ] Tested on systems without Python pre-installed
- [ ] Verified compatibility with various GTK themes
- [ ] Confirmed system tray icon visibility and function
- [ ] Tested across major desktop environments (GNOME, KDE, XFCE)

## Supported Distributions

Officially tested and supported on:
- Ubuntu 20.04, 22.04, 24.04
- Fedora 38, 39, 40
- Debian 11, 12
- Arch Linux
- Linux Mint 21
- Pop!_OS 22.04

The application is expected to function correctly on any modern Linux distribution with GTK3+ support.

## Support

For issues and debugging:
1. Review system logs: `journalctl -xe`
2. Verify dependencies by running manually: `python3 arkshield_app.py`
3. Check backend port availability: `netstat -tuln | grep 8000`

## License

Subject to the license terms of the parent ArkShield project.

---

**Last Updated:** March 10, 2026  
**Version:** 1.0.0  
**Platform:** Linux (GTK3)
