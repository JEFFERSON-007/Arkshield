# ArkShield Desktop Application - Windows

Native Windows desktop application for ArkShield security monitoring.

## 🚀 Features

- ✅ **Native Windows application** - No browser required
- ✅ **System tray integration** - Runs in background
- ✅ **Single .exe file** - No installation needed
- ✅ **Auto-start server** - Backend starts automatically
- ✅ **Native window controls** - Minimize, maximize, close
- ✅ **Professional look** - Feels like a real Windows app

## 📦 Installation

### Option 1: Run from Source (Development)

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Run the application:**
```bash
python arkshield_app.py
```

### Option 2: Build Standalone .exe

1. **Install build dependencies:**
```bash
pip install -r requirements.txt
```

2. **Build the executable:**
```bash
python build_exe.py
```

3. **Find your .exe:**
```
windows/dist/ArkShield.exe
```

4. **Run it:**
```bash
.\dist\ArkShield.exe
```

## 🎯 Usage

### Running the Application

**From source:**
```bash
cd windows
python arkshield_app.py
```

**From executable:**
```bash
.\dist\ArkShield.exe
```

The application will:
1. Start FastAPI server automatically on port 8000
2. Open native window with dashboard
3. Monitor your system in real-time

### Building for Distribution

To create a distributable .exe:

```bash
cd windows
python build_exe.py
```

This creates a single-file executable:
- **Location:** `windows/dist/ArkShield.exe`
- **Size:** ~50-80 MB (includes Python runtime)
- **Portable:** Copy to any Windows system

## 📁 File Structure

```
windows/
├── arkshield_app.py      # Main desktop application
├── build_exe.py          # Build script for .exe
├── requirements.txt      # Python dependencies
├── README.md            # This file
├── arkshield.ico        # Application icon (optional)
├── build/               # Build artifacts (auto-generated)
└── dist/                # Output .exe location
    └── ArkShield.exe    # Final executable
```

## 🔧 Configuration

### Port Configuration

If port 8000 is in use, the app automatically finds next available port (8001, 8002, etc.)

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

### Adding Custom Icon

Place `arkshield.ico` in the `windows/` folder before building.

To create icon from PNG:
```bash
# Using ImageMagick
magick convert logo.png -resize 256x256 arkshield.ico

# Or use online converter: https://convertio.co/png-ico/
```

## 🐛 Troubleshooting

### Issue: "Module not found" error
**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: Build fails with PyInstaller
**Solution:**
```bash
pip install --upgrade pyinstaller
python build_exe.py
```

### Issue: .exe file is too large
**Solution:** Use UPX compression:
```bash
pip install pyinstaller[upx]
python build_exe.py
```

### Issue: Antivirus blocks .exe
**Solution:** This is common with PyInstaller executables. Either:
1. Add exception in Windows Defender
2. Sign the executable with code-signing certificate
3. Run from source: `python arkshield_app.py`

### Issue: Window doesn't open
**Solution:** Check if server started:
```bash
netstat -ano | findstr :8000
```

## 📋 Requirements

- **OS:** Windows 10/11 (64-bit)
- **Python:** 3.8+ (for development)
- **RAM:** 2 GB minimum
- **Disk:** 100 MB free space

## 🔒 Security Notes

- Server binds to `127.0.0.1` (localhost only)
- No external network access by default
- All monitoring uses Windows APIs (psutil, winreg)
- No data sent to external servers

## 📦 Distribution Checklist

Before distributing the .exe:

- [ ] Test on clean Windows system
- [ ] Verify all features work
- [ ] Check file size is reasonable
- [ ] Run antivirus scan
- [ ] Test without Python installed
- [ ] Verify no console window appears
- [ ] Check system tray icon shows

## 🚀 Advanced: Auto-start on Windows Boot

Create shortcut in Startup folder:

1. Build `.exe`: `python build_exe.py`
2. Copy `dist/ArkShield.exe` to Desktop
3. Press `Win+R`, type: `shell:startup`
4. Create shortcut to `ArkShield.exe`
5. App starts automatically on login

## 📞 Support

For issues:
1. Check logs in application window
2. Verify port 8000 is available
3. Run from source for debugging: `python arkshield_app.py`

## 📝 License

Same as parent ArkShield project.

---

**Last Updated:** March 10, 2026  
**Version:** 1.0.0  
**Platform:** Windows 10/11
