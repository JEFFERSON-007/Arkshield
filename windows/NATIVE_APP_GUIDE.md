# ArkShield Native Desktop Application

## ✅ WHAT IS THIS?

This is a **completely native desktop application** with its own interface:
- ✅ NO web browser/localhost connection
- ✅ Works on both Windows AND Linux
- ✅ Modern dark theme GUI
- ✅ Real-time system monitoring
- ✅ Lightweight (only 12-13 MB)

---

## 🪟 WINDOWS USAGE

### Option 1: Run the EXE (Recommended)
```
1. Go to: windows\dist\ArkShield.exe
2. Double-click to run
3. Done!
```

### Option 2: Run from Python
```bash
cd windows
python arkshield_native.py
```

### Option 3: Rebuild the EXE
```bash
cd windows
BUILD_GUI_EXE.bat
```

---

## 🐧 LINUX USAGE

### Requirements
```bash
# Install Python and Tkinter
sudo apt-get update
sudo apt-get install python3 python3-tk python3-pip

# Install psutil
pip3 install psutil
```

### Running on Linux
```bash
# Navigate to the windows folder (yes, it works on Linux too!)
cd "sys scanner/windows"

# Run the application
python3 arkshield_native.py
```

### Building Linux Executable (Optional)
```bash
# Install PyInstaller
pip3 install pyinstaller

# Build the executable
python3 -m PyInstaller --onefile --windowed --name=ArkShield arkshield_native.py

# Run it
./dist/ArkShield
```

---

## 🎯 FEATURES

### Dashboard Tab (Overview)
- **CPU Usage**: Real-time CPU percentage, frequency, core count
- **Memory Usage**: Used/available RAM with progress bars
- **Disk Usage**: Storage space monitoring
- **Network Activity**: Bytes sent/received, packets, errors

### Processes Tab
- List of running processes
- PID, name, CPU%, memory, threads, status
- Sorted by CPU usage (top 100 processes)
- Refresh button for manual updates

### Network Tab
- Network statistics (bytes, packets, errors)
- Active connections (TCP/UDP)
- Local and remote addresses
- Connection status and PIDs

### Storage Tab
- All disk partitions
- Device, mount point, filesystem type
- Total, used, free space
- Usage percentage
- Disk I/O statistics (reads/writes)

### Security Tab
- Security monitor status
- All 6 security modules displayed
- System information
- Security score
- Real-time threat status

### Live Activity Feed (Right Panel)
- Real-time activity log
- Timestamped events
- System monitoring updates
- Last 100 events kept

---

## 🔧 TECHNICAL DETAILS

### What's Inside?
- **GUI Framework**: Tkinter (built into Python)
- **System Monitoring**: psutil library
- **Threading**: Multi-threaded for real-time updates
- **Update Interval**: Every 2 seconds
- **Memory Usage**: ~45-50 MB RAM when running

### Cross-Platform Compatibility
The app uses only Python standard library (Tkinter) and psutil, which work on:
- ✅ Windows 7/8/10/11
- ✅ Linux (Ubuntu, Debian, Fedora, etc.)
- ✅ macOS (with Tkinter installed)

### No Dependencies on Web Frameworks
Unlike the previous version, this app does NOT require:
- ❌ FastAPI
- ❌ Starlette
- ❌ Uvicorn
- ❌ Web browser
- ❌ Localhost server

---

## 📦 FILE SIZES

| Version | Size | Platform | Includes Web Server? |
|---------|------|----------|---------------------|
| Native GUI (NEW) | 12.8 MB | Windows + Linux | NO |
| Web Dashboard | 47.6 MB | Windows only | YES |

---

## 🚀 QUICK START

### Windows
```cmd
# Just double-click this file:
windows\dist\ArkShield.exe
```

### Linux
```bash
# Install requirements (first time only)
sudo apt-get install python3-tk python3-pip
pip3 install psutil

# Run the app
python3 "sys scanner/windows/arkshield_native.py"
```

---

## 🐛 TROUBLESHOOTING

### Windows: "App won't start"
- Make sure no antivirus is blocking it
- Try running as Administrator
- Rebuild the exe using `BUILD_GUI_EXE.bat`

### Linux: "No module named '_tkinter'"
```bash
sudo apt-get install python3-tk
```

### Linux: "No module named 'psutil'"
```bash
pip3 install psutil
```

### General: "Permission denied"
- On Linux, you may need admin privileges to read network connections
- Run with `sudo python3 arkshield_native.py` for full functionality

---

## 🎨 UI FEATURES

- **Dark Theme**: Modern dark blue/gray color scheme
- **Real-time Updates**: All metrics update every 2 seconds
- **Professional Layout**: Header, status bar, tabs, activity feed
- **Smooth Performance**: Multi-threaded to avoid UI freezing
- **Responsive Design**: Resizable window, scrollable content

---

## 📝 NOTES

1. **NO LOCALHOST**: This app does NOT use any web server or localhost connection
2. **NATIVE INTERFACE**: Pure desktop application with Tkinter GUI
3. **CROSS-PLATFORM**: Same code works on Windows and Linux
4. **LIGHTWEIGHT**: Only 12-13 MB executable size
5. **STANDALONE**: No web browser required

---

## ❓ FAQ

**Q: Why does it say "127.0.0.1" in the old version?**  
A: That was the old web-based version. This NEW native version doesn't use localhost at all.

**Q: Do I need internet connection?**  
A: No, this app works completely offline.

**Q: Can I run this on Linux?**  
A: Yes! The same Python script works on both Windows and Linux.

**Q: How do I make it run on startup?**  
A: 
- Windows: Copy `ArkShield.exe` to `shell:startup` folder
- Linux: Add to startup applications in your desktop environment

**Q: Is this better than the web dashboard version?**  
A: It depends on your needs:
- Native version: Lighter, faster, cross-platform, no localhost
- Web version: More features, prettier UI, but Windows-only and requires web server

---

## 🏆 WHAT'S NEW IN THIS VERSION

✅ Completely native desktop GUI (no web browser)  
✅ Works on both Windows AND Linux  
✅ 74% smaller file size (12 MB vs 47 MB)  
✅ NO localhost/web server required  
✅ Modern dark theme interface  
✅ Real-time monitoring with live activity feed  
✅ 5 comprehensive tabs (Overview, Processes, Network, Storage, Security)  
✅ Multi-threaded for smooth performance  
✅ Cross-platform compatible  

---

**Enjoy your native ArkShield desktop application! 🛡️**
