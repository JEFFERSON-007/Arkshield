# 🚀 ArkShield Windows Executable

## ✅ EXE File Created Successfully!

**File Location:** `windows\dist\ArkShield.exe`  
**File Size:** 58.4 MB  
**Type:** Standalone Executable (no installation needed)

---

## 📍 How to Access & Run

### Option 1: Direct Execution (Easiest)
```cmd
# From command prompt or PowerShell:
c:\Users\mariy\OneDrive\Documents\extra tasks i do when i am bored\system scanner\sys scanner\windows\dist\ArkShield.exe
```

Or simply:
```cmd
# Double-click the exe file in Windows Explorer
```

### Option 2: Create Desktop Shortcut
1. Navigate to `windows\dist\` folder
2. Right-click `ArkShield.exe`
3. Select **"Send to"** → **"Desktop (create shortcut)"**
4. Double-click the shortcut to launch

### Option 3: Pin to Start Menu
1. Right-click `ArkShield.exe`
2. Select **"Pin to Start"**
3. Find ArkShield in Windows Start Menu
4. Click to launch anytime

### Option 4: Create Quick Launch Shortcut
1. Right-click `ArkShield.exe`
2. Select **"Create shortcut"**
3. Name it something like **"ArkShield Shortcut"**
4. Move to Desktop or anywhere convenient
5. Double-click to launch

### Option 5: Add to PATH (System-Wide Access)
For advanced users who want to run `arkshield` from any terminal:

**Step 1:** Copy exe to a system folder
```cmd
mkdir "C:\Program Files\ArkShield"
copy "windows\dist\ArkShield.exe" "C:\Program Files\ArkShield\"
```

**Step 2:** Add to Windows PATH
1. Press `Win+X` → **Settings**
2. Search for **"Environment Variables"**
3. Click **"Edit the system environment variables"**
4. Click **"Environment Variables"** button
5. Under "User variables" click **"New"**
6. Variable name: `PATH`
7. Variable value: `C:\Program Files\ArkShield`
8. Click **"OK"** three times

**Step 3:** Use from anywhere
```cmd
# Open new Command Prompt/PowerShell and type:
arkshield
```

---

## 🎯 What Happens When You Run It

1. **Server starts automatically** on `http://127.0.0.1:8000-8100`
2. **Windows Edge opens** in app mode (looks like native app, no browser UI)
3. **Dashboard loads** with real-time system monitoring
4. **Security monitoring starts**:
   - Network connections
   - Process monitoring
   - Registry changes
   - File integrity
   - And 10+ more features

---

## 🛠️ Troubleshooting

### Issue: EXE won't start
**Solution 1:** Run as Administrator
- Right-click `ArkShield.exe` → **"Run as administrator"**

**Solution 2:** Check port conflicts
```cmd
netstat -ano | findstr :8000
```
If port 8000 is in use, the app auto-selects 8001-8100

**Solution 3:** Antivirus blocking
- Add exception in Windows Defender
- Settings → Virus & threat protection → Manage settings → Add exclusions

### Issue: "API unavailable" in dashboard
**Solution:** Wait 3-5 seconds for server to fully start

### Issue: Edge doesn't open
**Solution 1:** Ensure Microsoft Edge is installed (default on Windows 11)
**Solution 2:** Open manually: `http://localhost:8000`

---

## 📋 System Requirements

- **OS:** Windows 10/11 (64-bit)
- **RAM:** 2 GB minimum
- **Disk:** 100 MB free space
- **Port:** 8000 (auto-alternate if in use)
- **Administrative Rights:** Optional (for full Registry reading)

---

## 🔧 EXE File Properties

| Property | Value |
|----------|-------|
| **Name** | ArkShield.exe |
| **Size** | 58.4 MB |
| **Location** | `windows/dist/` |
| **Type** | Standalone Executable |
| **Dependencies** | None (all bundled) |
| **Python Required** | No |
| **Installation** | Not needed - just run |
| **Uninstall** | Delete .exe file |

---

## 📦 Distribution

To distribute ArkShield.exe to others:

1. **Direct Share:**
   - Copy `windows/dist/ArkShield.exe`
   - Send via email, USB, cloud storage, etc.
   - Recipient just double-clicks to run

2. **Create Installer (Optional):**
   - Use NSIS or InnoSetup
   - Package exe with setup wizard

3. **Portable Version:**
   - Create folder: `ArkShield_Portable/`
   - Copy exe inside
   - Create `README.txt` with instructions
   - Zip and share

---

## 🔐 Security Notes

- ✅ All code runs locally (no cloud)
- ✅ Server binds to `127.0.0.1` (localhost only)
- ✅ No data sent externally
- ✅ Real-time system monitoring using Windows APIs
- ✅ Admin rights optional (full features with admin)

---

## 💡 Pro Tips

### Tip 1: Create Quick Access Button
```cmd
# Pin to Quick Access in File Explorer:
# Right-click "windows\dist\" folder → Pin to Quick access
```

### Tip 2: Command Alias (PowerShell)
Add to PowerShell profile:
```powershell
New-Alias -Name arkshield -Value 'C:\path\to\ArkShield.exe'
```

### Tip 3: Run on Startup
1. Press `Win+R`, type: `shell:startup`
2. Create shortcut to `ArkShield.exe` there
3. Runs automatically when you login

### Tip 4: Different Port
To use a different port, edit `windows/arkshield_app.py` line where it says:
```python
self.port = self.find_free_port()  # Auto-selects 8000-8100
```

---

## 📖 Next Steps

1. ✅ **Run the executable:**
   ```
   windows\dist\ArkShield.exe
   ```

2. ✅ **Create desktop shortcut** for easy access

3. ✅ **Open http://localhost:8000** in browser (if Edge doesn't auto-open)

4. ✅ **Start monitoring:**
   - Network connections
   - Running processes
   - Registry changes
   - File integrity
   - System security

5. ✅ **Share exe** with others (it's standalone, needs no installation)

---

## 📞 Support

If you have issues:

1. Check system requirements above
2. Ensure Edge is installed (Windows 11 default)
3. Run as Administrator if needed
4. Check firewall/antivirus settings
5. Verify port 8000 isn't in use: `netstat -ano | findstr :8000`

---

## 🎉 You're All Set!

Your ArkShield Windows executable is ready to use! 

**Enjoy advanced system security monitoring!** 🚀

---

**Created:** March 10, 2026  
**Exe Size:** 58.4 MB  
**Python Version:** 3.14.3  
**Status:** ✅ Production Ready
