# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

# Get current directory
ROOT_DIR = Path(os.getcwd())

a = Analysis(
    [str(ROOT_DIR / 'windows' / 'arkshield_app.py')],
    pathex=[],
    binaries=[],
    datas=[
        (str(ROOT_DIR / 'src'), 'src'),
        (str(ROOT_DIR / 'src' / 'arkshield' / 'api' / 'dashboard.html'), 'src/arkshield/api'),
        (str(ROOT_DIR / 'src' / 'arkshield' / 'config' / 'ai_config.json'), 'src/arkshield/config'),
        (str(ROOT_DIR / 'src' / 'storage_manager' / 'data' / 'junk_patterns.json'), 'src/storage_manager/data')
    ],
    hiddenimports=[
        'uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 
        'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 
        'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 
        'uvicorn.lifespan', 'uvicorn.lifespan.on', 'fastapi', 'psutil', 
        'winreg', 'pydantic', 'starlette'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [('O', None, 'OPTION'), ('O', None, 'OPTION')],
    name='ArkShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
