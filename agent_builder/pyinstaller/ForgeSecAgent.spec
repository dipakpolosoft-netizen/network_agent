# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


builder_root = Path(SPECPATH).parent
source_root = builder_root / "src"
agent_icon = builder_root / "installer" / "assets" / "forgesec-agent.ico"

analysis = Analysis(
    [str(source_root / "forgesec_agent" / "main.py")],
    pathex=[str(source_root)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "pythoncom",
        "pywintypes",
        "servicemanager",
        "win32event",
        "win32service",
        "win32serviceutil",
        "win32timezone",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="ForgeSecAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(builder_root / "pyinstaller" / "version_info.txt"),
    icon=str(agent_icon),
    uac_admin=False,
)

tray_analysis = Analysis(
    [str(source_root / "forgesec_agent" / "tray_main.py")],
    pathex=[str(source_root)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "pywintypes",
        "win32api",
        "win32con",
        "win32gui",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
    optimize=1,
)
tray_pyz = PYZ(tray_analysis.pure)

tray_executable = EXE(
    tray_pyz,
    tray_analysis.scripts,
    tray_analysis.binaries,
    tray_analysis.datas,
    [],
    name="ForgeSecTray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(builder_root / "pyinstaller" / "version_info.txt"),
    icon=str(agent_icon),
    uac_admin=False,
)
