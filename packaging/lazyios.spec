# PyInstaller one-file build: pyinstaller packaging/lazyios.spec
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, copy_metadata

here = Path(SPECPATH)
datas, binaries, hiddenimports = [], [], []
for package in ("lazyios", "textual", "rich", "pymobiledevice3", "pmd_pytcp", "pmd_net_addr", "pytun_pmd3"):
    d, b, h = collect_all(package)
    datas += d
    binaries += b
    hiddenimports += h
datas += copy_metadata("lazyios") + copy_metadata("textual")

a = Analysis(
    [str(here / "entry.py")],
    pathex=[str(here.parent / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "IPython", "pytest"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="lazyios",
    console=True,
    upx=False,
)
