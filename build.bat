@echo off
echo Building WireBoard v7.2.0 with PyInstaller...
pyinstaller WireBoard.spec --noconfirm
echo Build complete. EXE: dist\WireBoard.exe
