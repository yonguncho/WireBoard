@echo off
echo Building WireBoard v7.1.0 with PyInstaller...
pyinstaller WireBoard.spec --noconfirm
echo Build complete. EXE: dist\WireBoard.exe
