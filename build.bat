@echo off
echo Building WireBoard v7.2.5 with PyInstaller...
pyinstaller WireBoard.spec --noconfirm
echo Build complete. EXE: dist\WireBoard.exe
