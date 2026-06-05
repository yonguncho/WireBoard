@echo off
echo Building WireBoard v5.0 with PyInstaller...
pyinstaller --onefile --name WireBoard --add-data "backend;backend" launcher.py
echo Build complete. EXE: dist\WireBoard.exe
