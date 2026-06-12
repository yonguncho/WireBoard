# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('backend', 'backend')],
    hiddenimports=[
        # FastAPI / Starlette / uvicorn
        'uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto',
        'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan', 'uvicorn.lifespan.on',
        'fastapi', 'fastapi.staticfiles', 'fastapi.responses', 'fastapi.routing',
        'fastapi.middleware', 'fastapi.middleware.cors', 'fastapi.encoders',
        'fastapi.exceptions', 'fastapi.params', 'fastapi.security',
        'starlette', 'starlette.responses', 'starlette.staticfiles',
        'starlette.middleware', 'starlette.middleware.base',
        'starlette.routing', 'starlette.requests', 'starlette.background',
        'starlette.concurrency', 'starlette.datastructures', 'starlette.exceptions',
        'starlette.formparsers', 'starlette.testclient', 'starlette.types',
        'anyio', 'anyio.abc', 'anyio._backends._asyncio',
        # dpkt
        'dpkt', 'dpkt.pcap', 'dpkt.pcapng', 'dpkt.ethernet', 'dpkt.ip',
        'dpkt.tcp', 'dpkt.udp', 'dpkt.icmp',
        # scapy core
        'scapy', 'scapy.all', 'scapy.layers', 'scapy.layers.l2',
        'scapy.layers.inet', 'scapy.layers.inet6',
        'scapy.utils', 'scapy.plist', 'scapy.packet',
        # yara (graceful degrade if absent)
        'yara',
        # geoip2 (graceful degrade if absent)
        'geoip2', 'geoip2.database',
        # PDF
        'reportlab', 'reportlab.lib', 'reportlab.lib.pagesizes',
        'reportlab.platypus', 'reportlab.lib.styles',
        # others
        'email.mime.multipart', 'email.mime.text',
        'multipart', 'python_multipart',
        'h11', 'httptools', 'watchfiles', 'websockets',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='WireBoard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
