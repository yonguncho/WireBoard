"""OUI vendor lookup — MAC 앞 3바이트로 장비 제조사 추정 (오프라인).

전체 IEEE OUI DB(수만 개)는 번들하지 않고, 네트워크 현장에서 자주 보이는
제조사 프리픽스만 큐레이션해 담는다. 미상이면 로컬/유니캐스트 여부만 표기.
"""
from __future__ import annotations

# OUI(첫 3바이트, 대문자 무구분) → 제조사
_OUI: dict[str, str] = {
    "000569": "VMware", "000C29": "VMware", "005056": "VMware", "001C14": "VMware",
    "080027": "VirtualBox",
    "00155D": "Microsoft Hyper-V", "001DD8": "Microsoft", "0050F2": "Microsoft",
    "0003FF": "Microsoft",
    "00000C": "Cisco", "000142": "Cisco", "0007EB": "Cisco", "001A2F": "Cisco",
    "001B0C": "Cisco", "0025B4": "Cisco", "00DEFB": "Cisco", "F866F2": "Cisco",
    "00005E": "IANA (VRRP/virtual)",
    "001560": "HP", "0017A4": "HP", "002481": "HP", "3863BB": "HP",
    "000BCD": "HP", "00508B": "HP",
    "00219B": "Dell", "0024E8": "Dell", "18A99B": "Dell", "B083FE": "Dell",
    "F8BC12": "Dell", "001AA0": "Dell",
    "001B21": "Intel", "001E67": "Intel", "0026C7": "Intel", "3C970E": "Intel",
    "A0369F": "Intel", "8C1645": "Intel",
    "001124": "Apple", "0016CB": "Apple", "001EC2": "Apple", "3C0754": "Apple",
    "A45E60": "Apple", "F0DBF8": "Apple", "ACBC32": "Apple",
    "0009F5": "Huawei", "00E0FC": "Huawei", "781DBA": "Huawei", "F4DCF9": "Huawei",
    "000C42": "Routerboard/MikroTik", "4C5E0C": "MikroTik", "E48D8C": "MikroTik",
    "000B86": "Aruba", "24DEC6": "Aruba", "94B40F": "Aruba",
    "0090FB": "Portwell", "00907F": "WatchGuard",
    "090007": "Fortinet", "00090F": "Fortinet", "084F0A": "Fortinet", "907AF1": "Fortinet",
    "001C73": "Arista", "444CA8": "Arista",
    "0017DF": "Cisco Meraki", "E0CB4E": "Cisco Meraki",
    "5847CA": "Juniper", "2C6BF5": "Juniper", "3CE5A6": "Juniper", "F01C2D": "Juniper",
    "B4FBE4": "Ubiquiti", "24A43C": "Ubiquiti", "788A20": "Ubiquiti", "FCECDA": "Ubiquiti",
    "001517": "Intel", "525400": "QEMU/KVM (virtual)",
    "000D3A": "Microsoft Azure", "7C1E52": "Microsoft",
    "0050C2": "IEEE Registration",
}


def lookup(mac: str) -> dict | None:
    """MAC 문자열 → {vendor, local, multicast}. 형식 오류면 None."""
    if not mac:
        return None
    hexs = mac.replace(":", "").replace("-", "").upper()
    if len(hexs) < 6:
        return None
    prefix = hexs[:6]
    vendor = _OUI.get(prefix)
    # locally-administered (2번째 비트) / multicast(1번째 비트) 판정
    try:
        first_octet = int(hexs[:2], 16)
    except ValueError:
        return None
    local = bool(first_octet & 0x02)
    multicast = bool(first_octet & 0x01)
    if not vendor:
        vendor = "Locally-administered" if local else "Unknown vendor"
    return {"vendor": vendor, "local": local, "multicast": multicast, "oui": prefix}
