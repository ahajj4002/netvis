"""
NetVis network utilities.
IP/MAC lookups, hostname resolution, device type guessing, and banner grabbing.
"""

import json
import socket
import subprocess
import urllib.request
from typing import Dict, List

from constants import IP_RANGES, KNOWN_SERVICES, MAC_VENDORS

# Cache for IP lookups (in-memory, cleared on restart)
ip_info_cache: Dict[str, dict] = {}


def identify_ip_service(ip: str) -> str:
    """Quick identification of IP service from known ranges."""
    if ip in KNOWN_SERVICES:
        return KNOWN_SERVICES[ip]
    for prefix, service in IP_RANGES.items():
        if ip.startswith(prefix):
            return service
    if (
        ip.startswith("192.168.")
        or ip.startswith("10.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
    ):
        return "Private Network"
    if ip.startswith("127."):
        return "Localhost"
    if ip == "0.0.0.0":
        return "Any/DHCP"
    return ""


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private/reserved range."""
    if not ip:
        return True
    return (
        ip.startswith("192.168.")
        or ip.startswith("10.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.20.")
        or ip.startswith("172.21.")
        or ip.startswith("172.22.")
        or ip.startswith("172.23.")
        or ip.startswith("172.24.")
        or ip.startswith("172.25.")
        or ip.startswith("172.26.")
        or ip.startswith("172.27.")
        or ip.startswith("172.28.")
        or ip.startswith("172.29.")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("127.")
        or ip.startswith("0.")
        or ip.startswith("224.")
        or ip.startswith("239.")
        or ip.startswith("255.")
    )


def get_mac_vendor_online(mac: str) -> str:
    """Look up MAC vendor from online API (macvendors.com)."""
    if not mac:
        return ""
    try:
        mac_clean = mac.replace(":", "").replace("-", "")[:6]
        url = f"https://api.macvendors.com/{mac_clean}"
        req = urllib.request.Request(url, headers={"User-Agent": "NetVis/1.0"})
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.read().decode("utf-8").strip()
    except Exception:
        return ""


def lookup_ip_info(ip: str) -> dict:
    """Look up detailed IP information using free API (ip-api.com)."""
    if ip in ip_info_cache:
        return ip_info_cache[ip]
    if (
        ip.startswith("192.168.")
        or ip.startswith("10.")
        or ip.startswith("172.")
        or ip.startswith("127.")
        or ip.startswith("0.")
        or ip.startswith("224.")
        or ip.startswith("239.")
        or ip.startswith("255.")
    ):
        result = {
            "ip": ip,
            "service": identify_ip_service(ip),
            "country": "Local",
            "city": "",
            "org": "Private Network",
            "isp": "",
            "is_private": True,
        }
        ip_info_cache[ip] = result
        return result
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "NetVis/1.0"})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success":
                service = identify_ip_service(ip)
                if not service:
                    org = (data.get("org") or "").lower()
                    isp = (data.get("isp") or "").lower()
                    if "amazon" in org or "amazon" in isp or "aws" in org:
                        service = "Amazon AWS"
                    elif "google" in org or "google" in isp:
                        service = "Google"
                    elif "microsoft" in org or "microsoft" in isp or "azure" in org:
                        service = "Microsoft Azure"
                    elif "cloudflare" in org or "cloudflare" in isp:
                        service = "Cloudflare"
                    elif "akamai" in org or "akamai" in isp:
                        service = "Akamai CDN"
                    elif "facebook" in org or "meta" in org:
                        service = "Meta/Facebook"
                    elif "apple" in org:
                        service = "Apple"
                    elif "netflix" in org:
                        service = "Netflix"
                result = {
                    "ip": ip,
                    "service": service,
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "as": data.get("as", ""),
                    "is_private": False,
                }
                ip_info_cache[ip] = result
                return result
    except Exception:
        pass
    result = {
        "ip": ip,
        "service": identify_ip_service(ip),
        "country": "Unknown",
        "city": "",
        "org": "",
        "isp": "",
        "is_private": False,
    }
    ip_info_cache[ip] = result
    return result


def lookup_mac_vendor(mac: str) -> str:
    """Look up vendor from MAC address OUI (local DB then online fallback)."""
    if not mac or mac == "unknown":
        return ""
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    parts = mac_clean.split(":")
    if len(parts) == 6:
        prefix = ":".join(parts[:3])
    elif len(parts) == 3:
        prefix = mac_clean[:8]
    else:
        prefix = mac_clean[:8]
    if prefix in MAC_VENDORS:
        return MAC_VENDORS[prefix]
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={"User-Agent": "NetVis/1.0"})
        with urllib.request.urlopen(req, timeout=2) as response:
            vendor = response.read().decode("utf-8").strip()
            if vendor and "error" not in vendor.lower():
                return vendor
    except Exception:
        pass
    return ""


def resolve_hostname_multi(ip: str) -> str:
    """Try multiple methods to resolve hostname (reverse DNS, mDNS, NetBIOS, avahi)."""
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.startswith(ip.replace(".", "-")):
            return hostname
    except Exception:
        pass
    try:
        subprocess.run(
            ["dns-sd", "-Q", f'{ip.replace(".", "-")}.local'],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.split("\n"):
            if "<00>" in line and "GROUP" not in line:
                parts = line.strip().split()
                if parts:
                    return parts[0]
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1].rstrip(".")
    except Exception:
        pass
    return hostname


def guess_device_type(hostname: str, vendor: str, open_ports: List[int]) -> str:
    """Guess device type from hostname, vendor, and open ports."""
    hostname_lower = (hostname or "").lower()
    vendor_lower = (vendor or "").lower()
    open_ports = open_ports or []
    if any(
        x in hostname_lower
        for x in ["router", "gateway", "gw", "rt-", "ubnt", "livebox", "bbox", "freebox", "neufbox"]
    ):
        return "Router"
    if any(
        x in vendor_lower
        for x in ["ubiquiti", "netgear", "linksys", "tp-link", "asus", "d-link", "actiontec"]
    ):
        if not open_ports or 80 in open_ports or 443 in open_ports:
            return "Router/AP"
    if "apple" in vendor_lower:
        if any(x in hostname_lower for x in ["iphone", "ipad"]):
            return "iPhone/iPad"
        if any(x in hostname_lower for x in ["macbook", "mbp", "mba"]):
            return "MacBook"
        if any(x in hostname_lower for x in ["imac", "mac-pro", "mac-mini"]):
            return "Mac Desktop"
        if "appletv" in hostname_lower or "apple-tv" in hostname_lower:
            return "Apple TV"
        if "homepod" in hostname_lower:
            return "HomePod"
        if "watch" in hostname_lower:
            return "Apple Watch"
        return "Apple Device"
    if any(
        x in hostname_lower
        for x in ["tv", "roku", "firetv", "chromecast", "appletv"]
    ):
        return "Smart TV/Streaming"
    if any(x in vendor_lower for x in ["roku", "samsung", "lg", "sony", "vizio"]):
        if "tv" in hostname_lower or not hostname:
            return "Smart TV"
    if any(
        x in hostname_lower
        for x in ["playstation", "ps4", "ps5", "xbox", "nintendo", "switch"]
    ):
        return "Gaming Console"
    if any(
        x in hostname_lower
        for x in ["phone", "android", "galaxy", "pixel", "oneplus"]
    ):
        return "Smartphone"
    if any(x in vendor_lower for x in ["samsung", "htc", "huawei", "xiaomi", "oneplus"]) and not hostname:
        return "Smartphone"
    if "amazon" in vendor_lower:
        if any(x in hostname_lower for x in ["echo", "alexa", "dot"]):
            return "Echo/Alexa"
        if "fire" in hostname_lower:
            return "Fire TV/Tablet"
        return "Amazon Device"
    if "google" in vendor_lower or "nest" in vendor_lower:
        if any(x in hostname_lower for x in ["nest", "thermostat", "protect"]):
            return "Nest Device"
        if any(x in hostname_lower for x in ["home", "mini", "hub"]):
            return "Google Home"
        return "Google Device"
    if any(
        x in hostname_lower
        for x in ["camera", "cam", "ipcam", "doorbell", "ring"]
    ):
        return "Camera"
    if "hikvision" in vendor_lower:
        return "IP Camera"
    if any(
        x in hostname_lower
        for x in ["printer", "print", "hp", "canon", "epson", "brother"]
    ):
        return "Printer"
    if 9100 in open_ports or 515 in open_ports or 631 in open_ports:
        return "Printer"
    if any(
        x in hostname_lower
        for x in ["nas", "synology", "qnap", "storage", "diskstation"]
    ):
        return "NAS"
    if any(
        x in hostname_lower
        for x in ["server", "srv", "proxmox", "esxi", "docker"]
    ):
        return "Server"
    if open_ports and any(p in open_ports for p in [22, 80, 443, 3306, 5432, 8080]):
        if len(open_ports) > 3:
            return "Server"
    if any(
        x in hostname_lower
        for x in ["laptop", "desktop", "pc", "workstation", "macbook"]
    ):
        return "Computer"
    if any(
        x in vendor_lower
        for x in ["dell", "hp", "lenovo", "asus", "acer", "intel"]
    ):
        return "Computer"
    if any(x in vendor_lower for x in ["vmware", "virtualbox", "hyper-v"]):
        return "Virtual Machine"
    if "raspberry" in vendor_lower:
        return "Raspberry Pi"
    if any(
        x in hostname_lower
        for x in ["iot", "smart", "sensor", "plug", "bulb", "hue", "wemo"]
    ):
        return "Smart Home Device"
    if "philips" in vendor_lower and "hue" in hostname_lower:
        return "Smart Light"
    if "espressif" in vendor_lower:
        return "IoT Device (ESP)"
    if "smart innovation" in vendor_lower:
        return "Smart Home Device"
    if "wnc" in vendor_lower:
        return "Network Device"
    if "arcadyan" in vendor_lower:
        return "Router"
    return "Unknown"


def grab_service_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Best-effort service banner grab for enriched service profiling."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            sock.close()
            return ""
        try:
            if port in (80, 8080, 8000, 8443, 443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = sock.recv(512)
            sock.close()
            return data.decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            sock.close()
            return ""
    except Exception:
        return ""
