"""
NetVis network scanner.
ARP discovery, port scanning, and nmap integration.
"""

import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from config import NMAP_AVAILABLE, SCAPY_AVAILABLE
from constants import APP_PORTS
from models import Device
from net_utils import (
    grab_service_banner,
    guess_device_type,
    lookup_mac_vendor,
    resolve_hostname_multi,
)


class NetworkScanner:
    """Handles network device discovery."""

    def __init__(self):
        self.devices: Dict[str, Device] = {}
        self.local_ip = self._get_local_ip()
        self.gateway_ip = self._get_gateway_ip()
        self.network_cidr = self._get_network_cidr()
        self.datastore = None  # Injected by app after creation

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_gateway_ip(self) -> str:
        import platform
        try:
            if platform.system() == "Darwin":
                result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if line.startswith("default") or line.startswith("0.0.0.0"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            else:
                result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if "default" in line:
                        parts = line.split()
                        if "via" in parts:
                            return parts[parts.index("via") + 1]
        except Exception:
            pass
        return ""

    def _get_network_cidr(self) -> str:
        if self.local_ip:
            parts = self.local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "192.168.1.0/24"

    def _get_local_mac(self) -> str:
        import platform
        try:
            if platform.system() == "Darwin":
                result = subprocess.run(["ifconfig"], capture_output=True, text=True)
                lines = result.stdout.split("\n")
                for i, line in enumerate(lines):
                    if self.local_ip in line:
                        for j in range(max(0, i - 5), i):
                            if "ether" in lines[j]:
                                parts = lines[j].strip().split()
                                if len(parts) >= 2:
                                    return parts[1]
        except Exception:
            pass
        return "unknown"

    def scan_network_arp(self) -> Dict[str, Device]:
        if not SCAPY_AVAILABLE:
            return self._scan_network_ping()
        try:
            from scapy.all import arping
            answered, _ = arping(self.network_cidr, timeout=2, verbose=False)
            now = datetime.now().isoformat()
            discovered_ips = []
            if self.local_ip and self.local_ip not in self.devices:
                self.devices[self.local_ip] = Device(
                    ip=self.local_ip,
                    mac=self._get_local_mac(),
                    hostname=socket.gethostname(),
                    first_seen=now,
                    last_seen=now,
                    is_local=True,
                )
                discovered_ips.append(self.local_ip)
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                discovered_ips.append(ip)
                if ip not in self.devices:
                    self.devices[ip] = Device(
                        ip=ip,
                        mac=mac,
                        first_seen=now,
                        last_seen=now,
                        is_gateway=(ip == self.gateway_ip),
                        is_local=(ip == self.local_ip),
                    )
                else:
                    self.devices[ip].mac = mac
                    self.devices[ip].last_seen = now
            datastore = getattr(self, "datastore", None)
            for ip in discovered_ips:
                device = self.devices[ip]
                if not device.vendor:
                    device.vendor = lookup_mac_vendor(device.mac)
                if not device.hostname:
                    device.hostname = resolve_hostname_multi(ip)
                device_type = guess_device_type(device.hostname, device.vendor, device.open_ports)
                if device_type != "Unknown":
                    device.os = device_type
                if device_type == "Router" or ip == self.gateway_ip:
                    device.is_gateway = True
                if datastore:
                    datastore.upsert_device(device, scan_profile="arp")
                    for port in device.open_ports:
                        datastore.upsert_service(ip, port, "tcp", device.services.get(port, ""))
        except Exception:
            return self._scan_network_ping()
        return self.devices

    def _scan_network_ping(self) -> Dict[str, Device]:
        base_ip = ".".join(self.local_ip.split(".")[:-1])
        now = datetime.now().isoformat()
        def ping_host(ip):
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip],
                    capture_output=True,
                    timeout=2,
                )
                return result.returncode == 0
            except Exception:
                return False
        datastore = getattr(self, "datastore", None)
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if ping_host(ip):
                if ip not in self.devices:
                    self.devices[ip] = Device(
                        ip=ip,
                        first_seen=now,
                        last_seen=now,
                        is_gateway=(ip == self.gateway_ip),
                        is_local=(ip == self.local_ip),
                    )
                else:
                    self.devices[ip].last_seen = now
                if datastore:
                    datastore.upsert_device(self.devices[ip], scan_profile="ping")
        return self.devices

    def scan_ports(
        self,
        ip: str,
        ports: Optional[List[int]] = None,
        banner_grab: bool = False,
    ) -> Device:
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        if ip not in self.devices:
            self.devices[ip] = Device(ip=ip, first_seen=datetime.now().isoformat())
        device = self.devices[ip]
        device.open_ports = []
        device.services = {}
        device.service_banners = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    device.open_ports.append(port)
                    device.services[port] = self._get_service_name(port)
                    if banner_grab:
                        banner = grab_service_banner(ip, port)
                        if banner:
                            device.service_banners[port] = banner
                sock.close()
            except Exception:
                pass
        datastore = getattr(self, "datastore", None)
        if datastore:
            datastore.upsert_device(device, scan_profile="port_scan")
            for port in device.open_ports:
                datastore.upsert_service(
                    ip,
                    port,
                    "tcp",
                    device.services.get(port, ""),
                    banner=device.service_banners.get(port, ""),
                )
        return device

    def _get_service_name(self, port: int) -> str:
        return APP_PORTS.get(port, f"Port {port}")

    def nmap_scan(self, target: Optional[str] = None) -> Dict[str, Device]:
        if not NMAP_AVAILABLE:
            return self.scan_network_arp()
        import nmap as nmap_module
        target = target or self.network_cidr
        nm = nmap_module.PortScanner()
        try:
            nm.scan(hosts=target, arguments="-sn")
            now = datetime.now().isoformat()
            datastore = getattr(self, "datastore", None)
            for host in nm.all_hosts():
                ip = host
                if ip not in self.devices:
                    self.devices[ip] = Device(
                        ip=ip,
                        first_seen=now,
                        last_seen=now,
                        is_gateway=(ip == self.gateway_ip),
                        is_local=(ip == self.local_ip),
                    )
                if "mac" in nm[host]["addresses"]:
                    self.devices[ip].mac = nm[host]["addresses"]["mac"]
                if "vendor" in nm[host] and nm[host]["vendor"]:
                    mac = self.devices[ip].mac
                    if mac in nm[host]["vendor"]:
                        self.devices[ip].vendor = nm[host]["vendor"][mac]
                if "hostnames" in nm[host]:
                    for hi in nm[host]["hostnames"]:
                        if hi.get("name"):
                            self.devices[ip].hostname = hi["name"]
                            break
                if datastore:
                    datastore.upsert_device(self.devices[ip], scan_profile="nmap")
        except Exception:
            pass
        return self.devices
