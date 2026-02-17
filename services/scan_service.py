"""
NetVis scan service.
Profile-based network scan with ARP/ICMP discovery and enrichment.
"""

import concurrent.futures
import socket
import subprocess
from dataclasses import asdict
from datetime import datetime
from typing import Callable, Dict, List, Optional

from constants import SCAN_PROFILES
from models import Device
from net_utils import guess_device_type, lookup_mac_vendor, resolve_hostname_multi


def get_network_diagnosis_internal(scanner) -> dict:
    """Build network diagnosis from scanner state (VPN, routed, etc.)."""
    diagnosis = {
        "local_ip": scanner.local_ip,
        "gateway_ip": scanner.gateway_ip,
        "network": scanner.network_cidr,
        "vpn_detected": False,
        "can_arp_scan": True,
        "network_type": "lan",
        "issues": [],
    }
    if scanner.local_ip:
        if scanner.local_ip.startswith("100.64.") or scanner.local_ip.startswith("100.100."):
            diagnosis["vpn_detected"] = True
            diagnosis["can_arp_scan"] = False
            diagnosis["network_type"] = "vpn_cgnat"
            diagnosis["issues"].append("CGNAT/VPN range detected (100.64.x.x)")
        elif scanner.local_ip.startswith("10.") and scanner.gateway_ip:
            local_parts = scanner.local_ip.split(".")[:3]
            gateway_parts = scanner.gateway_ip.split(".")[:3]
            if local_parts != gateway_parts:
                diagnosis["can_arp_scan"] = False
                diagnosis["network_type"] = "routed"
                diagnosis["issues"].append("Gateway on different subnet")
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True)
        utun_count = result.stdout.count("utun")
        if utun_count > 2:
            diagnosis["vpn_detected"] = True
            diagnosis["issues"].append(f"{utun_count} tunnel interfaces detected")
    except Exception:
        pass
    mac_counts: Dict[str, int] = {}
    for device in scanner.devices.values():
        if device.mac:
            mac_counts[device.mac] = mac_counts.get(device.mac, 0) + 1
    for mac, count in mac_counts.items():
        if count > 5:
            diagnosis["vpn_detected"] = True
            diagnosis["can_arp_scan"] = False
            if mac.upper().startswith("DE:AD"):
                diagnosis["network_type"] = "vpn_mesh"
                diagnosis["issues"].append(f"Virtual MAC detected ({mac[:8]}...)")
            break
    return diagnosis


def _discover_hosts_icmp_tcp(scanner, network_cidr: str, is_vpn: bool = False) -> List[dict]:
    """Discover hosts with ICMP and TCP probing for routed/VPN topologies."""
    base_parts = network_cidr.split("/")[0].split(".")[:3]
    ips_to_scan = [f"{'.'.join(base_parts)}.{i}" for i in range(1, 255)]

    def probe_host(ip: str) -> Optional[dict]:
        host_info = {"ip": ip, "alive": False}
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                timeout=2,
            )
            if result.returncode == 0:
                output = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
                host_info["alive"] = True
                ttl = 64
                if "ttl=" in output.lower():
                    ttl = int(output.lower().split("ttl=")[1].split()[0])
                host_info["ttl"] = ttl
                host_info["os_guess"] = "Linux/Unix" if ttl <= 64 else ("Windows" if ttl <= 128 else "Network Device")
        except Exception:
            pass
        if not host_info["alive"]:
            for port in [80, 443, 22, 445]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    if sock.connect_ex((ip, port)) == 0:
                        host_info["alive"] = True
                        host_info["tcp_detected"] = port
                        sock.close()
                        break
                    sock.close()
                except Exception:
                    pass
        if not host_info["alive"]:
            return None
        try:
            host_info["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            host_info["hostname"] = ""
        now = datetime.now().isoformat()
        if ip not in scanner.devices:
            scanner.devices[ip] = Device(
                ip=ip,
                mac="",
                hostname=host_info.get("hostname", ""),
                vendor="VPN/Tunnel" if is_vpn else "",
                os=host_info.get("os_guess", "unknown").lower().replace("/", "_").replace(" ", "_"),
                first_seen=now,
                last_seen=now,
                is_gateway=(ip == scanner.gateway_ip),
                is_local=(ip == scanner.local_ip),
                open_ports=[],
                services={},
            )
        else:
            scanner.devices[ip].last_seen = now
        return host_info

    alive_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(probe_host, ip): ip for ip in ips_to_scan}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive_hosts.append(result)
    return alive_hosts


def run_profile_scan(
    scanner,
    datastore,
    profile: str = "standard",
    target_network: Optional[str] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> dict:
    """Unified scan flow with profile depth and routed-network fallbacks."""
    profile = profile if profile in SCAN_PROFILES else "standard"
    cfg = SCAN_PROFILES[profile]

    def _progress(p: int, msg: str):
        if progress_callback:
            progress_callback(p, msg)

    _progress(5, "Diagnosing network")
    diagnosis = get_network_diagnosis_internal(scanner)
    network_cidr = target_network or scanner.network_cidr
    results = {
        "scan_method": "arp",
        "profile": profile,
        "network_type": diagnosis.get("network_type", "lan"),
        "vpn_detected": diagnosis.get("vpn_detected", False),
        "devices_found": 0,
        "alive_hosts": [],
        "issues": diagnosis.get("issues", []),
        "network": network_cidr,
    }
    can_arp = diagnosis.get("can_arp_scan", True)
    is_vpn = diagnosis.get("vpn_detected", False)
    _progress(15, "Discovering hosts")
    if can_arp and not is_vpn:
        results["scan_method"] = "arp"
        scanner.scan_network_arp()
    else:
        results["scan_method"] = "icmp_tcp"
        results["alive_hosts"] = _discover_hosts_icmp_tcp(scanner, network_cidr, is_vpn=is_vpn)
    discovered_ips = list(scanner.devices.keys())
    if not discovered_ips:
        _progress(100, "No devices found")
        results["devices"] = []
        return results
    _progress(55, f"Enriching {len(discovered_ips)} devices")

    def enrich_one(ip: str):
        device = scanner.devices.get(ip)
        if not device:
            return None
        if not device.vendor and device.mac:
            device.vendor = lookup_mac_vendor(device.mac)
        if not device.hostname:
            device.hostname = resolve_hostname_multi(ip)
        scanner.scan_ports(ip, ports=cfg["ports"], banner_grab=cfg["banner_grab"])
        device = scanner.devices[ip]
        device.os = guess_device_type(device.hostname, device.vendor, device.open_ports)
        datastore.upsert_device(device, scan_profile=profile)
        for port in device.open_ports:
            datastore.upsert_service(
                ip,
                port,
                "tcp",
                device.services.get(port, f"Port {port}"),
                banner=device.service_banners.get(port, ""),
            )
        return asdict(device)

    devices_out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["max_workers"]) as executor:
        futures = {executor.submit(enrich_one, ip): ip for ip in discovered_ips}
        for future in concurrent.futures.as_completed(futures):
            device_dict = future.result()
            if device_dict:
                devices_out.append(device_dict)
    devices_out.sort(key=lambda d: d.get("ip", ""))
    results["devices"] = devices_out
    results["devices_found"] = len(devices_out)
    datastore.add_observation(
        "scan",
        network_cidr,
        f"{profile} scan completed with {len(devices_out)} devices via {results['scan_method']}",
        {"profile": profile, "network": network_cidr, "method": results["scan_method"], "count": len(devices_out)},
    )
    _progress(100, "Scan complete")
    return results
