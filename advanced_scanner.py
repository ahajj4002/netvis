#!/usr/bin/env python3
"""
NetVis Advanced Scanner - For VPN/Mesh Networks
================================================

This scanner uses multiple techniques to gather information
about devices on networks where ARP scanning is limited:
- Tailscale
- WireGuard
- ZeroTier
- Corporate VPNs

Techniques:
1. ICMP Echo with TTL analysis
2. TCP SYN probing on common ports
3. Service banner grabbing
4. DNS resolution
5. Tailscale API integration (if available)

Usage:
    sudo python advanced_scanner.py [--network 100.64.100.0/24]
"""

import sys
import os
import socket
import subprocess
import concurrent.futures
import json
import time
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

# Check for root
if os.geteuid() != 0:
    print("⚠️  Some features require root. Run with sudo for full functionality.")

try:
    from scapy.all import IP, ICMP, TCP, UDP, sr1, sr, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0  # Quiet mode
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Some features will be limited.")

# Common ports to probe
COMMON_PORTS = {
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    445: 'SMB',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    3000: 'Dev-Server',
    5000: 'Dev-Server',
    5001: 'Dev-Server',
    9090: 'Prometheus',
    9100: 'Node-Exporter',
    41641: 'Tailscale',  # Tailscale default port
}

# Service signatures for banner grabbing
SERVICE_SIGNATURES = {
    b'SSH-': 'SSH Server',
    b'HTTP/': 'HTTP Server',
    b'220 ': 'FTP Server',
    b'SMTP': 'Mail Server',
    b'* OK': 'IMAP Server',
    b'+OK': 'POP3 Server',
    b'MongoDB': 'MongoDB',
    b'Redis': 'Redis',
    b'mysql': 'MySQL',
    b'PostgreSQL': 'PostgreSQL',
}


@dataclass
class DeviceInfo:
    ip: str
    hostname: str = ''
    is_alive: bool = False
    ttl: int = 0
    os_guess: str = ''
    open_ports: List[int] = None
    services: Dict[int, str] = None
    banners: Dict[int, str] = None
    response_time_ms: float = 0
    hop_count: int = 0
    tailscale_name: str = ''
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}
        if self.banners is None:
            self.banners = {}


def icmp_probe(ip: str, timeout: float = 1.0) -> Optional[DeviceInfo]:
    """Probe host with ICMP and analyze TTL for OS detection"""
    if not SCAPY_AVAILABLE:
        return ping_probe(ip)
    
    try:
        start_time = time.time()
        pkt = IP(dst=ip)/ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        response_time = (time.time() - start_time) * 1000
        
        if reply:
            ttl = reply.ttl
            
            # OS detection based on TTL
            os_guess = ''
            if ttl <= 64:
                os_guess = 'Linux/Unix' if ttl > 32 else 'Embedded/IoT'
                hop_count = 64 - ttl
            elif ttl <= 128:
                os_guess = 'Windows'
                hop_count = 128 - ttl
            else:
                os_guess = 'Cisco/Network Device'
                hop_count = 255 - ttl
            
            return DeviceInfo(
                ip=ip,
                is_alive=True,
                ttl=ttl,
                os_guess=os_guess,
                response_time_ms=response_time,
                hop_count=hop_count
            )
    except Exception as e:
        pass
    
    return None


def ping_probe(ip: str) -> Optional[DeviceInfo]:
    """Fallback ping probe using system ping"""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            # Parse TTL from output
            output = result.stdout
            ttl = 64
            if 'ttl=' in output.lower():
                ttl_part = output.lower().split('ttl=')[1].split()[0]
                ttl = int(ttl_part)
            
            # Parse response time
            response_time = 0
            if 'time=' in output:
                time_part = output.split('time=')[1].split()[0]
                response_time = float(time_part.replace('ms', ''))
            
            os_guess = 'Linux/Unix' if ttl <= 64 else ('Windows' if ttl <= 128 else 'Network Device')
            hop_count = (64 if ttl <= 64 else 128) - ttl
            
            return DeviceInfo(
                ip=ip,
                is_alive=True,
                ttl=ttl,
                os_guess=os_guess,
                response_time_ms=response_time,
                hop_count=max(0, hop_count)
            )
    except:
        pass
    return None


def tcp_probe(ip: str, port: int, timeout: float = 0.5) -> tuple:
    """Probe a TCP port and return (is_open, banner)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            banner = ''
            try:
                # Try to grab banner
                sock.settimeout(1.0)
                
                # Send probe for some services
                if port in [80, 8080, 8443, 443]:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                elif port == 22:
                    pass  # SSH sends banner automatically
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
            except:
                pass
            
            sock.close()
            return (True, banner)
        
        sock.close()
    except:
        pass
    
    return (False, '')


def resolve_hostname(ip: str) -> str:
    """Resolve IP to hostname"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return ''


def get_tailscale_status() -> Dict:
    """Get Tailscale network status if available"""
    try:
        result = subprocess.run(
            ['tailscale', 'status', '--json'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except:
        pass
    return {}


def get_tailscale_peers() -> List[Dict]:
    """Get list of Tailscale peers with their info"""
    status = get_tailscale_status()
    peers = []
    
    if 'Peer' in status:
        for peer_key, peer_info in status['Peer'].items():
            peers.append({
                'ip': peer_info.get('TailscaleIPs', [''])[0] if peer_info.get('TailscaleIPs') else '',
                'hostname': peer_info.get('HostName', ''),
                'dns_name': peer_info.get('DNSName', ''),
                'os': peer_info.get('OS', ''),
                'online': peer_info.get('Online', False),
                'last_seen': peer_info.get('LastSeen', ''),
                'tags': peer_info.get('Tags', []),
            })
    
    return peers


def traceroute_lite(ip: str, max_hops: int = 10) -> List[str]:
    """Quick traceroute to map path"""
    hops = []
    
    if SCAPY_AVAILABLE:
        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=ip, ttl=ttl)/ICMP()
            reply = sr1(pkt, timeout=0.5, verbose=0)
            
            if reply:
                hops.append(reply.src)
                if reply.src == ip:
                    break
            else:
                hops.append('*')
    
    return hops


def scan_device(ip: str, quick: bool = False) -> DeviceInfo:
    """Comprehensive scan of a single device"""
    print(f"  Scanning {ip}...", end='', flush=True)
    
    # ICMP probe first
    device = icmp_probe(ip) or DeviceInfo(ip=ip)
    
    if not device.is_alive:
        print(" ❌ No response")
        return device
    
    print(f" ✓ (TTL={device.ttl}, {device.os_guess})", end='', flush=True)
    
    # Hostname resolution
    device.hostname = resolve_hostname(ip)
    if device.hostname:
        print(f" [{device.hostname}]", end='', flush=True)
    
    # Port scanning
    ports_to_scan = list(COMMON_PORTS.keys()) if not quick else [22, 80, 443, 445, 3389]
    
    for port in ports_to_scan:
        is_open, banner = tcp_probe(ip, port)
        if is_open:
            device.open_ports.append(port)
            device.services[port] = COMMON_PORTS.get(port, f'Port {port}')
            if banner:
                device.banners[port] = banner[:100]
    
    if device.open_ports:
        print(f" Ports: {device.open_ports}", end='')
    
    print()
    return device


def detect_network_type(local_ip: str, gateway_ip: str) -> Dict:
    """Detect what type of network we're on"""
    network_type = {
        'type': 'unknown',
        'name': '',
        'is_vpn': False,
        'is_tailscale': False,
        'is_wireguard': False,
        'can_arp_scan': True,
        'recommendations': []
    }
    
    # Check for Tailscale
    if local_ip.startswith('100.64.') or local_ip.startswith('100.100.'):
        network_type['is_vpn'] = True
        network_type['is_tailscale'] = True
        network_type['type'] = 'tailscale'
        network_type['name'] = 'Tailscale Mesh VPN'
        network_type['can_arp_scan'] = False
        network_type['recommendations'].append('Use "tailscale status" for peer info')
    
    # Check for WireGuard (common subnets)
    elif local_ip.startswith('10.0.0.') or local_ip.startswith('10.200.'):
        # Could be WireGuard, need more checks
        try:
            result = subprocess.run(['wg', 'show'], capture_output=True, timeout=2)
            if result.returncode == 0:
                network_type['is_vpn'] = True
                network_type['is_wireguard'] = True
                network_type['type'] = 'wireguard'
                network_type['name'] = 'WireGuard VPN'
                network_type['can_arp_scan'] = False
        except:
            pass
    
    # Check if gateway is on different subnet
    if local_ip and gateway_ip:
        local_parts = local_ip.split('.')[:3]
        gateway_parts = gateway_ip.split('.')[:3]
        if local_parts != gateway_parts:
            network_type['can_arp_scan'] = False
            network_type['recommendations'].append('Gateway on different subnet')
    
    return network_type


def main():
    import argparse
    parser = argparse.ArgumentParser(description='NetVis Advanced Network Scanner')
    parser.add_argument('--network', '-n', default=None, help='Network to scan (e.g., 100.64.100.0/24)')
    parser.add_argument('--target', '-t', default=None, help='Single target IP')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick scan (fewer ports)')
    parser.add_argument('--tailscale', action='store_true', help='Use Tailscale API for peer discovery')
    parser.add_argument('--output', '-o', default=None, help='Output JSON file')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  NetVis Advanced Scanner")
    print("  For VPN/Mesh Network Analysis")
    print("="*60 + "\n")
    
    results = {
        'scan_time': datetime.now().isoformat(),
        'network_info': {},
        'devices': []
    }
    
    # Detect network type
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    
    gateway_ip = ''
    try:
        result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'default' in line or line.startswith('0.0.0.0'):
                parts = line.split()
                for part in parts:
                    if '.' in part and part.count('.') == 3 and part != '0.0.0.0':
                        gateway_ip = part
                        break
    except:
        pass
    
    network_info = detect_network_type(local_ip, gateway_ip)
    network_info['local_ip'] = local_ip
    network_info['gateway_ip'] = gateway_ip
    results['network_info'] = network_info
    
    print(f"📍 Local IP: {local_ip}")
    print(f"📍 Gateway: {gateway_ip}")
    print(f"📍 Network Type: {network_info['type']} ({network_info['name'] or 'Unknown'})")
    
    if network_info['is_tailscale']:
        print("\n🔗 Tailscale network detected!")
        print("   Fetching peer information from Tailscale API...\n")
        
        peers = get_tailscale_peers()
        if peers:
            print(f"   Found {len(peers)} Tailscale peers:\n")
            print(f"   {'IP':<18} {'Hostname':<25} {'OS':<15} {'Status'}")
            print("   " + "-"*70)
            
            for peer in peers:
                status_icon = '🟢' if peer['online'] else '⚪'
                print(f"   {peer['ip']:<18} {peer['hostname']:<25} {peer['os']:<15} {status_icon}")
                
                # Add to results
                device = DeviceInfo(
                    ip=peer['ip'],
                    hostname=peer['hostname'],
                    is_alive=peer['online'],
                    tailscale_name=peer['dns_name'],
                    os_guess=peer['os']
                )
                results['devices'].append(asdict(device))
            
            print()
        else:
            print("   ⚠️  Could not fetch Tailscale peers")
            print("   Make sure 'tailscale' CLI is installed and you're connected\n")
    
    # Manual scanning
    if args.target:
        print(f"\n🔍 Scanning target: {args.target}")
        device = scan_device(args.target, quick=args.quick)
        results['devices'].append(asdict(device))
    
    elif args.network:
        print(f"\n🔍 Scanning network: {args.network}")
        
        # Parse network
        if '/' in args.network:
            base_ip = args.network.split('/')[0]
            prefix = int(args.network.split('/')[1])
        else:
            base_ip = args.network
            prefix = 24
        
        # Generate IPs
        base_parts = list(map(int, base_ip.split('.')))
        
        if prefix == 24:
            ips = [f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}" for i in range(1, 255)]
        elif prefix == 16:
            # Too many IPs, just scan first 256
            ips = [f"{base_parts[0]}.{base_parts[1]}.0.{i}" for i in range(1, 255)]
        else:
            ips = [f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}" for i in range(1, 255)]
        
        print(f"   Probing {len(ips)} addresses...\n")
        
        # Quick ICMP sweep first
        alive_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(icmp_probe, ip): ip for ip in ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                result = future.result()
                if result and result.is_alive:
                    alive_hosts.append(result)
                    print(f"   ✓ {ip} is alive (TTL={result.ttl}, {result.os_guess})")
        
        print(f"\n   Found {len(alive_hosts)} alive hosts\n")
        
        # Detailed scan of alive hosts
        for device in alive_hosts:
            device = scan_device(device.ip, quick=args.quick)
            results['devices'].append(asdict(device))
    
    else:
        # Default: scan local subnet
        if not network_info['is_tailscale'] or args.tailscale:
            subnet = '.'.join(local_ip.split('.')[:3])
            print(f"\n🔍 Scanning local subnet: {subnet}.0/24")
            print("   (Use --network to specify a different range)\n")
    
    # Summary
    print("\n" + "="*60)
    print("  SCAN SUMMARY")
    print("="*60)
    
    alive_count = sum(1 for d in results['devices'] if d.get('is_alive'))
    print(f"  Devices found: {alive_count}")
    
    # Group by OS
    os_counts = {}
    for d in results['devices']:
        os = d.get('os_guess', 'Unknown')
        os_counts[os] = os_counts.get(os, 0) + 1
    
    print(f"  OS Distribution:")
    for os, count in sorted(os_counts.items(), key=lambda x: -x[1]):
        print(f"    - {os}: {count}")
    
    # Services found
    all_ports = set()
    for d in results['devices']:
        all_ports.update(d.get('open_ports', []))
    
    if all_ports:
        print(f"  Open Ports Found: {sorted(all_ports)}")
    
    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n  Results saved to: {args.output}")
    
    print()
    return results


if __name__ == '__main__':
    main()

