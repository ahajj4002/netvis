#!/usr/bin/env python3
"""
NetVis Topology Mapper
======================

Advanced network topology mapping using multiple techniques:

1. ICMP TTL Analysis - Map hop distances and estimate network topology
2. Traceroute Mapping - Discover intermediate routers
3. DNS Enumeration - Find hosts via DNS zone queries
4. TCP Fingerprinting - OS detection via TCP/IP stack behavior
5. UDP Probing - Find UDP services
6. Banner Grabbing - Service identification
7. SSL/TLS Certificate Analysis - Identify services from certificates

For VPN/Tailscale networks, this provides much more insight than ARP scanning.

Usage:
    sudo python topology_mapper.py [network]
    sudo python topology_mapper.py 100.64.100.0/24
    sudo python topology_mapper.py --single 100.64.100.42
"""

import sys
import os
import socket
import subprocess
import ssl
import struct
import time
import json
import concurrent.futures
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple

# Check root
if os.geteuid() != 0:
    print("⚠️  Run with sudo for full functionality")

try:
    from scapy.all import (
        IP, ICMP, TCP, UDP, DNS, DNSQR, sr1, sr, send, conf,
        RandShort, sniff
    )
    SCAPY_AVAILABLE = True
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not available. Install with: pip install scapy")

# Color output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


@dataclass
class Host:
    ip: str
    hostname: str = ''
    mac: str = ''
    os_guess: str = ''
    ttl: int = 0
    hops: int = 0
    open_tcp_ports: List[int] = None
    open_udp_ports: List[int] = None
    services: Dict[int, str] = None
    banners: Dict[int, str] = None
    ssl_certs: Dict[int, dict] = None
    response_time_ms: float = 0
    is_alive: bool = False
    path: List[str] = None  # Traceroute path
    
    def __post_init__(self):
        if self.open_tcp_ports is None:
            self.open_tcp_ports = []
        if self.open_udp_ports is None:
            self.open_udp_ports = []
        if self.services is None:
            self.services = {}
        if self.banners is None:
            self.banners = {}
        if self.ssl_certs is None:
            self.ssl_certs = {}
        if self.path is None:
            self.path = []


def print_header(text: str):
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}{Colors.RESET}\n")


def print_success(text: str):
    print(f"{Colors.GREEN}  ✓ {text}{Colors.RESET}")


def print_warning(text: str):
    print(f"{Colors.YELLOW}  ⚠ {text}{Colors.RESET}")


def print_error(text: str):
    print(f"{Colors.RED}  ✗ {text}{Colors.RESET}")


def print_info(text: str):
    print(f"{Colors.BLUE}  → {text}{Colors.RESET}")


# ============= TECHNIQUE 1: ICMP Ping with TTL Analysis =============

def icmp_probe(ip: str, timeout: float = 1.0) -> Optional[Host]:
    """ICMP ping with TTL analysis for OS guessing and hop counting"""
    if not SCAPY_AVAILABLE:
        return ping_fallback(ip)
    
    try:
        start = time.time()
        pkt = IP(dst=ip)/ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        elapsed = (time.time() - start) * 1000
        
        if reply:
            ttl = reply.ttl
            
            # OS detection based on initial TTL
            if ttl <= 64:
                os_guess = 'Linux/Unix/macOS' if ttl > 32 else 'Embedded Device'
                initial_ttl = 64
            elif ttl <= 128:
                os_guess = 'Windows'
                initial_ttl = 128
            else:
                os_guess = 'Cisco/Network Device'
                initial_ttl = 255
            
            hops = initial_ttl - ttl
            
            return Host(
                ip=ip,
                is_alive=True,
                ttl=ttl,
                hops=hops,
                os_guess=os_guess,
                response_time_ms=elapsed
            )
    except:
        pass
    return None


def ping_fallback(ip: str) -> Optional[Host]:
    """Fallback ping using system command"""
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            # Parse TTL
            ttl = 64
            if 'ttl=' in result.stdout.lower():
                ttl = int(result.stdout.lower().split('ttl=')[1].split()[0])
            
            # Parse time
            time_ms = 0
            if 'time=' in result.stdout:
                time_ms = float(result.stdout.split('time=')[1].split()[0].replace('ms', ''))
            
            os_guess = 'Linux/Unix' if ttl <= 64 else ('Windows' if ttl <= 128 else 'Network Device')
            
            return Host(
                ip=ip,
                is_alive=True,
                ttl=ttl,
                hops=max(0, (64 if ttl <= 64 else 128) - ttl),
                os_guess=os_guess,
                response_time_ms=time_ms
            )
    except:
        pass
    return None


# ============= TECHNIQUE 2: Traceroute =============

def traceroute(ip: str, max_hops: int = 15) -> List[str]:
    """Traceroute to map network path"""
    hops = []
    
    if SCAPY_AVAILABLE:
        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=ip, ttl=ttl)/ICMP()
            reply = sr1(pkt, timeout=1, verbose=0)
            
            if reply:
                hops.append(reply.src)
                if reply.src == ip:
                    break
            else:
                hops.append('*')
    else:
        # Fallback to system traceroute
        try:
            result = subprocess.run(
                ['traceroute', '-n', '-m', str(max_hops), '-w', '1', ip],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    hop = parts[1]
                    hops.append(hop if hop != '*' else '*')
        except:
            pass
    
    return hops


# ============= TECHNIQUE 3: TCP SYN Scan =============

COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
]

def tcp_syn_scan(ip: str, ports: List[int] = None, timeout: float = 0.5) -> List[int]:
    """TCP SYN scan (half-open scan)"""
    if ports is None:
        ports = COMMON_TCP_PORTS
    
    open_ports = []
    
    if SCAPY_AVAILABLE:
        for port in ports:
            pkt = IP(dst=ip)/TCP(dport=port, flags='S')
            reply = sr1(pkt, timeout=timeout, verbose=0)
            if reply and reply.haslayer(TCP):
                if reply[TCP].flags == 0x12:  # SYN-ACK
                    open_ports.append(port)
                    # Send RST to close
                    send(IP(dst=ip)/TCP(dport=port, flags='R'), verbose=0)
    else:
        # Fallback to connect scan
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
    
    return open_ports


def tcp_connect_scan(ip: str, port: int, timeout: float = 0.5) -> Tuple[bool, str]:
    """TCP connect with banner grabbing"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            banner = ''
            try:
                sock.settimeout(2)
                if port in [80, 8080]:
                    sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:300]
            except:
                pass
            sock.close()
            return (True, banner)
        sock.close()
    except:
        pass
    return (False, '')


# ============= TECHNIQUE 4: UDP Scan =============

UDP_PORTS = {
    53: ('DNS', b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
    67: ('DHCP', b''),
    68: ('DHCP', b''),
    69: ('TFTP', b'\x00\x01test\x00octet\x00'),
    123: ('NTP', b'\x1b' + 47 * b'\x00'),
    137: ('NetBIOS', b''),
    161: ('SNMP', b'\x30\x26\x02\x01\x01\x04\x06public'),
    500: ('IKE', b''),
    1900: ('SSDP', b'M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\n'),
}

def udp_probe(ip: str, port: int, probe: bytes, timeout: float = 2.0) -> bool:
    """UDP probe with specific payload"""
    if SCAPY_AVAILABLE:
        try:
            pkt = IP(dst=ip)/UDP(dport=port)/probe
            reply = sr1(pkt, timeout=timeout, verbose=0)
            # If we get ICMP port unreachable, port is closed
            # If we get UDP reply or no response, could be open
            if reply:
                if reply.haslayer(UDP):
                    return True
                if reply.haslayer(ICMP) and reply[ICMP].type == 3:
                    return False  # Port unreachable
            return True  # Assume open if no response (filtered or open)
        except:
            pass
    return False


# ============= TECHNIQUE 5: SSL/TLS Certificate Grab =============

def grab_ssl_cert(ip: str, port: int = 443, timeout: float = 3.0) -> Optional[dict]:
    """Grab SSL/TLS certificate information"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'notBefore': cert.get('notBefore', ''),
                        'notAfter': cert.get('notAfter', ''),
                        'serialNumber': cert.get('serialNumber', ''),
                        'version': cert.get('version', 0)
                    }
    except:
        pass
    return None


# ============= TECHNIQUE 6: DNS Enumeration =============

def dns_resolve(ip: str) -> str:
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ''


def dns_query(domain: str, qtype: str = 'A', server: str = '8.8.8.8') -> List[str]:
    """DNS query for a domain"""
    results = []
    if SCAPY_AVAILABLE:
        try:
            pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
            reply = sr1(pkt, timeout=2, verbose=0)
            if reply and reply.haslayer(DNS):
                for i in range(reply[DNS].ancount):
                    results.append(str(reply[DNS].an[i].rdata))
        except:
            pass
    return results


# ============= TECHNIQUE 7: TCP Fingerprinting =============

def tcp_fingerprint(ip: str, port: int = 80) -> dict:
    """TCP/IP stack fingerprinting for OS detection"""
    fingerprint = {}
    
    if not SCAPY_AVAILABLE:
        return fingerprint
    
    try:
        # SYN packet
        syn = IP(dst=ip)/TCP(dport=port, flags='S', seq=1000)
        reply = sr1(syn, timeout=2, verbose=0)
        
        if reply and reply.haslayer(TCP):
            fingerprint['window_size'] = reply[TCP].window
            fingerprint['options'] = [opt[0] for opt in reply[TCP].options]
            fingerprint['ttl'] = reply[IP].ttl
            fingerprint['df'] = bool(reply[IP].flags & 0x2)  # Don't Fragment
            
            # OS guessing based on characteristics
            win = fingerprint['window_size']
            ttl = fingerprint['ttl']
            
            if ttl <= 64:
                if win == 65535:
                    fingerprint['os_guess'] = 'macOS/iOS'
                elif win == 5840 or win == 14600:
                    fingerprint['os_guess'] = 'Linux'
                else:
                    fingerprint['os_guess'] = 'Unix/Linux variant'
            elif ttl <= 128:
                if win == 8192 or win == 64240:
                    fingerprint['os_guess'] = 'Windows Server'
                elif win == 65535:
                    fingerprint['os_guess'] = 'Windows 10/11'
                else:
                    fingerprint['os_guess'] = 'Windows variant'
            else:
                fingerprint['os_guess'] = 'Network Device/Cisco'
            
            # Send RST to clean up
            send(IP(dst=ip)/TCP(dport=port, flags='R'), verbose=0)
    except:
        pass
    
    return fingerprint


# ============= MAIN SCANNING LOGIC =============

def deep_scan_host(ip: str, quick: bool = False) -> Host:
    """Comprehensive scan of a single host"""
    host = Host(ip=ip)
    
    # Step 1: ICMP Ping
    print_info(f"Probing {ip}...")
    ping_result = icmp_probe(ip)
    if ping_result:
        host.is_alive = True
        host.ttl = ping_result.ttl
        host.hops = ping_result.hops
        host.os_guess = ping_result.os_guess
        host.response_time_ms = ping_result.response_time_ms
        print_success(f"Alive! TTL={host.ttl} ({host.os_guess}), {host.response_time_ms:.1f}ms")
    else:
        print_warning(f"No ICMP response, trying TCP...")
        # Try TCP probe
        for port in [80, 443, 22]:
            is_open, _ = tcp_connect_scan(ip, port)
            if is_open:
                host.is_alive = True
                print_success(f"Alive (TCP port {port} open)")
                break
        if not host.is_alive:
            print_error(f"Host appears down")
            return host
    
    # Step 2: Hostname
    host.hostname = dns_resolve(ip)
    if host.hostname:
        print_success(f"Hostname: {host.hostname}")
    
    # Step 3: Port Scan
    print_info("TCP port scanning...")
    ports = [22, 80, 443, 445, 3389] if quick else COMMON_TCP_PORTS
    host.open_tcp_ports = tcp_syn_scan(ip, ports)
    if host.open_tcp_ports:
        print_success(f"Open TCP ports: {host.open_tcp_ports}")
        
        # Banner grabbing
        for port in host.open_tcp_ports[:5]:  # Limit to first 5
            _, banner = tcp_connect_scan(ip, port)
            if banner:
                host.banners[port] = banner[:100]
                # Determine service from banner
                service = identify_service(port, banner)
                host.services[port] = service
    
    # Step 4: SSL/TLS on HTTPS ports
    ssl_ports = [p for p in host.open_tcp_ports if p in [443, 8443, 993, 995]]
    for port in ssl_ports:
        cert = grab_ssl_cert(ip, port)
        if cert:
            host.ssl_certs[port] = cert
            cn = cert.get('subject', {}).get('commonName', '')
            if cn:
                print_success(f"SSL Cert on :{port} -> {cn}")
    
    # Step 5: TCP Fingerprint (if not quick)
    if not quick and host.open_tcp_ports:
        print_info("TCP fingerprinting...")
        fp = tcp_fingerprint(ip, host.open_tcp_ports[0])
        if fp.get('os_guess'):
            host.os_guess = fp['os_guess']
            print_success(f"OS Fingerprint: {host.os_guess}")
    
    # Step 6: Traceroute (if not quick)
    if not quick:
        print_info("Mapping route...")
        host.path = traceroute(ip, max_hops=10)
        if host.path:
            print_success(f"Route ({len(host.path)} hops): {' -> '.join(host.path[:5])}...")
    
    return host


def identify_service(port: int, banner: str) -> str:
    """Identify service from port and banner"""
    # Common port mapping
    port_services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt', 9200: 'Elasticsearch'
    }
    
    # Banner-based detection
    banner_lower = banner.lower()
    if 'ssh' in banner_lower:
        return f"SSH ({banner.split('\\n')[0][:30]})"
    elif 'nginx' in banner_lower:
        return 'Nginx'
    elif 'apache' in banner_lower:
        return 'Apache'
    elif 'microsoft' in banner_lower:
        return 'IIS'
    elif 'openssh' in banner_lower:
        return 'OpenSSH'
    
    return port_services.get(port, f'Port {port}')


def scan_network(network: str, quick: bool = True) -> List[Host]:
    """Scan an entire network"""
    # Parse network
    if '/' in network:
        base_ip = network.split('/')[0]
        prefix = int(network.split('/')[1])
    else:
        base_ip = network
        prefix = 24
    
    base_parts = list(map(int, base_ip.split('.')))
    
    if prefix == 24:
        ips = [f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}" for i in range(1, 255)]
    elif prefix == 16:
        # Just scan first /24 for now
        ips = [f"{base_parts[0]}.{base_parts[1]}.0.{i}" for i in range(1, 255)]
    else:
        ips = [f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}" for i in range(1, 255)]
    
    print_header(f"Scanning {len(ips)} addresses")
    
    # Phase 1: Quick ICMP sweep
    print_info("Phase 1: ICMP Discovery")
    alive_hosts = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(icmp_probe, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result.is_alive:
                alive_hosts.append(result)
                print(f"    {Colors.GREEN}✓ {result.ip} (TTL={result.ttl}){Colors.RESET}")
    
    print_success(f"Found {len(alive_hosts)} alive hosts")
    
    # Phase 2: Deep scan alive hosts
    if not quick and alive_hosts:
        print_info("Phase 2: Deep Scanning")
        detailed = []
        for host in alive_hosts[:20]:  # Limit to 20 for time
            detailed_host = deep_scan_host(host.ip, quick=True)
            detailed.append(detailed_host)
        return detailed
    
    return alive_hosts


def send_to_gui(hosts: List[Host]):
    """Send discovered hosts to the NetVis GUI"""
    import urllib.request
    import json
    
    devices = []
    for host in hosts:
        devices.append({
            'ip': host.ip,
            'mac': host.mac,
            'hostname': host.hostname,
            'os_guess': host.os_guess,
            'open_ports': host.open_tcp_ports,
            'services': host.services,
            'device_type': host.os_guess.lower().replace('/', '_').replace(' ', '_')
        })
    
    try:
        data = json.dumps({'devices': devices}).encode('utf-8')
        req = urllib.request.Request(
            'http://localhost:5001/api/mitm/devices',
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            print_success(f"Sent {len(devices)} devices to GUI")
    except Exception as e:
        print_warning(f"Could not send to GUI: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='NetVis Topology Mapper')
    parser.add_argument('network', nargs='?', default=None, help='Network to scan (e.g., 100.64.100.0/24)')
    parser.add_argument('--single', '-s', default=None, help='Single host to scan')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick scan (fewer probes)')
    parser.add_argument('--deep', '-d', action='store_true', help='Deep scan all hosts')
    parser.add_argument('--output', '-o', default=None, help='Output JSON file')
    parser.add_argument('--gui', action='store_true', help='Send results to NetVis GUI')
    args = parser.parse_args()
    
    print_header("NetVis Topology Mapper")
    print(f"  Techniques: ICMP, TCP SYN, Banner Grab, SSL Cert, Traceroute")
    print()
    
    results = []
    
    if args.single:
        # Single host deep scan
        host = deep_scan_host(args.single, quick=args.quick)
        results.append(host)
        
        print_header("SCAN RESULTS")
        print(f"  {Colors.BOLD}IP:{Colors.RESET} {host.ip}")
        print(f"  {Colors.BOLD}Hostname:{Colors.RESET} {host.hostname or 'N/A'}")
        print(f"  {Colors.BOLD}OS Guess:{Colors.RESET} {host.os_guess}")
        print(f"  {Colors.BOLD}TTL:{Colors.RESET} {host.ttl} ({host.hops} hops away)")
        print(f"  {Colors.BOLD}Response:{Colors.RESET} {host.response_time_ms:.1f}ms")
        print(f"  {Colors.BOLD}Open Ports:{Colors.RESET} {host.open_tcp_ports}")
        if host.services:
            print(f"  {Colors.BOLD}Services:{Colors.RESET}")
            for port, svc in host.services.items():
                print(f"    {port}: {svc}")
        if host.path:
            print(f"  {Colors.BOLD}Route:{Colors.RESET} {' → '.join(host.path)}")
    
    elif args.network:
        results = scan_network(args.network, quick=not args.deep)
        
        print_header("SCAN SUMMARY")
        print(f"  Total hosts found: {len(results)}")
        
        # Group by OS
        os_counts = {}
        for h in results:
            os_counts[h.os_guess] = os_counts.get(h.os_guess, 0) + 1
        print(f"  OS Distribution:")
        for os, count in sorted(os_counts.items(), key=lambda x: -x[1]):
            print(f"    {os}: {count}")
    
    else:
        # Default: show help
        parser.print_help()
        return
    
    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump([asdict(h) for h in results], f, indent=2)
        print_success(f"Saved to {args.output}")
    
    # Send to GUI
    if args.gui:
        send_to_gui(results)
    
    print()


if __name__ == '__main__':
    main()

