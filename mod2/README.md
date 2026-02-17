# Module 2: Transport-Layer Port Scanning

Implements rubric items 2a–2g using Scapy (raw packets) and sockets for the 2b baseline.

## Techniques
- `syn`: 2a TCP SYN half-open scan (sends RST after SYN-ACK)
- `connect`: 2b TCP connect scan (full handshake baseline, via OS sockets)
- `fin`: 2c TCP FIN scan
- `xmas`: 2d TCP XMAS scan (FIN+PSH+URG)
- `null`: 2e TCP NULL scan (no flags)
- `udp`: 2f UDP scan (DNS/NTP/SNMP payloads on 53/123/161)
- `ack`: 2g TCP ACK scan (maps filtering/unfiltered; produces a simple firewall topology map)

## Timing Controls (used for Module 4)
- `--delay <sec>` fixed inter-probe delay
- `--jitter none|uniform|exponential` with `--jitter-arg`
- `--shuffle` randomizes full (host,port) tuple ordering

## Usage Examples
Single host:
```bash
sudo venv/bin/python mod2/transport_scans.py --host 192.168.56.10 --ports 22,80,443 syn
sudo venv/bin/python mod2/transport_scans.py --host 192.168.56.10 --ports 22,80,443 connect
sudo venv/bin/python mod2/transport_scans.py --host 192.168.56.10 --ports 22,80,443 fin
sudo venv/bin/python mod2/transport_scans.py --host 192.168.56.10 --ports 53,123,161 udp
sudo venv/bin/python mod2/transport_scans.py --host 192.168.56.10 --ports 22,80,443,445 ack
```

Subnet scan:
```bash
sudo venv/bin/python mod2/transport_scans.py --network 192.168.56.0/24 --ports 22,80,443 syn
```

## Output
Structured JSON logs under `logs/mod2/`.

## Detection Exercises
Run Suricata/Snort/Zeek alongside these scans and record:
- detection/no detection per technique
- timing profile used
- completeness (% ports classified)
