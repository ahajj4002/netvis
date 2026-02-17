# Module 1: Link-Layer Discovery

Implements rubric items 1a–1c using Scapy.

## 1a Active ARP Enumeration
- Broadcast ARP over target subnet
- Extract IP-to-MAC mapping
- Measures:
  - `scan_duration_seconds`, `time_per_probe_ms`
  - `response_rate`
  - VLAN boundary behavior heuristic
- Supports `/24` and `/16` via CIDR input

Run:
```bash
sudo venv/bin/python mod1/link_layer_discovery.py active --network 192.168.56.0/24 --interface en0
```

## 1b Passive ARP Observation
- Promiscuous capture of ARP frames only (no transmissions)
- Reconstructs IP-to-MAC table
- Measures coverage at 1 min / 10 min / 1 hour
- Verifies zero tool transmission using interface TX counters (best-effort)

Run:
```bash
sudo venv/bin/python mod1/link_layer_discovery.py passive --duration 600 --interface en0
```

## 1c MAC Address Randomization
- Uses a randomized locally-administered MAC as the Ethernet source for the ARP probe session
- Logs both real interface MAC and randomized probe MAC

Run:
```bash
sudo venv/bin/python mod1/link_layer_discovery.py randomized --network 192.168.56.0/24 --interface en0
```

## Output
Structured JSON logs are written under `logs/mod1/`.
