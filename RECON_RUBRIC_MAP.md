# NetVis Rubric Mapping (Code + Commands)

This repository contains a NetVis GUI plus a rubric-aligned toolkit organized by module (`mod1/`..`mod7/`).

## Key Requirements Checklist
- Structured JSON logs: `logs/mod*/<session>.json`
- Per-module READMEs: `mod*/README.md`
- Lab-safety guardrails: private targets only; spoofing requires explicit acknowledgement

## Module 1 (40 pts)
- **1a Active ARP Enumeration**
  - Script: `mod1/link_layer_discovery.py active`
  - Example:
    ```bash
    sudo venv/bin/python mod1/link_layer_discovery.py active --network 192.168.56.0/24 --interface eth0
    ```
- **1b Passive ARP Observation**
  - Script: `mod1/link_layer_discovery.py passive`
  - Example:
    ```bash
    sudo venv/bin/python mod1/link_layer_discovery.py passive --duration 600 --interface eth0
    ```
- **1c MAC Address Randomization**
  - Script: `mod1/link_layer_discovery.py randomized`

## Module 2 (80 pts)
- **2a TCP SYN Scan**: `mod2/transport_scans.py syn`
- **2b TCP Connect Scan**: `mod2/transport_scans.py connect`
- **2c FIN**: `mod2/transport_scans.py fin`
- **2d XMAS**: `mod2/transport_scans.py xmas`
- **2e NULL**: `mod2/transport_scans.py null`
- **2f UDP**: `mod2/transport_scans.py udp`
- **2g ACK**: `mod2/transport_scans.py ack`

## Module 3 (60 pts)
- **3a Fragmentation**: `mod3/ip_layer_techniques.py frag`
- **3b TTL Path**: `mod3/ip_layer_techniques.py ttl`
- **3c IPID + Idle Scan**: `mod3/ip_layer_techniques.py ipid` and `idle --lab-ok`
- **(Helper) IPID Sweep**: `mod3/ip_layer_techniques.py ipid-sweep` (find suitable zombies faster)
- **3d Decoy Mixing**: `mod3/ip_layer_techniques.py decoy --lab-ok`

## Module 4 (35 pts)
- **4a Fixed Rates**: `mod4/timing_rate_control.py fixed`
- **4b Jitter**: `mod4/timing_rate_control.py jitter`
- **4c Ordering**: `mod4/timing_rate_control.py order`

## Module 5 (75 pts)
- **5a Banner**: `mod5/app_fingerprinting.py banner`
- **5b TLS Certs**: `mod5/app_fingerprinting.py tls`
- **5c HTTP Headers**: `mod5/app_fingerprinting.py http`
- **5d TCP Fingerprint**: `mod5/app_fingerprinting.py tcpfp`
- **5e DNS Enum + Passive DNS**: `mod5/app_fingerprinting.py dns` and `passive-dns`

## Module 6 (35 pts)
- **6a Promisc Capture**: `mod6/passive_collection.py promisc`
- **6b SPAN Alternative (pcap)**: `mod6/passive_collection.py pcap`
- **6c NetFlow v5 Collector**: `mod6/passive_collection.py netflow`

## Module 7 (50 pts)
- **7a IDS Rules**: `mod7/suricata.rules`
- **7b Zeek Script**: `mod7/zeek/scan_detect.zeek`
- **7c ARPwatch-style monitor**: `mod7/arpwatch_like.py`
- **(Helper) NetFlow Alerting**: `mod7/netflow_detect.py` (timestamped alerts from NetFlow v5 exports)

### Detection Matrix (Recommended)
After running scans and collecting Suricata/Zeek logs, correlate and summarize:
```bash
venv/bin/python mod7/detection_matrix.py --suricata-eve /var/log/suricata/eve.json --zeek-notice notice.log
```
Outputs: `report/detection_matrix.json` and `report/detection_matrix.md`

### Report Template
Use: `report/FINAL_REPORT_TEMPLATE.md`

## NetVis GUI
- Backend: `sudo venv/bin/python server.py`
- Frontend: `npm run dev`
- Intelligence story endpoint: `GET /api/intel/story`
