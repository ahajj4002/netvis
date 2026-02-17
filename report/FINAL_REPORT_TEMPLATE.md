# NetVis: Network Reconnaissance Report (Template)

Fill this in with results from your lab runs. This repo already produces structured JSON logs under `logs/mod*/`.

## 0. Lab Setup
- Date/time:
- Lab topology: (VMs, subnets, gateway)
- Scanner host OS:
- Scanner interface:
- Target subnet(s):
- Tools running:
- Suricata version/config (HOME_NET, interface):
- Zeek version/config:
- NetFlow exporter (device + export settings) if used:

## 1. Link-Layer Discovery (Module 1)
### 1a Active ARP Enumeration
- Command used:
- Log file: `logs/mod1/<session>.json`
- Metrics to report:
- `scan_duration_seconds`
- `response_rate`
- `time_per_probe_ms`
- VLAN boundary observations from `vlan_boundary_behavior`

### 1b Passive ARP Observation
- Command used:
- Log file: `logs/mod1/<session>.json`
- Promisc verification from `promiscuous_flag_before/after`
- Coverage metrics:
- `hosts_seen_within_1_min`
- `hosts_seen_within_10_min`
- `hosts_seen_within_1_hour`
- Compare passive coverage vs. active coverage:

### 1c MAC Address Randomization
- Command used:
- Log file: `logs/mod1/<session>.json`
- Real MAC vs randomized probe MAC:
- Observations:
- Switch CAM behavior:
- Port security / 802.1X behavior:
- Correlation behavior (arpwatch, etc.):

## 2. Transport-Layer Scans (Module 2)
For each technique, include: ports tested, results, and which logging/detection systems recorded it.

### 2a TCP SYN (Half-Open) Scan
- Command used:
- Log file: `logs/mod2/<session>.json`
- Detection notes: Suricata/Zeek/host logs

### 2b TCP Connect Scan (Baseline)
- Command used:
- Log file: `logs/mod2/<session>.json`
- Compare detection vs SYN:

### 2c TCP FIN Scan
- Command used:
- Log file: `logs/mod2/<session>.json`
- OS behavior notes (RFC 793 vs Windows):

### 2d TCP XMAS Scan
- Command used:
- Log file: `logs/mod2/<session>.json`

### 2e TCP NULL Scan
- Command used:
- Log file: `logs/mod2/<session>.json`

### 2f UDP Scan
- Command used:
- Log file: `logs/mod2/<session>.json`
- ICMP rate-limiting observations:

### 2g TCP ACK Scan (Firewall Mapping)
- Command used:
- Log file: `logs/mod2/<session>.json`
- Inferred filtering topology:

## 3. IP-Layer Techniques (Module 3)
### 3a IP Fragmentation
- Command used:
- Log file: `logs/mod3/<session>.json`
- Compare target vs monitor reassembly observations:

### 3b TTL-Based Path Inference
- Command used:
- Log file: `logs/mod3/<session>.json`
- Hop list and inferred topology:

### 3c IPID Sequence Analysis (Idle Scan)
- IPID profile command + log:
- Idle scan command + log:
- Notes on modern OS behavior:

### 3d Decoy Source Mixing
- Command used:
- Log file: `logs/mod3/<session>.json`
- What target logs looked like:
- What defender would need to correlate:

## 4. Timing and Rate Variation (Module 4)
### 4a Fixed-Rate Scanning at Multiple Speeds
- Command used:
- Log file: `logs/mod4/<session>.json`
- For each rate profile, include:
- Scan duration
- Completeness
- IDS detection outcome

### 4b Randomized Jitter
- Command used:
- Log file: `logs/mod4/<session>.json`
- Compare inter-arrival histograms and detection:

### 4c Target Ordering Randomization
- Command used:
- Log file: `logs/mod4/<session>.json`
- Compare sequential vs shuffled detection:

## 5. Application-Layer Fingerprinting (Module 5)
### 5a Banner Grabbing
- Command used:
- Log file: `logs/mod5/<session>.json`
- Findings:

### 5b TLS Certificate Inspection
- Command used:
- Log file: `logs/mod5/<session>.json`
- Certificate leakage notes:

### 5c HTTP Header Analysis
- Command used:
- Log file: `logs/mod5/<session>.json`
- Security headers posture:

### 5d TCP Stack Fingerprinting
- Command used:
- Log file: `logs/mod5/<session>.json`
- Match confidence:

### 5e DNS Enumeration (Active + Passive)
- Commands used:
- Log files: `logs/mod5/<session>.json`
- Zone transfer attempts:
- Passive DNS top domains:

## 6. Passive Collection Methods (Module 6)
### 6a Promiscuous-Mode Capture
- Command used:
- Log file: `logs/mod6/<session>.json`
- Inventory/graph summary (unique hosts, flows, top talkers):

### 6b SPAN/Mirror Port Ingestion (PCAP)
- Command used:
- Log file: `logs/mod6/<session>.json`
- Compare visibility vs promisc capture:

### 6c NetFlow/IPFIX/sFlow Collection
- Command used:
- Log file: `logs/mod6/<session>.json`
- Matrix/top talkers/long flows/scanning pattern signals:

## 7. Detection-Side Exercises (Module 7)
### Suricata Rules
- Rules file: `mod7/suricata.rules`
- SIDs that fired and why:

### Zeek Detection
- Script: `mod7/zeek/scan_detect.zeek`
- Notices observed and why:

### ARPwatch-Style Monitoring
- Command used:
- Log file: `logs/mod7/<session>.json`
- Events observed:

### Detection Matrix (Auto-Correlated)
Run:
```bash
venv/bin/python mod7/detection_matrix.py --suricata-eve /var/log/suricata/eve.json --zeek-notice notice.log
```
Include:
- `report/detection_matrix.md`
- Key takeaways: which techniques/timing profiles were most detectable and why

## 8. "Network Story" (Correlation Narrative)
Use the NetVis GUI story panel and your module logs to tell a coherent story:
- Asset inventory: who exists, where, and why you believe it
- Exposures: open ports, risky services, weak security headers
- Behavior: traffic patterns, top talkers, DNS patterns, long flows
- Defender view: what your IDS/Zeek/flow telemetry saw for each technique

## Appendix A: Commands Run
- Paste the exact commands you ran (or reference `RECON_RUBRIC_MAP.md`)

## Appendix B: Artifacts
- List log files submitted and any pcaps/Suricata/Zeek logs referenced
