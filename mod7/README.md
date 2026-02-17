# Module 7: Detection and Analysis

Implements rubric items 7a–7c via Suricata rules, Zeek script, and ARP anomaly monitoring.

## 7a Suricata Rules
File: `mod7/suricata.rules`

Covers:
- SYN scan threshold
- FIN / XMAS / NULL flag signatures
- ACK scan threshold
- UDP scan threshold
- IP fragment observations

Usage (example):
1. Add `mod7/suricata.rules` to your Suricata rule path.
2. Ensure `$HOME_NET` is set to your lab subnet in `suricata.yaml`.
3. Run Suricata on the capture interface while running Modules 2–4.

## 7b Zeek Script
File: `mod7/zeek/scan_detect.zeek`

Covers:
- Port scan detection by counting unique destination ports per source within a window
- Weird TCP flag notices (FIN/XMAS/NULL patterns)

Example (pcap):
```bash
zeek -r capture.pcap mod7/zeek/scan_detect.zeek
```

## 7c ARP/NetFlow Anomaly Detection
- ARPwatch-style monitoring: `mod7/arpwatch_like.py`

Run:
```bash
sudo venv/bin/python mod7/arpwatch_like.py --interface en0 --duration 300
```

- NetFlow rate/pattern detection (timestamped alerts): `mod7/netflow_detect.py`

Run:
```bash
sudo venv/bin/python mod7/netflow_detect.py --listen-port 2055 --duration 60 --window-seconds 10 --unique-port-threshold 20
```

Notes:
- You can still use Module 6 (`mod6/passive_collection.py netflow`) for NetFlow analytics summaries (top talkers, matrices).
- For full credit, correlate NetFlow alerts with Modules 2–4 timing profiles and include a detection matrix in the final report.

## Output
Structured JSON logs under `logs/mod7/`.

## Detection Matrix Helper (Recommended for Full Credit)
To quantify detection success rates across techniques and timing profiles, correlate your scan windows
with IDS outputs:

```bash
venv/bin/python mod7/detection_matrix.py --suricata-eve /var/log/suricata/eve.json --zeek-notice notice.log
```

Outputs:
- `report/detection_matrix.json`
- `report/detection_matrix.md`
