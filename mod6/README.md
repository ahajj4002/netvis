# Module 6: Passive Collection Methods

Implements rubric items 6a–6c.

## 6a Promiscuous-Mode Capture
Captures frames visible to the NIC and parses:
- L2: MAC addresses
- L3: IPs + TTL
- L4: ports/protocols
- L7: application identifiers via port mapping

Run:
```bash
sudo venv/bin/python mod6/passive_collection.py promisc --interface en0 --duration 60
```

## 6b SPAN/Mirror Port Ingestion
If a SPAN port is available, run `promisc` capture on the SPAN interface.
If hardware is unavailable, use `pcap` ingestion to simulate mirrored visibility:

```bash
venv/bin/python mod6/passive_collection.py pcap --path /path/to/span_capture.pcap
```

Document limitations and compare visibility vs inline promisc capture.

## 6c NetFlow/IPFIX/sFlow Collection
Includes a NetFlow v5 collector for lab simulation (e.g., using `softflowd`).

Run collector:
```bash
sudo venv/bin/python mod6/passive_collection.py netflow --listen-port 2055 --duration 60
```

Then configure an exporter (router or `softflowd`) to send to `<collector_ip>:2055`.

Analytics:
- connection matrix
- top talkers
- long-duration flow detection
- scanning pattern identification (many unique dst ports)

## Output
Structured JSON logs under `logs/mod6/`.
