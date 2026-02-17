# Module 3: IP-Layer Techniques

Implements rubric items 3a–3d.

## 3a IP Fragmentation Testing
- Fragments TCP SYN probes so TCP header spans multiple fragments (`--fragsize` < 20)
- Optional overlapping fragment scenario (`--overlap`) to explore reassembly disagreements

Run:
```bash
sudo venv/bin/python mod3/ip_layer_techniques.py frag --target 192.168.56.10 --dport 80 --fragsize 8 --overlap
```

## 3b TTL-Based Path Inference
- Traceroute-like TTL increment mapping
- ICMP mode or TCP-SYN mode

Run:
```bash
sudo venv/bin/python mod3/ip_layer_techniques.py ttl --target 192.168.56.10 --max-hops 20 --method icmp
sudo venv/bin/python mod3/ip_layer_techniques.py ttl --target 192.168.56.10 --max-hops 20 --method tcp --dport 80
```

## 3c IPID Sequence Analysis + Idle Scan
- `ipid` profiles zombie IPID predictability
- `ipid-sweep` profiles many hosts to quickly find zombies with sequential IPID behavior
- `idle` performs the classic idle scan procedure (requires `--lab-ok`)

Run:
```bash
sudo venv/bin/python mod3/ip_layer_techniques.py ipid --zombie 192.168.56.20 --probes 25
sudo venv/bin/python mod3/ip_layer_techniques.py ipid-sweep --network 192.168.56.0/24 --max-hosts 64 --probes 12
sudo venv/bin/python mod3/ip_layer_techniques.py idle --lab-ok --zombie 192.168.56.20 --target 192.168.56.10 --dport 22
```

Notes:
- `idle` performs an IPID suitability pre-check and will refuse to spoof if the selected zombie does not look sequential/predictable.

## 3d Decoy Source Mixing
- Sends interleaved real and spoofed-source SYN probes (requires `--lab-ok`)
- Analysis is primarily from the target's logs perspective

Run:
```bash
sudo venv/bin/python mod3/ip_layer_techniques.py decoy --lab-ok --target 192.168.56.10 --dport 80 \
  --decoy 192.168.56.30 --decoy 192.168.56.31 --decoy 192.168.56.32
```

## Output
Structured JSON logs under `logs/mod3/`.
