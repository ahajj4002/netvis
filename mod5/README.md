# Module 5: Application-Layer Fingerprinting

Implements rubric items 5a–5e.

## 5a Banner Grabbing
Grabs initial banners on:
- FTP (21)
- SSH (22)
- SMTP (25)
- HTTP (80)
- HTTPS (443)

Run:
```bash
sudo venv/bin/python mod5/app_fingerprinting.py banner --host 192.168.56.10 --ports 21,22,25,80,443
```

## 5b TLS Certificate Inspection
Uses `openssl s_client -showcerts` to extract the full chain, then parses each cert.

Run:
```bash
venv/bin/python mod5/app_fingerprinting.py tls --host 192.168.56.10 --port 443
```

## 5c HTTP Header Analysis
Collects response headers and flags security-relevant headers (CSP/HSTS/etc).

Run:
```bash
venv/bin/python mod5/app_fingerprinting.py http --host 192.168.56.10 --port 80
venv/bin/python mod5/app_fingerprinting.py http --host 192.168.56.10 --port 443 --tls
```

## 5d TCP Stack Fingerprinting
Sends crafted SYN probes and matches against a small heuristic DB, outputting a confidence score.

Run:
```bash
sudo venv/bin/python mod5/app_fingerprinting.py tcpfp --host 192.168.56.10 --dport 80
```

## 5e DNS Enumeration + Passive DNS
- `dns` queries A/AAAA/MX/NS/TXT/SRV/CNAME and attempts AXFR (if `dig` exists)
- `passive-dns` sniffs local DNS queries on UDP/53

Run:
```bash
venv/bin/python mod5/app_fingerprinting.py dns --domain example.com --server 8.8.8.8
sudo venv/bin/python mod5/app_fingerprinting.py passive-dns --interface en0 --duration 60
```

## Output
Structured JSON logs under `logs/mod5/`.
