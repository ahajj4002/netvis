# Module 4: Timing and Rate Control

Implements rubric items 4a–4c. This module orchestrates identical scans with different timing profiles and logs inter-arrival distributions.

## 4a Fixed-Rate Profiles
Runs the same SYN scan at 5 rates:
- 1 probe / 5 min
- 1 / 15 sec
- 1 / 0.4 sec
- 1 / 10 ms
- unrestricted

To keep the 5-minute profile feasible, use `--max-tuples` to limit targets.

Run:
```bash
sudo venv/bin/python mod4/timing_rate_control.py fixed --host 192.168.56.10 --ports 22,80,443 --max-tuples 10
```

## 4b Randomized Jitter
Runs fixed vs uniform jitter vs exponential jitter and logs histograms.

Run:
```bash
sudo venv/bin/python mod4/timing_rate_control.py jitter --host 192.168.56.10 --ports 22,80,443 --base-delay 0.4 --max-tuples 30
```

## 4c Target Ordering Randomization
Compares sequential ordering vs shuffled ordering.

Run:
```bash
sudo venv/bin/python mod4/timing_rate_control.py order --host 192.168.56.10 --ports 22,80,443 --delay 0.4 --max-tuples 30
```

## Output
Structured JSON logs under `logs/mod4/`.
