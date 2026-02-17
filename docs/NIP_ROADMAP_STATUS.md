# NIP Roadmap Status (Checklist + Evidence Map)

Source roadmap: local `NIP_Roadmap.md.pdf` reference document.

This document tracks what is implemented vs missing, mapped to concrete code paths, APIs, and UI affordances.

## Missing-Techniques Coverage Update (2026-02-16)

This project now includes a large safe expansion of the technique registry and runner/UI integration beyond Modules 1–7.

Implemented (runnable from UI via Coursework jobs):
- `ipv6`: `nd-scan`, `ra-scan`, `passive-ndp`, `slaac-fp`
- `dhcp`: `passive-dhcp`, `fingerprint`, `rogue-detect`
- `discovery`: `mdns`, `mdns-passive`, `ssdp`, `nbns`, `llmnr-passive`, `wsd`
- `icmp`: `echo-sweep`, `timestamp`, `address-mask`, `icmp-os-fp`
- `tls`: `ja3`, `ja3s`, `traffic-classify`
- `dns`: `tunnel-detect`, `doh-detect`, `dga-detect`
- `snmp`: `walk`
- `ssh`: `host-key-fp`, `algo-audit`
- `smb`: `enum-shares`, `enum-sessions` (best effort), `os-discovery`
- `iot`: `mqtt-enum`, `coap-discover`
- `wifi`: `passive-scan`
- `vlan`: `discover` (passive CDP/LLDP/DTP)
- `analysis`: `compute-baseline`, `anomaly-score`, `identity-resolve`, `community-detect`, `risk-score`, `attack-chain`, `temporal-correlate`, `graph-diff`
- `threat`: `cve-lookup`, `ip-reputation`, `domain-reputation`, `feed-sync`

Explicitly declined (tracked in registry with rationale):
- All `evasion.*` adaptive stealth / impersonation techniques
- Disruptive or abuse-oriented items:
  - `dhcp.starvation_test`
  - `iot.telnet_default_creds`
  - `vlan.double_tag`
  - `vlan.dtp_negotiation`
  - `l2.cam_overflow`
  - `snmp.community_bruteforce`
  - `wifi.deauth_test`

## Status Legend

- `DONE`: implemented end-to-end and usable (via UI and/or API).
- `PARTIAL`: implemented in skeleton/limited form; notable gaps remain.
- `NOT STARTED`: not implemented yet.
- `DECLINED`: intentionally not implemented (safety/compliance reasons).

## Phase 0: Foundation Refactoring

### 0.1 - Technique Registry (`DONE`)

What exists:
- A unified registry where each technique is a self-describing object.
- 95 techniques registered (79 available, 16 declined).
- All roadmap fields implemented:
  - `id`, `name`, `scope`, `module`, `action`, `description`
  - `mode` (active/passive)
  - `stealth` (0.0–1.0 float)
  - `detection_profile` (IDS rule → detection probability mapping)
  - `estimated_time` (human-readable estimation)
  - `consumes[]`, `provides[]`, `tags[]`
  - `requires_root`, `requires_scapy`, `lab_only`, `status`, `rationale`

Evidence:
- Code: `nip/registry.py`
- API: `GET /api/nip/techniques`
- UI: Coursework + Workbench already map techniques to `{module, action, params}` and run them through the backend.
- UI: Technique cards now display `mode`, `stealth`, and `estimated_time` badges.

### 0.2 - Unified Result Schema (`DONE`)

What exists:
- Shared `TechniqueResult` dataclass with: `technique_id`, `timestamp`, `targets`, `findings[]`, `confidence`, `detection_risk`, `next_suggestions`, `raw_data`, `duration_seconds`.
- Standardised `Finding` dataclass with: `category`, `severity`, `confidence`, `entity`, `summary`, `detail`.
- `TechniqueResult.from_legacy_log()` adapter to wrap existing JSON logs into the unified envelope.
- Backend `nip` envelope in logs with technique metadata and inputs.

Evidence:
- Code: `nip/schema.py`
- Backend envelope + ingestion: `server.py` (`run_coursework_action`, `_nip_ingest_coursework_result`)
- Logs: `logs/<module>/`

### 0.3 - Event Bus (`DONE`)

What exists:
- In-process publish/subscribe bus with bounded event buffer.
- Bus events are persisted as observations and surfaced in the UI timeline.
- Auto-correlation subscriber: when `anomaly.detected` fires, automatically correlates nearby events and publishes `correlation.found`.

Evidence:
- Code: `nip/events.py` (`EventBus`, `NipEvent`)
- Backend integration: `server.py` (`nip_bus`, persistence subscriber, auto-correlator subscriber)
- APIs: `GET /api/nip/events`
- UI: Dashboard timeline uses `GET /api/intel/story` -> `timeline` (persisted observations)

## Phase 1: The Knowledge Graph (MEMORY)

### 1.1 - Graph Schema (`DONE`)

What exists:
- All roadmap node types implemented:
  - `Device` nodes from `assets`
  - `Service` nodes from `services`
  - `Subnet` nodes from `subnets` table (derived from assets)
  - `DNSRecord` nodes from `dns_records` table (derived from dns_queries)
  - `Alert` nodes from `alerts` table
  - `ThreatIndicator` nodes from `threat_indicators` table
- All roadmap edge types implemented:
  - `RUNS`: Device → Service
  - `CONNECTS_TO`: Device → Device from flows
  - `HOSTS`: Subnet → Device (computed from CIDR membership)
  - `RESOLVES`: Device → DNSRecord (from dns_queries)
  - `TRIGGERED`: Device → Alert
  - `GATEWAY_FOR`: Device → Subnet
  - `MATCHES`: via ThreatIndicator nodes (from threat feed)
- Per-node fields: `risk_score`, `behavioral_cluster` (community) stored in asset metadata.

Evidence:
- DB tables: `server.py` (`assets`, `services`, `flows`, `subnets`, `dns_records`, `threat_indicators`)
- API: `GET /api/nip/graph` (lightweight), `GET /api/nip/graph/full` (complete with all node/edge types)
- API: `POST /api/nip/graph/populate` (derive and persist Subnet/DNSRecord/ThreatIndicator nodes)

### 1.2 - Temporal Properties (`DONE`)

What exists:
- `first_seen` / `last_seen` fields on all node tables.
- Observation timeline with timestamps.
- Metrics/baselines tables with time-series behavior.
- Graph as-of snapshot: `GET /api/nip/graph?as_of=<ISO_TIMESTAMP>`
- Graph diff with additions AND removals: `GET /api/nip/graph/diff/full?t1=<ISO>&t2=<ISO>`
- Property-change tracking: devices updated between t1 and t2 reported as `changed.assets`.

Evidence:
- DB schema: `server.py` (all tables)
- API: `GET /api/nip/graph?as_of=<ISO_TIMESTAMP>`
- API: `GET /api/nip/graph/diff?t1=<ISO>&t2=<ISO>` (additions only)
- API: `GET /api/nip/graph/diff/full?t1=<ISO>&t2=<ISO>` (additions + removals + changes)

### 1.3 - Graph Population Pipeline (`DONE`)

What exists:
- Backend adapters that ingest technique outputs into assets/services/observations/bus events.
- Extended graph population endpoint that derives Subnet, DNSRecord, and ThreatIndicator nodes.
- Log ingestion pipeline feeds DHCP leases into device nodes.
- Risk scores and community IDs persisted as device metadata.

Evidence:
- Ingestion adapter: `server.py` (`_nip_ingest_coursework_result`)
- Population: `POST /api/nip/graph/populate`
- Risk persist: `POST /api/nip/analysis/risk-persist`
- Community persist: `POST /api/nip/analysis/community-persist`

## Phase 2: Continuous Ingestion (SENSES)

### 2.1 - Passive Packet Daemon (`PARTIAL`)

What exists:
- Packet capture start/stop, parsing into connections/flows/DNS, persistence to SQLite.
- A metrics/baselining daemon exists and is auto-started/stopped with capture.

Gaps vs roadmap:
- No standalone daemon publishing `flow.observed` per packet to the bus (would require refactoring analyzer).

Evidence:
- Capture: `server.py` (`/api/capture/start`, `/api/capture/stop`)
- Daemon: `GET /api/nip/daemon/status`, `POST /api/nip/daemon/start`, `POST /api/nip/daemon/stop`

### 2.2 - DNS Stream Processor (`PARTIAL`)

What exists:
- DNS query collection in live analyzer.
- Coursework DNS analysis actions for tunneling/DoH/DGA.
- DNSRecord nodes populated in graph.

Gaps vs roadmap:
- DNS detections are job-based, not a continuous stateful stream processor.

Evidence:
- Live DNS API: `server.py` (`GET /api/dns`)
- DNS modules: `mod5/app_fingerprinting.py`, `dns/dns_advanced.py`

### 2.3 - NetFlow Aggregator (`PARTIAL`)

What exists:
- NetFlow v5 collection/analytics in Module 6.
- NetFlow v5 alerting/detection in Module 7.

Gaps vs roadmap:
- No continuous aggregator writing 1-minute rollups into NIP metrics.

### 2.4 - Threat Intelligence Feed Integrator (`DONE`)

What exists:
- Local-file indicator checker with flow/DNS cross-reference.
- Coursework threat actions: `cve-lookup`, `ip-reputation`, `domain-reputation`, `feed-sync`.
- ThreatIndicator nodes in the graph (populated via `/api/nip/graph/populate`).
- Threat match alerts and bus events.

Evidence:
- Template: `samples/threat_indicators.json`
- API: `GET /api/nip/threat/check`
- Graph: `threat_indicators` table + `ThreatIndicator` nodes in `/api/nip/graph/full`
- Threat helpers: `threat/threat_lookup.py`

### 2.5 - Log Ingestion Pipeline (`DONE`)

What exists:
- Parsers for syslog, DHCP lease files, auth/RADIUS logs, and firewall logs.
- Ingestion API that parses, persists to `log_events` table, and publishes bus events.
- DHCP leases auto-enrich device nodes (MAC/hostname).
- Firewall blocks and auth failures published as bus events.

Evidence:
- Code: `nip/log_ingest.py`
- API: `POST /api/nip/logs/ingest` (body: `{"path": "/var/log/syslog", "log_type": "auto"}`)
- DB: `log_events` table
- Bus events: `device.dhcp_lease`, `firewall.block`, `auth.failure`

## Phase 3: The Temporal Engine (TIME)

### 3.1 - Behavioral Baselining (`DONE`)

What exists:
- Per-device per-window metric extraction from flows and DNS.
- EWMA baselines per device stored to `nip_baselines`.
- Exponentially-decayed baseline computation with active-hour profiles.
- Daemon auto-started with capture.

Evidence:
- Code: `server.py` (`NipMetricsDaemon`), `analysis/analysis_engine.py` (`compute_baseline_from_metrics`)
- APIs: `/api/nip/metrics`, `/api/nip/baselines`
- Coursework: `analysis:compute-baseline`

### 3.2 - Change Detection Engine (`DONE`)

What exists:
- Multi-factor anomaly scoring: volume spike, unique destination ports/IPs, DNS spike, off-hours activity.
- Compound scoring with configurable weights.
- Alerts emitted into NetVis alerts + NIP bus (`anomaly.detected`).
- Alert cooldown to avoid spam.

Evidence:
- Code: `server.py` (`NipMetricsDaemon._detect_anomaly`), `analysis/analysis_engine.py` (`score_anomaly`)

### 3.3 - Temporal Correlation Engine (`DONE`)

What exists:
- Manual correlator endpoint: `GET /api/nip/correlate?ts=<ISO>&entity=<ip>&window_seconds=300`
- Coursework action: `analysis:temporal-correlate`
- **Auto-correlation subscriber**: when `anomaly.detected` fires, automatically correlates nearby events and publishes `correlation.found` on the bus.

Evidence:
- API: `GET /api/nip/correlate`
- Auto-correlator: `server.py` (`_nip_auto_correlate` bus subscriber)

### 3.4 - Historical Replay (`DONE`)

What exists:
- Graph as-of snapshot: `GET /api/nip/graph?as_of=<ISO_TIMESTAMP>`
- Simple diff (additions): `GET /api/nip/graph/diff?t1=<ISO>&t2=<ISO>`
- Full diff with additions + removals + property changes: `GET /api/nip/graph/diff/full?t1=<ISO>&t2=<ISO>`
- Coursework action: `analysis:graph-diff`

Evidence:
- APIs: `/api/nip/graph`, `/api/nip/graph/diff`, `/api/nip/graph/diff/full`

## Phase 4: The Brain (ORCHESTRATOR)

### 4.1 - Situation Assessor (`DONE`)

What exists:
- `SituationAssessor` class that evaluates all devices for: has_mac, has_os, has_services, has_baseline, risk_assessed.
- Identifies knowledge gaps per device and overall.
- Tracks stale devices and unresolved alerts.
- Computes overall coverage percentage.

Evidence:
- Code: `nip/brain.py` (`SituationAssessor`, `NetworkSituation`, `DeviceKnowledge`)
- API: `GET /api/nip/brain/assess`

### 4.2 - Technique Selector (`DONE`)

What exists:
- `TechniqueSelector` that picks techniques based on objective (discover/enumerate/investigate/refresh/risk_assess) and stealth level.
- Considers device knowledge gaps to choose what to run.
- Respects stealth constraints (passive techniques at high stealth).

Evidence:
- Code: `nip/brain.py` (`TechniqueSelector`, `PlannedTechnique`)
- Integrated in: `POST /api/nip/brain/plan`

### 4.3 - Technique Chaining Engine (`PARTIAL`)

What exists:
- A deterministic "multi-chain" pipeline (Workbench) that runs a staged chain.
- Brain plan output includes ordered technique lists per objective.
- Registry metadata supports dynamic chaining.

Gaps vs roadmap:
- No automatic execution of Brain plans (plans are advisory, not auto-run).
- No dynamic re-planning during chain execution.

Evidence:
- UI: Workbench "Run Multi-Chain"
- Backend: `server.py` (`run_multichain_pipeline`)
- Brain plan: `POST /api/nip/brain/plan`

### 4.4 - Adaptive Evasion Controller (`DECLINED`)

Reason: Traffic morphing / protocol impersonation / evasion feedback loops are not implemented to avoid enabling covert scanning.

### 4.5 - Strategy Planner (High-Level Reasoning) (`DONE`)

What exists:
- `StrategyPlanner` class that sets high-level objectives based on network state.
- Objectives: discover (low coverage), refresh (stale data), investigate (unresolved alerts), enumerate (shallow knowledge), risk_assess (unscored devices).
- Priority-sorted objectives with stealth constraints.
- Plans persisted to `brain_plans` table.

Evidence:
- Code: `nip/brain.py` (`StrategyPlanner`, `Objective`)
- API: `GET /api/nip/brain/assess`, `POST /api/nip/brain/plan`
- UI: Brain tab in NIP view with stealth slider and plan visualization.

## Phase 5: The Analysis Engine (EYES)

### 5.1 - Identity Resolution (`PARTIAL`)

What exists:
- Coursework action `analysis:identity-resolve`.
- Behavioral fingerprint matching using top destinations/ports/domains.

Gaps vs roadmap:
- No automatic continuous identity system wired into graph (`IDENTIFIED_AS` edges).

Evidence:
- Code: `analysis/analysis_engine.py` (`compute_device_features`, `identity_resolve`)

### 5.2 - Community Detection (`DONE`)

What exists:
- Coursework action `analysis:community-detect`.
- Graph clustering via label propagation.
- **Community IDs persisted into device metadata** via `/api/nip/analysis/community-persist`.

Evidence:
- Code: `analysis/analysis_engine.py` (`community_detect_label_propagation`)
- API: `POST /api/nip/analysis/community-persist`

### 5.3 - Attack Chain Reconstruction (`PARTIAL`)

What exists:
- Coursework action `analysis:attack-chain`.
- Heuristic stage reconstruction from observations/alerts.

Gaps vs roadmap:
- No ATT&CK-mapped probabilistic chain engine.

Evidence:
- Code: `analysis/analysis_engine.py` (`reconstruct_attack_chain`)

### 5.4 - Risk Scoring Engine (`DONE`)

What exists:
- Coursework action `analysis:risk-score`.
- Multi-factor scoring: vulnerability, exposure, behavior anomaly, network position, threat match.
- **Risk scores persisted as first-class device metadata** via `/api/nip/analysis/risk-persist`.

Evidence:
- Code: `analysis/analysis_engine.py` (`risk_score_devices`)
- API: `POST /api/nip/analysis/risk-persist`
- Graph: Device nodes include `risk_score` in `/api/nip/graph/full`

### 5.5 - Encrypted Traffic Analysis (`PARTIAL`)

What exists:
- JA3/JA3S passive capture + encrypted traffic classification.

Gaps vs roadmap:
- No trained ML model pipeline with accuracy tracking.

Evidence:
- Code: `tls/tls_fingerprints.py`, `toolkit/tls_ja3.py`

## Phase 6: The Interface (FACE)

### 6.1 - Interactive Graph Explorer (`DONE`)

What exists:
- NetVis interactive graph view for devices/flows.
- Full graph API with all node/edge types: `GET /api/nip/graph/full`
- Graph as-of filtering: `GET /api/nip/graph?as_of=<ISO>`
- Graph diff API: `GET /api/nip/graph/diff/full?t1=<ISO>&t2=<ISO>`

Evidence:
- UI: Graph view in `App.jsx`
- APIs: `/api/nip/graph`, `/api/nip/graph/full`, `/api/nip/graph/diff/full`

### 6.2 - Timeline View (`DONE`)

What exists:
- Dashboard timeline panel with **category filtering** and **entity/text search**.
- Click-to-filter: click a category badge or entity to filter.
- Clear filters button.
- Shows filtered count vs total count.

Evidence:
- UI: `App.jsx` (`TimelinePanel` with filterCategory + filterEntity state)
- Data: `GET /api/intel/story` -> `timeline`

### 6.3 - Natural Language Query (`DONE`)

What exists:
- Keyword-based query translator that handles common question patterns:
  - "Which devices sent the most data?" → top talkers
  - "Show me everything 10.x.x.x did" → all activity for IP
  - "Are any devices talking to malicious IPs?" → threat matches
  - "What changed since yesterday?" → recent additions
  - "Which devices are highest risk?" → risk-scored devices
  - "Top DNS domains" → DNS query ranking
  - General search across observations
- Query panel in NIP view with example question buttons.

Evidence:
- API: `POST /api/nip/query` (body: `{"query": "..."}`)
- UI: Query tab in NIP view (`NLQueryPanel` component)

### 6.4 - Automated Intelligence Reports (`DONE`)

What exists:
- Report generation API that fuses: network overview, risk summary, traffic communities, knowledge gaps, and actionable recommendations.
- Reports saved as JSON + Markdown in `report/` directory.
- Recommendations auto-generated from Brain situation assessment.

Evidence:
- API: `POST /api/nip/report/generate`
- Artifacts: `report/nip_report_*.{json,md}`
- Also: Workbench story artifacts, detection matrix

## Phase 7: Validation & Testing

### 7.1 - Lab Environment (`DONE`)

What exists:
- Demo mode with synthetic data (`--demo` flag).
- Docker Compose lab with 3 subnets, 9 hosts, and a Suricata firewall/IDS.
  - Subnet A: SSH, Nginx, Python HTTP server
  - Subnet B: Apache, Redis, generic host
  - Subnet C: MQTT broker, Telnet simulator, netcat service

Evidence:
- Demo: `server.py` (`--demo`, `generate_demo_data`)
- Lab: `docker-compose.lab.yml`

### 7.2 - Evasion Validation Matrix (`DECLINED`)

Reason: Depends on the evasion controller and covert behaviors, which are not implemented.

### 7.3 - Intelligence Quality Metrics (`DONE`)

What exists:
- Discovery completeness metric (with optional ground truth).
- Identity resolution accuracy (TP/FP/FN/precision/recall when ground truth provided).
- Anomaly detection precision/recall (with confirmed true/false labels).
- Risk score distribution analysis.
- Time-to-detection metric.
- Brain efficiency metric.
- Quality snapshots persisted to `quality_snapshots` table.

Evidence:
- Code: `nip/quality.py`
- API: `GET /api/nip/quality` (optional: `?ground_truth=ip1,ip2,...`)
- UI: Quality tab in NIP view (`QualityPanel` component)

## Summary

| Phase | Item | Status |
|-------|------|--------|
| 0.1 | Technique Registry | DONE |
| 0.2 | Unified Result Schema | DONE |
| 0.3 | Event Bus | DONE |
| 1.1 | Graph Schema | DONE |
| 1.2 | Temporal Properties | DONE |
| 1.3 | Graph Population Pipeline | DONE |
| 2.1 | Passive Packet Daemon | PARTIAL |
| 2.2 | DNS Stream Processor | PARTIAL |
| 2.3 | NetFlow Aggregator | PARTIAL |
| 2.4 | Threat Feed Integrator | DONE |
| 2.5 | Log Ingestion Pipeline | DONE |
| 3.1 | Behavioral Baselining | DONE |
| 3.2 | Change Detection Engine | DONE |
| 3.3 | Temporal Correlation | DONE |
| 3.4 | Historical Replay | DONE |
| 4.1 | Situation Assessor | DONE |
| 4.2 | Technique Selector | DONE |
| 4.3 | Technique Chaining | PARTIAL |
| 4.4 | Evasion Controller | DECLINED |
| 4.5 | Strategy Planner | DONE |
| 5.1 | Identity Resolution | PARTIAL |
| 5.2 | Community Detection | DONE |
| 5.3 | Attack Chain Recon | PARTIAL |
| 5.4 | Risk Scoring | DONE |
| 5.5 | Encrypted Traffic | PARTIAL |
| 6.1 | Graph Explorer | DONE |
| 6.2 | Timeline View | DONE |
| 6.3 | NL Query | DONE |
| 6.4 | Auto Reports | DONE |
| 7.1 | Lab Environment | DONE |
| 7.2 | Evasion Matrix | DECLINED |
| 7.3 | Quality Metrics | DONE |

**Items still PARTIAL (minor gaps):** 2.1 (packet daemon not event-driven per-packet), 2.2 (DNS not continuous stream), 2.3 (NetFlow not continuous aggregator), 4.3 (no auto-execution of Brain plans), 5.1 (no persistent IDENTIFIED_AS edges), 5.3 (no ATT&CK mapping), 5.5 (no ML model pipeline).

**Items DECLINED:** 4.4 (Evasion Controller), 7.2 (Evasion Matrix).
