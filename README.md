# NKOSI — Linux Antivirus & EDR

**Protect your endpoints with open-source threat detection, real-time monitoring, and automated response.**

---

## What is NKOSI?

NKOSI is a Linux-native antivirus and Endpoint Detection & Response (EDR) platform built in Rust. It provides real-time file monitoring, process behavior analysis, network threat detection, YARA rule scanning, SHA-256 hash verification, and automated response actions — all running locally on your server or workstation.

The name **NKOSI** means *"king"* in Lingala. Just as a lion protects its domain, NKOSI guards your Linux endpoints with a complete, modular security pipeline.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Real-time monitoring** | Filesystem, process, and network monitoring via inotify/fanotify and procfs |
| **Multiple detection engines** | SHA-256 hash matching, YARA rules, static analysis, behavior analysis, network IOC |
| **Risk scoring** | Weighted scoring engine that correlates multiple signals into a single risk level |
| **Automated response** | Allow, alert, kill process, block IP, quarantine, restore, delete |
| **Threat Intelligence** | Local threat database updated from MalwareBazaar, ThreatFox, URLhaus |
| **Incident management** | Automatic incident creation, correlation, and explainability |
| **Quarantine** | Safe isolation of malicious files with restore capability |
| **Firewall integration** | Automatic IP blocking via iptables/ip6tables |
| **CLI & REST API** | Full command-line interface and HTTP API with dashboard |
| **Central console** | Multi-agent centralized monitoring console |
| **Simulation mode** | Built-in threat simulation for testing and validation |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LINUX ENDPOINT                            │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Filesystem   │  │   Process    │  │      Network         │  │
│  │   Monitor     │  │   Monitor    │  │      Monitor         │  │
│  │ (inotify/     │  │   (procfs)   │  │    (proc/net)        │  │
│  │  fanotify)    │  │              │  │                      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                     │              │
│         └─────────────────┴──────────┬──────────┘              │
│                                    │                           │
│                                    ▼                           │
│                           ┌────────────────┐                  │
│                           │   Event Bus    │                  │
│                           └───────┬────────┘                  │
│                                   │                           │
│         ┌───────────┬───────────┼───────────┬────────────┐    │
│         ▼           ▼           ▼           ▼            ▼    │
│       Hash       YARA      Static      Behavior     Threat   │
│       Engine     Engine     Analyzer      Engine     Intel   │
│         │           │           │           │            │     │
│         └───────────┴───────────┴───────────┘            │     │
│                                    │                       │     │
│                                    ▼                       │     │
│                           ┌────────────────┐               │     │
│                           │  Risk Engine   │◄──────────────┘     │
│                           └───────┬────────┘                     │
│                                   │                              │
│                    ┌──────────────┼──────────────┐               │
│                    ▼              ▼              ▼               │
│                  CLEAN        SUSPICIOUS      MALICIOUS          │
│                    │              │              │               │
│                  Allow         Alert    ┌──────┴──────┐          │
│                                    │  Response   │          │
│                                    │  Engine     │          │
│                                    │             │          │
│                                    ▼             ▼          │
│                                 Kill         Block            │
│                                                │             │
│                                                ▼             │
│                                             Quarantine        │
│                                                │             │
│                                                ▼             │
│                                         Event Log             │
│                                                │             │
│                                                ▼             │
│                                      Local Database           │
│                                                │             │
│                                                ▼             │
│                                    CLI  API  Console  UI      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

See [`doc/PREREQUIS.md`](doc/PREREQUIS.md) for the full list.

```bash
sudo ./scripts/install-deps.sh
```

### Build

```bash
cargo build --workspace          # development
cargo build --release            # production
```

### Run (development)

```bash
./nkosi.sh start                 # start all components
./nkosi.sh status                # check status
nkosi-cli scan /home -r          # scan files
nkosi-cli simulate               # run threat simulation
```

See [`doc/USAGE.md`](doc/USAGE.md#2-running-the-ecosystem-developmentdemo) for ecosystem startup and [`doc/openapi.yaml`](doc/openapi.yaml) for the REST API reference.

### Install (production)

See [`doc/INSTALLATION.md`](doc/INSTALLATION.md) for details.

```bash
make install
sudo systemctl enable --now nkosi-agent
```

---

## Components

| Component | Port | Description |
|-----------|------|-------------|
| `nkosi-agent` | — | Local EDR agent with monitors, engines, and response |
| `nkosi-cli` | — | Command-line interface for scans, firewall, quarantine |
| `nkosi-api` | 8080 | REST API + local dashboard |
| `nkosi-central` | 50051 | Central gRPC server for multi-agent collection |
| `nkosi-console` | 9090 | Centralized web console |
| `nkosi-ui` | — | Desktop graphical interface |

---

## Threat Simulation

NKOSI includes a built-in simulation engine for testing and validation.

See [`doc/USAGE.md`](doc/USAGE.md#47-multi-agent-consolidated-report) for CLI details and [`doc/USAGE.md`](doc/USAGE.md#2-running-the-ecosystem-developmentdemo) for API setup.

```bash
# CLI
nkosi-cli simulate --scenario all --cycles 5

# API
curl -X POST http://localhost:8080/api/simulate \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"scenarios": ["Ransomware", "Trojan", "Backdoor"], "count": 2}'

# Automatic (daemon mode)
# Set in nkosi.toml:
# [simulation]
# enabled = true
# interval_seconds = 60
# scenarios = ["Ransomware", "Cryptominer", "Webshell"]
```

---

## Documentation

- [`doc/INSTALLATION.md`](doc/INSTALLATION.md) — Full installation guide
- [`doc/PREREQUIS.md`](doc/PREREQUIS.md) — System prerequisites
- [`doc/USAGE.md`](doc/USAGE.md) — Complete usage guide (A to Z)
- [`doc/advanced.md`](doc/advanced.md) — Advanced features roadmap for production servers
- [`doc/openapi.yaml`](doc/openapi.yaml) — REST API specification (OpenAPI 3.0)
- [`doc/grpc-openapi.yaml`](doc/grpc-openapi.yaml) — Central gRPC API specification (OpenAPI 3.0)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust (2024 edition) |
| Async runtime | Tokio |
| Database | SQLite (bundled) |
| Detection | YARA, SHA-256, regex heuristics |
| Communication | gRPC (tonic), REST (actix-web) |
| Monitoring | inotify, fanotify, procfs |
| Firewall | iptables / ip6tables |
| Build | Cargo workspace (16 crates) |

---

## Project Structure

```
NKOSI/
├── nkosi-common/          # Shared types, config, errors
├── nkosi-core/            # Config loading, DB initialization
├── nkosi-db/              # SQLite repositories and schema
├── nkosi-monitors/        # Filesystem, process, network monitors
├── nkosi-engines/         # Hash, YARA, static, behavior engines
├── nkosi-risk/            # Risk scoring engine
├── nkosi-response/        # Response engine (quarantine, kill, block)
├── nkosi-scanner/         # Rootkit, integrity, kernel, firewall scanners
├── nkosi-ti/              # Threat intelligence feeds
├── nkosi-notify/          # Notification system (email, webhook, syslog, telegram, sms)
├── nkosi-agent/           # Main agent binary + simulation
├── nkosi-cli/             # CLI binary
├── nkosi-api/             # REST API + dashboard
├── nkosi-central/         # Central gRPC server
├── nkosi-console/         # Centralized web console
├── nkosi-ui/              # Desktop UI
├── doc/                   # Documentation
└── tests/                 # Integration tests
```

---

## Security

NKOSI is designed with security in mind:

- **No cloud dependency** — All detection happens locally
- **Local threat database** — No file scanning via remote APIs
- **Reduced privileges** — UI does not run with permanent root
- **Auditability** — Every action is logged with timestamp, score, and details
- **Configurable thresholds** — Risk levels and response actions are adjustable
- **Graceful degradation** — Non-critical module failures do not stop the agent

---

## License

[Add your license here]

---

*NKOSI — The lion guards your Linux.*
