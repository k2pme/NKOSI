# NKOSI — User Guide (A to Z)

NKOSI is a Linux antivirus/EDR with multiple components: a local protection
**agent**, a **central gRPC server**, a centralized **web console**
(multi-agent monitoring), a local **REST API + dashboard**, and a **CLI**.

This guide describes, from A to Z, how to use NKOSI once installed.

---

## 1. Preparation & installation

```bash
# 1. System prerequisites (protoc, libyara, iptables, build tools)
sudo ./scripts/install-deps.sh

# 2. Compilation
cargo build --workspace          # development
# cargo build --release          # for binary installation

# 3. (Optional) binary installation + systemd services
make install                     # binaries in /usr/local/bin + services
```

> Full details: `doc/INSTALLATION.md` and `doc/PREREQUIS.md`.

---

## 2. Running the ecosystem (development/demo)

The `./nkosi.sh` script orchestrates all components from `target/debug`:

```bash
./nkosi.sh start          # starts central + console + api + agent
./nkosi.sh status         # status of all services
./nkosi.sh list           # list of components
./nkosi.sh start central console   # start only specific ones
./nkosi.sh stop           # stop everything
./nkosi.sh restart        # restart everything
./nkosi.sh logs agent     # follow agent logs
```

**Components and ports:**

| Component | Binary          | Role                                   | Port |
|-----------|------------------|----------------------------------------|------|
| `agent`   | `nkosi-agent`    | Local protection agent (monitors + engines) | — |
| `central` | `nkosi-central`  | Central gRPC multi-agent server        | 50051 |
| `console` | `nkosi-console`  | Centralized web console                | 9090 |
| `api`     | `nkosi-api`      | REST API + local dashboard             | 8080 |

Useful environment variables: `NKOSI_CENTRAL_BIND`, `NKOSI_CENTRAL_ADDR`,
`NKOSI_CONSOLE_BIND`, `NKOSI_API_KEYS`, `NKOSI_RUN_DIR`, `NKOSI_LOG_DIR`.

---

## 3. Web interface

While the ecosystem is running:

- **Centralized dashboard (multi-agents)**: http://localhost:9090
  Overview, events (expandable, hash copy, agent id),
  **Servers/Agents** tab, history.
- **Local dashboard (API)**: http://localhost:8080

---

## 4. The `nkosi-cli` command

The CLI allows interactive use of NKOSI, **without a daemon**.
`./nkosi.sh cli <command>` is equivalent to `nkosi-cli <command>`.

### 4.1 Status & logs

```bash
nkosi-cli status               # system status
nkosi-cli logs                 # last 50 log lines
nkosi-cli logs 200             # 200 lines
```

### 4.2 Scans

```bash
nkosi-cli scan /home/user --recursive   # scan a file/directory
nkosi-cli scan /etc/hosts               # scan a file
nkosi-cli scan /tmp -r -q               # recursive + quiet
nkosi-cli scan /path --dry-run          # no action
nkosi-cli quick                         # critical system directories
nkosi-cli full                          # full system scan
nkosi-cli process <PID>                 # scan a process
nkosi-cli network <IP|CIDR>             # scan a network
```

### 4.3 Security modules

```bash
nkosi-cli rootkit              # rootkit scan
nkosi-cli kernel               # kernel modules
nkosi-cli integrity            # system integrity (current baseline)
nkosi-cli integrity --baseline # create a new baseline
nkosi-cli ssh                  # SSH brute-force (5 failures threshold)
nkosi-cli ssh --block --threshold 5 --block-threshold 10   # + iptables blocking
```

### 4.4 Firewall

```bash
nkosi-cli firewall status      # firewall status
nkosi-cli firewall init        # initializes NKOSI chains
nkosi-cli firewall block <IP>  # blocks an IP
nkosi-cli firewall unblock <IP>
nkosi-cli firewall whitelist <IP>
nkosi-cli firewall rate-limit ...
nkosi-cli firewall save        # saves rules
nkosi-cli firewall load        # loads rules from a file
nkosi-cli firewall flush       # clears NKOSI rules
```

### 4.5 Quarantine

```bash
nkosi-cli quarantine list      # items in quarantine
nkosi-cli quarantine restore <id>
nkosi-cli quarantine delete <id>
nkosi-cli quarantine purge     # empties all quarantine
```

### 4.6 Updates & backups

```bash
nkosi-cli update               # updates threat intelligence feeds
nkosi-cli update --force
nkosi-cli backup create        # configuration backup
nkosi-cli backup list
nkosi-cli backup restore
nkosi-cli backup prune         # old backup rotation
```

### 4.7 Multi-agent consolidated report

```bash
nkosi-cli report consolidated  # consolidated report of all agents
```

---

## 5. Full lifecycle example

```bash
# Prerequisites + build
sudo ./scripts/install-deps.sh
cargo build --workspace

# Start the ecosystem
./nkosi.sh start

# Check status
./nkosi.sh status
curl http://localhost:9090          # centralized console

# Security actions
nkosi-cli scan /home/user -r
nkosi-cli rootkit
nkosi-cli ssh --block               # blocks brute-force IPs
nkosi-cli firewall block 1.2.3.4    # manually blocks an IP
nkosi-cli quarantine list

# Update threat definitions
nkosi-cli update

# Stop
./nkosi.sh stop
```

---

## 6. System service startup (production)

```bash
make install
sudo systemctl enable --now nkosi-agent
sudo systemctl start nkosi-ti-update.timer   # threat feed updates
systemctl status nkosi-agent
journalctl -u nkosi-agent -f
```

---

## 7. Quick troubleshooting

| Symptom | Likely cause | Action |
|----------|----------------|--------|
| build fails on protoc | `protoc` missing | `sudo ./scripts/install-deps.sh` |
| build fails on yara | `libyara-dev` missing | `sudo ./scripts/install-deps.sh` |
| console 9090 not responding | central not started | `./nkosi.sh start central console` |
| agent not reporting alerts | central unreachable | check `NKOSI_CENTRAL_ADDR` |

See `doc/INSTALLATION.md` and `doc/PREREQUIS.md` for installation details.

---

## 8. API reference

- [`doc/openapi.yaml`](doc/openapi.yaml) — REST API specification (OpenAPI 3.0)
- [`doc/grpc-openapi.yaml`](doc/grpc-openapi.yaml) — Central gRPC API specification (OpenAPI 3.0)

The REST API is served on port `8080`. The central gRPC service is served on port `50051`.
Both specs include authentication, rate limiting, request/response schemas, and error codes.

---

## 9. Advanced features for production servers

- [`doc/advanced.md`](doc/advanced.md) — Advanced detection, response, hunting, hardening, and forensics features to make NKOSI more aggressive and powerful on a production server.
