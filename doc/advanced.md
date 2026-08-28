# NKOSI — Advanced Features Roadmap

This document describes advanced functional features that would make NKOSI more aggressive and powerful on a server. They are organized by category and prioritized for implementation on a production server.

---

## 1. Advanced Detection

### Memory Scanning
- Scan process memory to detect injected code, reverse shells, encrypted RAM payloads
- Detect process hollowing / process doppelgänging
- Scan memory mappings for RWX (writable + executable) permissions

### Advanced Behavioral Engine
- Detect **fileless malware** (execution from memory, PowerShell/bash without file)
- Detect **living-off-the-land** (LOLBins): legitimate tools used maliciously (`curl`, `wget`, `nc`, `python`, `perl`)
- Detect **privilege escalation**: local exploit abuse, SUID binaries, suspicious cron jobs, malicious systemd timers
- Detect **persistence**: Linux registry keys (`~/.bashrc`, `/etc/profile`, systemd units, crontab, at jobs, rc.local)

### Anti-evasion / Anti-rootkit
- Detect syscall hooking / LD_PRELOAD abuse
- Detect kernel rootkits (LKM) by comparing `/proc/modules` vs `/sys/module`
- Detect filesystem hiding (invisible files in `/proc`, suspicious mount points)
- Scan suspicious Linux capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN` on non-system binaries)

### Network Behavioral
- Detect **DNS tunneling** (exfiltrating DNS queries, abnormal lengths, suspicious TXT records)
- Detect **beaconing** (periodic C2 connections, jitter analysis)
- Detect **exfiltration** (abnormal outbound volume, non-standard protocols, transfers to suspicious IPs/ports)
- Detect **lateral movement**: internal SSH brute-force, RDP, SMB from server to other machines

---

## 2. Automated and Proactive Response

### Kill + Forensics
- Auto-kill + automatic memory backup of the process (`/proc/PID/mem`) before kill for post-mortem analysis
- Kill + filesystem snapshot backup before quarantine
- Network kill: immediate cut of a suspicious process connections + C2 IP blocking

### Proactive Quarantine
- Auto-quarantine files created in `/tmp`, `/dev/shm`, `/run` without legitimate extension
- Quarantine newly created SUID/SGID binaries outside system paths
- Quarantine scripts (`.sh`, `.php`, `.py`, `.pl`) dropped in web directories (`/var/www`, `/usr/share/nginx`)

### Aggressive Auto-blocking
- Auto-block IP after N rejected connections (integrated fail2ban-like behavior)
- Auto-block known mining pool IPs (dynamically updated lists)
- Block Linux users whose processes have high risk scores (not just kill process, but lock account)
- Block suspicious outbound ports (non-standard) if a process attempts external connection

---

## 3. Threat Hunting

### Integrated Hunting Queries
- Pre-built queries to hunt suspicious patterns:
  - "All processes listening on non-standard ports"
  - "All connections to IPs not resolved by DNS"
  - "All files modified in the last 24h in `/etc`"
  - "All cron jobs added yesterday"
  - "All binaries with suspicious capabilities"
  - "All child processes of `httpd`/`nginx` doing outbound network"

### Behavioral Baseline
- Automatic learning of "normal" over 7 days (processes, connections, modified files)
- Anomaly detection against baseline (e.g., Apache launching `python` or `nc` for the first time)
- Adaptive scoring based on behavior rarity

### YARA Dynamic / Custom Rules
- Dynamic injection of new YARA rules without restart
- Rules specific to web servers: webshells, PHP backdoors, base64 obfuscation, eval/gzinflate, etc.
- Rules specific to cryptominers: pool strings, wallet addresses, CPU affinity manipulation

---

## 4. Automatic Hardening

### SSH / Auth
- Detect and auto-block SSH brute-force (partially present, to be extended)
- Detect SSH connections from unauthorized IPs (geographic/company whitelist)
- Detect SSH keys added to `authorized_keys` without authorization
- Detect suspicious local user creation (`useradd`, `adduser`)

### Apache / Nginx Hardening
- Detect modifications to Apache/Nginx config (`httpd.conf`, `nginx.conf`, sites-enabled)
- Detect deployment of malicious `.htaccess` files
- Detect suspicious Apache modules (`LoadModule` to non-standard paths)
- Auto-scan web directories (`/var/www`, `/srv`, `/usr/share/nginx`) after each modification

### Kernel / OS Hardening
- Detect loading of unsigned kernel modules
- Detect modification of `/etc/sudoers`, `/etc/passwd`, `/etc/shadow`
- Detect creation of `/dev/mem`, `/dev/kmem` devices
- Monitor `dmesg` for kernel anomalies (rootkit signs, hidden processes)

---

## 5. Visibility and Forensics

### Unified Timeline
- Single chronological view of all events: files, processes, network, auth, firewall
- Automatic correlation: "File created → Process launched → Network connection → Alert"

### Process Lineage / Tree
- Reconstruct process tree with full arguments
- Detect suspicious "process spawning chains" (e.g., `httpd` → `bash` → `python` → `curl`)

### Advanced File Integrity Monitoring (FIM)
- Real-time monitoring of `/etc`, `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`
- Alerting on system binary modification
- Baseline of hashes for all system binaries at startup

### Network Forensics
- Limited packet capture (not full tcpdump, but metadata: src/dst IP, port, proto, size, timestamp)
- Reconstruction of suspicious sessions
- Detect abnormal protocols (e.g., HTTP on port 22, SSH on port 53)

---

## 6. Intelligence and Correlation

### Internal + External TI
- Detect crypto-malware wallet addresses (BTC, ETH, XMR) in files
- Detect mining pool URLs in binaries/scripts
- Correlation with dynamic IP/domain blacklists (abuse.ch, emergingthreats, etc.)

### Incident Linking
- Automatic incident linking: same IP, same hash, same process, same time window
- Scoring of linked incidents (multiple detections on same target = increased score)

### Predictive / Proactive
- Alert before a threat becomes critical: "Apache process doing DNS to unknown domain, score 35/100, enhanced monitoring"

---

## Recommended Implementation Order for a Production Server

To make NKOSI truly aggressive on an infected server, implement in this order:

1. **Advanced Behavioral Engine** (LOLBins, fileless, persistence) — maximum detection impact
2. **Memory Scanning** — against fileless cryptominers
3. **Aggressive Auto-blocking** (IPs + users + ports) — stop exfiltration/mining immediately
4. **Hunting queries + baseline** — find what has already been installed
5. **Apache/web hardening** — specific to your Apache-based infection
6. **Advanced FIM** — detect future modifications
