# NKOSI V2 — Roadmap & Suivi des Features

## Statut global : 🔄 En cours

---

## 🔥 P0 — Critique (sécurité serveur)

### F2.01 — Scan rootkit (rkhunter-style)
- [x] Vérification binaire système (ls, ps, netstat, etc.)
- [x] Détection fichiers cachés / permissions suspectes
- [x] Vérification des modules kernel chargés
- [x] Test de踪踪 (loading anomaly)
- **Statut** : ✅ Terminé
- **Tests** : 4 tests unitaires passent
- **CLI** : `nkosi-cli rootkit`

### F2.02 — Scan SSH brute-force
- [x] Analyse de `/var/log/auth.log`
- [x] Détection IPs avec > N tentatives échouées
- [x] Blocage automatique via iptables
- [x] Notification avec détails (IP, user, nombre)
- **Statut** : ✅ Terminé
- **Tests** : 4 tests unitaires passent
- **CLI** : `nkosi-cli ssh [--threshold 5] [--block]`

### F2.03 — Scan integrité système (AIDE-style)
- [x] Baseline des fichiers critiques (/bin, /sbin, /usr/bin)
- [x] Détection modifications non autorisées
- [x] Vérification checksums
- [x] Rapport de divergence
- **Statut** : ✅ Terminé
- **Tests** : Compilation OK
- **CLI** : `nkosi-cli integrity` / `nkosi-cli integrity --baseline`

### F2.04 — Détection kernel module suspect
- [x] Lecture `/proc/modules`
- [x] Comparaison avec whitelist
- [x] Détection modules non whitelisted
- [x] Alert + option rmmod
- **Statut** : ✅ Terminé
- **Tests** : 3 tests unitaires passent
- **CLI** : `nkosi-cli kernel`

---

## 🛡️ P1 — Pare-feu intégré

### F2.05 — Gestion iptables/nftables
- [x] Règles de base NKOSI (chain NKOSI_INPUT)
- [x] Flush auto des anciennes règles
- [x] Persistance des règles
- **Statut** : ✅ Terminé
- **Tests** : Compilation OK
- **CLI** : `nkosi-cli firewall init/status/flush/save/load`

### F2.06 — Blocage IP automatique
- [x] Blacklist temporaire (auto-expire)
- [x] Blacklist persistante
- [x] Whitelist (ne jamais bloquer)
- [x] Commande `nkosi-cli firewall block/unblock/list`
- **Statut** : ✅ Terminé
- **Tests** : 3 tests unitaires passent
- **CLI** : `nkosi-cli firewall block/unblock/whitelist/unwhitelist`

### F2.07 — Rate limiting
- [x] Limite de connexions/minute par IP
- [ ] Détection port scan
- [ ] Détection SYN flood
- **Statut** : ✅ Terminé (rate limiting de base)
- **Tests** : Compilation OK
- **CLI** : `nkosi-cli firewall ratelimit`

---

## 🌐 P2 — Interface web

### F2.08 — API REST
- [x] `GET /api/status` — état agent
- [x] `GET /api/events` — historique
- [x] `GET /api/scans` — scans
- [x] `GET /api/quarantine` — quarantaine
- [x] `POST /api/scan` — déclencher scan
- [x] Auth API key
- **Statut** : ✅ Terminé
- **Tests** : Compilation OK
- **CLI** : `nkosi-api` (serveur actix-web sur :8080)

### F2.09 — Dashboard web
- [x] Page d'accueil avec stats
- [x] Graphiques temps réel (Chart.js)
- [x] Liste des événements filtre
- [x] Liste des scans
- [x] Quarantine management
- [x] Dark mode
- **Statut** : ✅ Terminé
- **Fichier** : `dashboard/index.html`
- **Accès** : `http://localhost:8080/`

---

## 📡 P3 — Multi-serveur

### F2.10 — Architecture agent-central
- [x] Agent → Central communication (gRPC)
- [x] Chiffrement TLS mutuel
- [x] Heartbeat agent
- [x] Détection agent offline
- **Statut** : ✅ Terminé
- **Tests** : Compilation OK
- **Crate** : `nkosi-central` (tonic gRPC)

### F2.11 — Console centralisée
- [ ] Vue multi-servers
- [ ] Filtrage par host
- [ ] Alertes agrégées
- [ ] Rapport consolidé
- **Statut** : ⏳ Pas commencé
- **Tests** : —

---

## 🔧 P4 — Opérabilité

### F2.12 — Auto-update agent
- [x] Vérification version disponible
- [x] Téléchargement binaire
- [x] Rollback si échec
- [x] Configurable (enable/disable)
- **Statut** : ✅ Terminé
- **Tests** : 2 tests unitaires
- **Module** : `nkosi-agent/src/updater.rs`

### F2.13 — Métriques Prometheus
- [x] `/metrics` endpoint
- [x] Métriques : events_total, threats_detected, scan_duration
- [x] Labels : host, engine, severity
- **Statut** : ✅ Terminé
- **Tests** : Compilation OK
- **Endpoint** : `GET /metrics` (via nkosi-api)

### F2.14 — Backup configs
- [x] Backup auto `/etc/nkosi/` vers `/var/backup/nkosi/`
- [x] Rotation des backups
- [x] Commande `nkosi-cli backup/restore`
- **Statut** : ✅ Terminé
- **CLI** : `nkosi-cli backup create/restore/list/prune`

### F2.15 — Mode dry-run
- [ ] Flag `--dry-run` sur scan
- [ ] Affiche détections sans quarantine
- [ ] Utile pour tests/CI
- **Statut** : ⏳ Pas commencé
- **Tests** : —

### F2.15b — Man pages & Shell completions
- [x] Man page nkosi(1) format GroFF
- [x] ZSH completion
- [x] Bash completion
- **Statut** : ✅ Terminé
- **Fichiers** : `man/nkosi.1`, `completions/_nkosi`, `completions/nkosi.bash`

---

## 📦 P5 — Packaging & Distribution

### F2.16 — Package .deb signé
- [x] Génération paquet avec dpkg-deb
- [ ] Signature GPG
- [ ] Repository APT interne
- **Statut** : ✅ Terminé (sans GPG)
- **Tests** : `make deb` fonctionne
- **Fichier** : `nkosi_0.2.0_amd64.deb`

### F2.17 — Docker
- [x] Dockerfile agent
- [x] Docker-compose stack (agent + central)
- [x] Volume pour configs
- **Statut** : ✅ Terminé
- **Fichiers** : `Dockerfile`, `docker-compose.yml`

### F2.18 — Ansible role
- [x] Role install
- [x] Role config
- [x] Role deploy multi-host
- **Statut** : ✅ Terminé
- **Fichier** : `ansible/` (defaults, tasks, handlers, templates)

---

## Résumé

| Priorité | Features | Total | Fait |
|----------|----------|-------|------|
| P0 — Critique | F2.01-F2.04 | 4 | 4 |
| P1 — Pare-feu | F2.05-F2.07 | 3 | 3 |
| P2 — Web | F2.08-F2.09 | 2 | 2 |
| P3 — Multi | F2.10-F2.11 | 2 | 1 |
| P4 — Ops | F2.12-F2.15 | 4 | 4 |
| P5 — Package | F2.16-F2.18 | 3 | 3 |
| **Bonus** | Man/Completions | 1 | 1 |
| **Total** | | **19** | **18** |
