# NKOSI — Guide d'utilisation (de A à Z)

NKOSI est un antivirus/EDR pour Linux, multi-composants : un **agent** de
protection locale, un **serveur central** gRPC, une **console web** centralisée
(monitoring multi-agents), une **API REST + dashboard** local, et un **CLI**.

Ce guide décrit, de A à Z, comment utiliser NKOSI une fois installé.

---

## 1. Préparation & installation

```bash
# 1. Prérequis système (protoc, libyara, iptables, outils de build)
sudo ./scripts/install-deps.sh

# 2. Compilation
cargo build --workspace          # développement
# cargo build --release          # pour l'installation binaire

# 3. (Optionnel) installation binaire + services systemd
make install                     # binaires dans /usr/local/bin + services
```

> Détail complet : `doc/INSTALLATION.md` et `doc/PREREQUIS.md`.

---

## 2. Lancer l'écosystème (développement/démo)

Le script `./nkosi.sh` orchestre l'ensemble des composants depuis `target/debug` :

```bash
./nkosi.sh start          # démarre central + console + api + agent
./nkosi.sh status         # état de tous les services
./nkosi.sh list           # liste des composants
./nkosi.sh start central console   # démarre seulement certains
./nkosi.sh stop           # arrête tout
./nkosi.sh restart        # redémarre tout
./nkosi.sh logs agent     # suit les logs de l'agent
```

**Composants et ports :**

| Composant | Binaire          | Rôle                                   | Port |
|-----------|------------------|----------------------------------------|------|
| `agent`   | `nkosi-agent`    | Agent de protection locale (moniteurs + moteurs) | — |
| `central` | `nkosi-central`  | Serveur central gRPC multi-agents       | 50051 |
| `console` | `nkosi-console`  | Console web centralisée                 | 9090 |
| `api`     | `nkosi-api`      | API REST + dashboard local              | 8080 |

Environnement utiles (variables) : `NKOSI_CENTRAL_BIND`, `NKOSI_CENTRAL_ADDR`,
`NKOSI_CONSOLE_BIND`, `NKOSI_API_KEYS`, `NKOSI_RUN_DIR`, `NKOSI_LOG_DIR`.

---

## 3. L'interface web

Pendant que l'écosystème tourne :

- **Dashboard centralisé (multi-agents)** : http://localhost:9090
  Vue d'ensemble, événements (dépliables, copie du hash, agent id),
  onglet **Serveurs/Agents**, historique.
- **Dashboard local (API)** : http://localhost:8080

---

## 4. La commande `nkosi-cli`

Le CLI permet d'utiliser NKOSI de façon interactive, **sans démon**.
`./nkosi.sh cli <commande>` équivaut à `nkosi-cli <commande>`.

### 4.1 État & logs

```bash
nkosi-cli status               # état du système
nkosi-cli logs                 # 50 dernières lignes de log
nkosi-cli logs 200             # 200 lignes
```

### 4.2 Scans

```bash
nkosi-cli scan /home/user --recursive   # scan d'un fichier/répertoire
nkosi-cli scan /etc/hosts               # scan d'un fichier
nkosi-cli scan /tmp -r -q               # récursif + silencieux
nkosi-cli scan /path --dry-run          # sans agir
nkosi-cli quick                         # répertoires système critiques
nkosi-cli full                          # tout le système
nkosi-cli process <PID>                 # scan d'un processus
nkosi-cli network <IP|CIDR>             # scan d'un réseau
```

### 4.3 Security modules

```bash
nkosi-cli rootkit              # scan des rootkits
nkosi-cli kernel               # modules kernel
nkosi-cli integrity            # intégrité système (baseline courant)
nkosi-cli integrity --baseline # créer une nouvelle baseline
nkosi-cli ssh                  # brute-force SSH (seuil 5 échecs)
nkosi-cli ssh --block --threshold 5 --block-threshold 10   # + blocage iptables
```

### 4.4 Firewall

```bash
nkosi-cli firewall status      # état du pare-feu
nkosi-cli firewall init        # initialise les chaînes NKOSI
nkosi-cli firewall block <IP>  # bloque une IP
nkosi-cli firewall unblock <IP>
nkosi-cli firewall whitelist <IP>
nkosi-cli firewall rate-limit ... 
nkosi-cli firewall save        # sauvegarde les règles
nkosi-cli firewall load        # charge les règles depuis un fichier
nkosi-cli firewall flush       # vide les règles NKOSI
```

### 4.5 Quarantaine

```bash
nkosi-cli quarantine list      # éléments en quarantaine
nkosi-cli quarantine restore <id>
nkosi-cli quarantine delete <id>
nkosi-cli quarantine purge     # vide toute la quarantaine
```

### 4.6 Mises à jour & backups

```bash
nkosi-cli update               # met à jour les sources de menaces
nkosi-cli update --force
nkosi-cli backup create        # backup de configuration
nkosi-cli backup list
nkosi-cli backup restore
nkosi-cli backup prune         # rotation des anciens backups
```

### 4.7 Rapport centralisé multi-agents

```bash
nkosi-cli report consolidated  # rapport consolidé de tous les agents
```

---

## 5. Cycle de vie complet (exemple)

```bash
# Prérequis + build
sudo ./scripts/install-deps.sh
cargo build --workspace

# Lancer l'écosystème
./nkosi.sh start

# Vérifier
./nkosi.sh status
curl http://localhost:9090          # console centralisée

# Actions de sécurité
nkosi-cli scan /home/user -r
nkosi-cli rootkit
nkosi-cli ssh --block               # bloque les IP brute-force
nkosi-cli firewall block 1.2.3.4    # bloque manuellement une IP
nkosi-cli quarantine list

# Mise à jour des définitions
nkosi-cli update

# Arrêt
./nkosi.sh stop
```

---

## 6. Démarrage comme service système (production)

```bash
make install
sudo systemctl enable --now nkosi-agent
sudo systemctl start nkosi-ti-update.timer   # mise à jour des menaces
systemctl status nkosi-agent
journalctl -u nkosi-agent -f
```

---

## 7. Dépannage rapide

| Symptôme | Cause probable | Action |
|----------|----------------|--------|
| build échoue sur protoc | `protoc` absent | `sudo ./scripts/install-deps.sh` |
| build échoue sur yara | `libyara-dev` absent | `sudo ./scripts/install-deps.sh` |
| console 9090 ne répond pas | central non démarré | `./nkosi.sh start central console` |
| agent ne remonte pas les aléas | central inaccessible | vérifier `NKOSI_CENTRAL_ADDR` |

Voir `doc/INSTALLATION.md` et `doc/PREREQUIS.md` pour les détails d'installation.
