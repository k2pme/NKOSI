# Plan d'exécution — NKOSI Antivirus Linux V1

## Vue d'ensemble

| Élément | Valeur |
|---------|--------|
| **Durée estimée** | 20 semaines |
| **Stack principal** | Rust + SQLite + fanotify + YARA |
| **Cible** | Debian/Ubuntu x86-64 |
| **Approche** | Itérative, incréments fonctionnels |

---

## Phase 1 — Fondations (Semaines 1-3)

### Objectif
Mettre en place l'architecture de base, la configuration et la persistance.

### Livrables

| # | Tâche | Priorité | Durée |
|---|-------|----------|-------|
| 1.1 | Créer le workspace Cargo multi-crates | Haute | 1j |
| 1.2 | Définir les types partagés (Event, ThreatIndicator, Detection, QuarantineItem, Scan) | Haute | 2j |
| 1.3 | Schéma SQLite + couche d'accès (CRUD) | Haute | 3j |
| 1.4 | Système de configuration TOML (seuils, chemins, exclusions) | Haute | 2j |
| 1.5 | Logging structuré `tracing` + rotation logs | Haute | 1j |
| 1.6 | Script d'installation systemd (service daemon) | Haute | 1j |
| 1.7 | Tests unitaires sur DB et config | Haute | 2j |

### Structure finale Phase 1

```
nkosi/
├── Cargo.toml
├── nkosi-common/         # types, config, erreurs
├── nkosi-db/             # SQLite, migrations, repositories
├── nkosi-agent/          # daemon entry point
└── config/
    └── nkosi.toml        # configuration par défaut
```

### Critère de validation
- Le daemon démarre, charge la config, initialise la DB, puis attend des événements.

---

## Phase 2 — Moniteurs système (Semaines 4-6)

### Objectif
Capturer les événements filesystem, processus et réseau en temps réel.

### Livrables

| # | Tâche | Priorité | Durée |
|---|-------|----------|-------|
| 2.1 | Filesystem Monitor — fanotify bindings FFI | Haute | 4j |
| 2.2 | Filesystem Monitor — collecte métadonnées (path, taille, propriétaire, perms) | Haute | 2j |
| 2.3 | Filesystem Monitor — bus d'événements internes | Haute | 1j |
| 2.4 | Process Monitor — lecture /proc + netlink connector fork/exit | Haute | 4j |
| 2.5 | Process Monitor — mapping PID → executable, args, PPID, user | Haute | 2j |
| 2.6 | Network Monitor — netlink conntrack ou /proc/net/tcp polling | Haute | 4j |
| 2.7 | Network Monitor — association PID ↔ connexion (IP, port, protocole) | Haute | 2j |
| 2.8 | Intégration des 3 moniteurs dans le daemon | Haute | 2j |
| 2.9 | Tests d'intégration moniteurs → event bus | Haute | 2j |

### Architecture Phase 2

```
┌─────────────────────────────────────┐
│           Security Agent            │
│         (tokio async runtime)       │
├──────────┬──────────┬───────────────┤
│ Filesys  │ Process  │   Network     │
│ Monitor  │ Monitor  │   Monitor     │
│ fanotify │ /proc    │   netlink     │
└────┬─────┴────┬─────┴──────┬────────┘
     │          │             │
     └──────────┴─────────────┘
                │
          Event Bus (tokio::mpsc)
                │
         ┌──────┴──────┐
         │  Event DB   │
         └─────────────┘
```

### Critère de validation
- Un fichier créé/modify dans une zone surveillée génère un event en DB.
- Un processus forké est capturé avec son PID, PPID, executable.
- Une connexion sortante est associée au bon PID.

---

## Phase 3 — Moteurs de détection (Semaines 7-10)

### Objectif
Analyser chaque événement pour extraire des signaux de détection.

### Livrables

| # | Tâche | Priorité | Durée |
|---|-------|----------|-------|
| 3.1 | Hash Engine — calcul SHA-256 streaming (pas de charge mémoire) | Haute | 2j |
| 3.2 | Hash Engine — comparaison vs Threat DB locale | Haute | 1j |
| 3.3 | YARA Engine — binding crate `yara` / compilation rules | Haute | 3j |
| 3.4 | YARA Engine — scan fichier, extraction metadata règle (family, severity) | Haute | 2j |
| 3.5 | Static Analyzer — identification type (ELF, script, archive) via `file` magic | Haute | 1j |
| 3.6 | Static Analyzer — ELF : sections, imports, SUID, strings, URLs/IPs | Haute | 3j |
| 3.7 | Static Analyzer — Scripts : commandes shell, obfuscation basique | Haute | 2j |
| 3.8 | Behavior Engine — fenêtre temporelle d'événements par PID | Haute | 3j |
| 3.9 | Behavior Engine — règles de corrélation (accès SSH, chiffrement, exfil) | Haute | 3j |
| 3.10 | Tests avec fichiers EICAR + règles YARA test | Haute | 2j |

### Architecture Phase 3

```
Event Bus
    │
    ├──► Hash Engine ──────┐
    │                      │
    ├──► YARA Engine ──────┤
    │                      │
    ├──► Static Analyzer ──┼──► Detection Objects
    │                      │        │
    └──► Behavior Engine ──┘        │
                                   ▼
                            Risk Engine (Phase 4)
```

### Critère de validation
- Fichier EICAR → Hash connu → détection malware.
- Règle YARA test → match détecté avec family/severity.
- Binaire ELF avec SUID → signal static analyzer.
- Chaîne comportementale suspecte → score élevé behavior engine.

---

## Phase 4 — Core décisionnel (Semaines 11-12)

### Objectif
Centraliser les décisions et exécuter les réponses.

### Livrables

| # | Tâche | Priorité | Durée |
|---|-------|----------|-------|
| 4.1 | Risk Engine — pondération configurable par source | Haute | 3j |
| 4.2 | Risk Engine — normalisation score 0-100 + seuils LOW/SUSPECT/MALICIOUS | Haute | 2j |
| 4.3 | Response Engine — autoriser, alerter | Haute | 1j |
| 4.4 | Response Engine — kill processus (SIGKILL via kill(2)) | Haute | 1j |
| 4.5 | Response Engine — quarantaine (déplacement + chmod 000 + rename) | Haute | 2j |
| 4.6 | Response Engine — restauration depuis quarantaine | Haute | 1j |
| 4.7 | Response Engine — suppression explicite depuis quarantaine | Haute | 1j |
| 4.8 | Response Engine — blocage connexion (netlink) quand supporté | Moyenne | 2j |
| 4.9 | Intégration Event → Detection → Risk → Response | Haute | 2j |
| 4.10 | Tests end-to-end avec scénarios complets | Haute | 2j |

### Architecture Phase 4

```
Detections (Hash/YARA/Static/Behavior)
            │
            ▼
      ┌─────────────┐
      │ Risk Engine  │
      │ (0-100)      │
      └──────┬──────┘
             │
    ┌────────┼────────────┐
    ▼        ▼            ▼
  0-29     30-69        70-100
   LOW    SUSPECT      MALICIOUS
    │        │            │
  Allow    Alert    Quarantine + Kill
```

### Critère de validation
- Score calculé correctement pour chaque combinaison de signaux.
- Processus tué uniquement quand score ≥ 70.
- Fichier en quarantaine inaccessible (permissions 000).
- Restauration fonctionne avec avertissement loggé.

---

## Phase 5 — Threat Intelligence (Semaines 13-14)

### Objectif
Alimenter la base locale depuis des sources publiques.

### Livrables

| # | Tâche | Priorité | Durée |
|---|-------|----------|-------|
| 5.1 | Client MalwareBazaar (hashes SHA-256, family, tags) | Haute | 2j |
| 5.2 | Client ThreatFox (IOC IP, domain, URL) | Haute | 2j |
| 5.3 | Client URLhaus (URLs malveillantes) | Haute | 1j |
| 5.4 | Normalisation + upsert SQLite (déduplication) | Haute | 2j |
| 5.5 | Update Service — vérification version, download, intégrité | Haute | 2j |
| 5.6 | Update Service — scheduled task (systemd timer ou cron) | Haute | 1j |
| 5.7 | Fallback — conserver dernière base valide si update échoue | Haute | 1j |
| 5.8 | Tests — simulation update, corruption, fallback | Haute | 1j |

### Flux Phase 5

```
Internet
    │
    ├── MalwareBazaar ──┐
    ├── ThreatFox ──────┼──► Update Service
    └── URLhaus ────────┘         │
                                  ▼
                            Normalize + Verify
                                  │
                                  ▼
                            Threat DB Locale
                                  │
                                  ▼
                            Detection Engines
```

### Critère de validation
- Update télécharge et insère les IOC en DB.
- DB locale contient hashes + IP + domaines.
- Pas de consultation Internet par fichier analysé.
- Update échouée → dernière base conservée.

---

## Phase 6 — Interface (Semaines 15-17)

### Objectif
CLI complète + interface desktop/TUI pour l'utilisateur.

### Livrables

| # | Tâche | Priorité | Durée |
|---|-------|----------|-------|
| 6.1 | CLI scan — fichier, dossier, rapide, complet | Haute | 3j |
| 6.2 | CLI quarantine — list, restore, delete | Haute | 2j |
| 6.3 | CLI status — état agent, modules, DB, stats | Haute | 1j |
| 6.4 | CLI logs — affichage incidents récents | Haute | 1j |
| 6.5 | IPC agent↔CLI (Unix socket) | Haute | 2j |
| 6.6 | Desktop UI — dashboard état protection (GTK4 ou TUI) | Haute | 4j |
| 6.7 | Desktop UI — liste incidents avec drill-down | Haute | 3j |
| 6.8 | Desktop UI — boutons scan rapide/complet | Haute | 1j |
| 6.9 | Desktop UI — gestion quarantaine | Haute | 2j |
| 6.10 | Notification desktop (libnotify ou DBus) | Moyenne | 1j |

### Maquette CLI

```bash
nkosi status                    # état protection
nkosi scan file /path/to/file   # scan fichier
nkosi scan dir /home            # scan dossier
nkosi scan quick                # scan rapide
nkosi scan full                 # scan complet
nkosi quarantine list           # liste quarantaine
nkosi quarantine restore <id>   # restauration
nkosi quarantine delete <id>    # suppression définitive
nkosi logs --last 50            # 50 derniers événements
nkosi update                    # mise à jour TI
```

### Critère de validation
- CLI fonctionne sans UI graphique.
- UI affiche l'état en temps réel.
- Un scan via CLI produit un rapport structuré.
- Notification déclenchée sur détection.

---

## Phase 7 — Intégration & Qualité (Semaines 18-20)

### Objectif
Stabiliser, tester, documenter et préparer le déploiement.

### Livrables

| # | Tâche | Priorité | Durée |
|---|-------|----------|-------|
| 7.1 | Tests unitaires complets (couverture > 80%) | Haute | 3j |
| 7.2 | Tests d'intégration pipeline complet | Haute | 2j |
| 7.3 | Tests fonctionnels (EICAR, YARA test, IOC factices) | Haute | 2j |
| 7.4 | Benchmarks performance (CPU, mémoire, I/O) | Haute | 2j |
| 7.5 | Optimisation cache (fichiers inchangés) | Haute | 2j |
| 7.6 | Gestion erreurs — protection dégradée visible | Haute | 2j |
| 7.7 | Packaging — package .deb | Haute | 2j |
| 7.8 | Script install + systemd service | Haute | 1j |
| 7.9 | Documentation technique (architecture, API interne) | Haute | 2j |
| 7.10 | Validation critères d'acceptation V1 | Haute | 2j |

### Critères d'acceptation V1

| # | Critère |
|---|---------|
| AC-01 | L'agent démarre automatiquement sur Debian/Ubuntu |
| AC-02 | Protection temps réel détecte un nouveau fichier |
| AC-03 | SHA-256 comparé à la base locale |
| AC-04 | Règle YARA produit une détection visible |
| AC-05 | Fichier analysé statiquement |
| AC-06 | Processus et PPID observables |
| AC-07 | Connexion réseau associée au processus |
| AC-08 | Signaux corrélés dans un même incident |
| AC-09 | Score de risque calculé |
| AC-10 | Processus tué sur décision du moteur |
| AC-11 | Fichier en quarantaine puis restauré |
| AC-12 | Incidents enregistrés localement |
| AC-13 | Scan manuel produit un rapport |
| AC-14 | Base TI mise à jour sans consultation distante par fichier |
| AC-15 | Interface affiche l'état de protection |
| AC-16 | Détection expliquée par signaux et actions |

---

## Matrice de dépendances

```
Phase 1 (Fondations)
    │
    ├──► Phase 2 (Moniteurs)
    │        │
    │        └──► Phase 3 (Détection)
    │                 │
    │                 └──► Phase 4 (Risk/Response)
    │                          │
    │                          └──► Phase 6 (UI/CLI)
    │
    └──► Phase 5 (Threat Intelligence)
                    │
                    └──► Phase 4 (alimente les moteurs)
                                 │
                                 └──► Phase 7 (Qualité)
```

---

## Gestion des risques

| Risque | Impact | Mitigation |
|--------|--------|------------|
| fanotify nécessite root | Élevé | Capabilities Linux, pas de SUID permanent |
| YARA binding complexe | Moyen | Wrapper C minimal, tests progressifs |
| Performance I/O scan complet | Moyen | Cache SHA-256, parallelisme tokio |
| DB SQLite concurrence | Moyen | WAL mode, connection pool |
| Sources TI indisponibles | Faible | Fallback dernière base valide |

---

## Commandes de démarrage

```bash
# Initialiser le workspace
cargo init nkosi --name nkosi
cd nkosi

# Créer les crates
cargo new nkosi-common --lib
cargo new nkosi-db --lib
cargo new nkosi-agent --bin
cargo new nkosi-monitors --lib
cargo new nkosi-engines --lib
cargo new nkosi-risk --lib
cargo new nkosi-response --lib
cargo new nkosi-ti --lib
cargo new nkosi-cli --bin
cargo new nkosi-ui --bin

# Dépendances de base
cargo add tokio --features full
cargo add serde serde_json --features derive
cargo add rusqlite --features bundled
cargo add sha2
cargo add clap --features derive
cargo add tracing tracing-subscriber
cargo add toml
cargo add thiserror anyhow
cargo add yara
cargo add goblin
```

---

## Calendrier synthétique

```
Sem 1-3   ████ Phase 1 : Fondations
Sem 4-6   ████ Phase 2 : Moniteurs
Sem 7-10  ██████ Phase 3 : Détection
Sem 11-12 ███ Phase 4 : Risk/Response
Sem 13-14 ███ Phase 5 : Threat Intelligence
Sem 15-17 ████ Phase 6 : UI/CLI
Sem 18-20 ████ Phase 7 : Qualité
```

---

*Document généré — NKOSI V1*
