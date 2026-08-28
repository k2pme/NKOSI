# Plan d'exécution — Améliorations NKOSI

## Vue d'ensemble

| Phase | Priorité | Estimée | Items |
|-------|----------|---------|-------|
| 1 | P0 Sécurité critique | 2-3h | 3 items |
| 2 | P1 Qualité + Performance | 4-5h | 7 items |
| 3 | P2 Déploiement + Tests | 3-4h | 5 items |
| 4 | P3 Tests avancés | 2-3h | 3 items |
| **Total** | | **11-15h** | **18 items** |

---

## Phase 1 — Sécurité critique (P0)

> Blocage : impossible à déployer en prod sans ça.

### 1.1 Refuser démarrage sans API key explicite
- **Fichier:** `nkosi-api/src/main.rs`
- **Action:** Si `NKOSI_API_KEYS` n'est pas défini ou vaut la valeur par défaut, `panic!()` au démarrage avec message explicite.
- **Effet:** Force l'opérateur à configurer une vraie clé.
- **Risque:** Casser le cas d'usage dev local → ajouter un flag `--allow-default-key` ou variable `NKOSI_ALLOW_DEFAULT_KEY=1`.

### 1.2 Gérer erreurs BDD sans unwrap
- **Fichier:** `nkosi-db/src/repositories.rs`
- **Action:** Remplacer les `.unwrap()` sur `Uuid::parse_str` et `DateTime::parse_from_rfc3339` par `unwrap_or_else(|_| Uuid::new_v4())` ou propagation d'erreur `?`.
- **Lignes concernées:** 39, 74, 115, 157, 813 (EventRepository), 405 (ThreatIndicatorRepository).
- **Effet:** Une corruption BDD ne crash plus le service.

### 1.3 Sécuriser le fichier health
- **Fichier:** `nkosi-agent/src/main.rs`
- **Action:** Écrire dans `/run/nkosi/health.json` (dossier systemd RuntimeDirectory) au lieu de `/tmp/`. Ajouter `RuntimeDirectory=nkosi` dans le service systemd.
- **Alternative:** `XDG_RUNTIME_DIR` si disponible.
- **Effet:** Permissions restreintes (0700), inaccessible aux autres utilisateurs.

---

## Phase 2 — Qualité + Performance (P1)

> Améliore la maintenabilité et les performances sans casser l'API.

### 2.1 Dédupliquer load_config / init_database
- **Action:** Créer `nkosi-common/src/utils.rs` avec `pub fn load_config()` et `pub fn init_database()`.
- **Fichiers:** `nkosi-agent/src/main.rs`, `nkosi-cli/src/main.rs`, `nkosi-ui/src/app.rs`.
- **Effet:** ~50 lignes supprimées de chaque main.rs.

### 2.2 Séparer nkosi-cli en modules
- **Action:** Créer `nkosi-cli/src/commands/` :
  - `status.rs` — commande `status`
  - `scan.rs` — commande `scan`
  - `quarantine.rs` — commande `quarantine`
  - `report.rs` — commande `report`
  - `config.rs` — commande `config`
- **Effet:** `main.rs` passe de 1236 à ~100 lignes (dispatch seul).

### 2.3 Séparer nkosi-api en modules
- **Action:** Créer `nkosi-api/src/handlers/` :
  - `status.rs` — `/api/status`
  - `events.rs` — `/api/events*`
  - `agents.rs` — `/api/agents*`
  - `quarantine.rs` — `/api/quarantine`
  - `firewall.rs` — `/api/firewall`
  - `scan.rs` — `/api/scan`
- **Effet:** `main.rs` passe de 665+ à ~150 lignes.

### 2.4 Cache LRU pour les hashes
- **Fichier:** `nkosi-engines/src/hash_engine.rs`
- **Action:** Ajouter `lru` crate,缓存 les 10000 derniers SHA-256 calculés (path → hash).
- **Dépendance:** Ajouter `lru = "0.12"` dans `Cargo.toml`.
- **Effet:** Évite de re-hasher les fichiers déjà traités.

### 2.5 Corriger le fallback polling (exclusions)
- **Fichier:** `nkosi-monitors/src/filesystem.rs:192`
- **Action:** Transmettre `config.monitors.excluded_paths` au fallback polling au lieu de `Vec::new()`.
- **Effet:** `/proc`, `/sys`, etc. ne sont plus surveillés en polling.

### 2.6 Réduire fréquence scan processus
- **Fichier:** `nkosi-monitors/src/process.rs:128`
- **Action:** Passer l'intervalle de 500ms à 2000ms (configurable via `config.monitors.process_scan_interval_ms`).
- **Effet:** Réduit la charge CPU de ~75%.

### 2.7 Mutex empoisonné → logging
- **Fichier:** `nkosi-monitors/src/process.rs:70`
- **Action:** Remplacer `unwrap_or_else(|e| e.into_inner())` par :
  ```rust
  match self.processes.lock() {
      Ok(guard) => guard,
      Err(e) => {
          tracing::error!("Mutex empoisonné, récupération: {}", e);
          e.into_inner()
      }
  }
  ```
- **Effet:** L'empoisonnement est loggé au lieu d'être silencieux.

---

## Phase 3 — Déploiement + Tests (P2)

> Prépare le déploiement production et renforce la fiabilité.

### 3.1 Nettoyer .gitignore
- **Fichier:** `.gitignore`
- **Action:** Ajouter :
  ```
  target/
  *.db
  data/
  .kilo/
  *.tar.gz
  protoc-*.zip
  /tmp/
  ```
- **Effet:** Les artefacts build et fichiers temporaires ne sont plus trackés.

### 3.2 Ajouter limites systemd
- **Fichier:** `config/nkosi-agent.service`
- **Action:** Ajouter :
  ```ini
  MemoryMax=512M
  CPUQuota=50%
  LimitNOFILE=65536
  LimitNPROC=512
  PrivateTmp=true
  ProtectSystem=strict
  ProtectHome=true
  NoNewPrivileges=true
  ```
- **Effet:** Le daemon ne peut pas consommer plus que prévu.

### 3.3 Limiter Docker capabilities
- **Fichier:** `docker-compose.yml`
- **Action:** Remplacer `privileged: true` par :
  ```yaml
  cap_add:
    - NET_ADMIN
    - SYS_PTRACE
  cap_drop:
    - ALL
  security_opt:
    - no-new-privileges:true
  ```
- **Effet:** Réduit la surface d'attaque container.

### 3.4 Corriger health check Docker
- **Fichier:** `Dockerfile:53`
- **Action:** Si ENTRYPOINT = nkosi-agent, le health check doit cibler l'agent :
  ```dockerfile
  HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD test -f /run/nkosi/health.json || exit 1
  ```
- **Effet:** Le health check vérifie le bon processus.

### 3.5 Uniformiser la langue
- **Fichiers:** `nkosi-cli/src/main.rs:590,621` et autres.
- **Action:** Remplacer les caractères chinois (`不存在`, `尚未配置`) par leurs équivalents français (`introuvable`, `non configuré`).
- **Effet:** UI cohérente en français.

---

## Phase 4 — Tests avancés (P3)

> Renforce la fiabilité à long terme.

### 4.1 Tests monitors
- **Fichier:** `tests/src/integration/monitor_test.rs` (nouveau)
- **Tests:**
  - `test_filesystem_monitor_create_event` — Crée un fichier, vérifie l'événement
  - `test_process_monitor_detect_new` — Lance un processus, vérifie la détection
  - `test_network_monitor_cache` — Teste le cache et le TTL

### 4.2 Tests engines (fuzzing)
- **Fichier:** `tests/src/integration/engine_fuzz_test.rs` (nouveau)
- **Tests:**
  - `test_yara_fuzz_random_bytes` — 1000 buffers aléatoires → pas de panic
  - `test_hash_fuzz_empty_files` — Fichiers vides, très gros, symliques
  - `test_static_analyzer_fuzz` — Binaires corrompus, ELF malformés
- **Dépendance:** Ajouter `proptest` ou `bolero` dans les dev-dependencies.

### 4.3 Tests API (end-to-end HTTP)
- **Fichier:** `tests/src/integration/api_test.rs` (nouveau)
- **Tests:**
  - `test_api_status_endpoint` — GET /api/status → 200
  - `test_api_auth_required` — Sans X-API-Key → 401
  - `test_api_rate_limit` — 100 requêtes rapides → 429
  - `test_api_agents_endpoint` — GET /api/agents → 200
  - `test_api_consolidated_report` — GET /api/report/consolidated → 200
- **Dépendance:** `actix-rt` + `awc` (actix web client) dans les dev-dependencies.

---

## Exécution recommandée

```
Sprint 1 (2-3h) : Phase 1 — Sécurité critique
  → 1.1 API key     → 1.2 BDD unwrap     → 1.3 Health file

Sprint 2 (4-5h) : Phase 2 — Qualité + Performance
  → 2.1 Dédup code  → 2.2 CLI modules    → 2.3 API modules
  → 2.4 Cache LRU   → 2.5 Polling fix    → 2.6 Process interval
  → 2.7 Mutex log

Sprint 3 (3-4h) : Phase 3 — Déploiement + Tests
  → 3.1 gitignore   → 3.2 systemd        → 3.3 Docker caps
  → 3.4 Health check → 3.5 Langue

Sprint 4 (2-3h) : Phase 4 — Tests avancés
  → 4.1 Monitors    → 4.2 Fuzzing        → 4.3 API tests
```

---

## Critères de validation

Après chaque sprint, vérifier :

```bash
# Compilation
cargo build --workspace

# Pas de warnings
cargo clippy --workspace -- -D warnings

# Tous les tests passent
cargo test --workspace

# Formatage
cargo fmt --check
```

Pour Sprint 3, vérifier en plus :

```bash
# Docker build
docker build -t nkosi:test .

# Systemd validation
systemd-analyze verify config/nkosi-agent.service
```

Pour Sprint 4, vérifier en plus :

```bash
# Couverture (si cargo-tarpaulin installé)
cargo tarpaulin --workspace --out Html
```
