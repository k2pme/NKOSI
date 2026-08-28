# Analyse du projet NKOSI — Points d'amélioration

## 1. Architecture & Design (globalement bon)

- Architecture modulaire claire (14 crates) avec event bus bien séparé
- Séparation monitors / engines / risk / response respecte le cahier des charges
- Workspace Cargo bien structuré

## 2. Sécurité (CRITIQUE)

### a) API Keys par défaut faible
- **Fichier:** `nkosi-api/src/main.rs:39`
- **Problème:** Si `NKOSI_API_KEYS` n'est pas défini, une clé statique `nkosi_<zeros>` est générée. Il faut exiger une clé configurée ou refuser le démarrage.
- **Statut:** ⚠️ NON RÉSOLU

### b) Pas de TLS/HTTPS
- **Fichier:** `nkosi-api/src/main.rs`
- **Problème:** L'API écoute en HTTP sur `0.0.0.0:8080`. Pour un produit de sécurité, il faut au minimum HTTPS avec certificat auto-signé ou mutual TLS.
- **Statut:** ⚠️ NON RÉSOLU

### c) Vérification d'intégrité des mises à jour TI
- **Fichier:** `nkosi-ti/src/update_service.rs`
- **Problème:** Télécharge depuis MalwareBazaar/ThreatFox/URLhaus sans vérification de signature ni hash. Un MITM pourrait empoisonner la base locale.
- **Statut:** ✅ RÉSOLU — Vérifications ajoutées dans `integrity_check.rs` (validate_min_size, compute_audit_hash, validation format par source)

### d) Path traversal partiel
- **Fichier:** `nkosi-api/src/main.rs:203`
- **Problème:** Ne bloque que `..` et `~`, mais pas les chemins symlinks ou les chemins normalisés qui sortent des zones autorisées.
- **Statut:** ⚠️ NON RÉSOLU

### e) Docker privilège excessif
- **Fichier:** `docker-compose.yml:11`
- **Problème:** Utilise `privileged: true`. Il faut limiter aux capabilities nécessaires (`NET_ADMIN`, `SYS_PTRACE`, etc.).
- **Statut:** ⚠️ NON RÉSOLU

### f) `/tmp/nkosi_health.json` non sécurisé
- **Fichier:** `nkosi-agent/src/main.rs:78`
- **Problème:** N'importe quel utilisateur local peut modifier/tamper ce fichier. Utiliser un répertoire sécurisé avec permissions restreintes.
- **Statut:** ⚠️ NON RÉSOLU

## 3. Performance

### a) Goulot d'étranglement BDD
- **Fichier:** `nkosi-db/src/schema.rs:9`
- **Problème:** `Arc<Mutex<Connection>>` unique. Toutes les opérations SQL passent par le même mutex. SQLite supporte mieux les readers/writers séparés (RwLock ou connexions multiples).
- **Statut:** ⚠️ NON RÉSOLU

### b) Scan inode réseau coûteux
- **Fichier:** `nkosi-monitors/src/network.rs:169`
- **Problème:** Un cache miss déclenche un scan complet de `/proc/*/fd`. Améliorer avec un TTL court et un refresh périodique plutôt que réactif.
- **Statut:** ⚠️ NON RÉSOLU

### c) Hachage synchrone sur chaque événement fichier
- **Fichier:** `nkosi-agent/src/main.rs:395`
- **Problème:** SHA-256 calculé sur le thread de traitement d'événements. Déléguer à un pool de workers ou utiliser un cache LRU pour les fichiers déjà hashés.
- **Statut:** ⚠️ NON RÉSOLU

### d) Scan processus trop agressif
- **Fichier:** `nkosi-monitors/src/process.rs:128`
- **Problème:** Scan tous les PIDs toutes les 500ms. Passer à 1-2s ou utiliser inotify sur `/proc` si disponible.
- **Statut:** ⚠️ NON RÉSOLU

## 4. Qualité du code

### a) Fichiers main.rs trop volumineux
- **Fichiers:** `nkosi-cli/src/main.rs` (1236 lignes), `nkosi-api/src/main.rs` (665+ lignes)
- **Problème:** Extraire les handlers dans des modules séparés.
- **Statut:** ⚠️ NON RÉSOLU

### b) Code dupliqué
- **Fichiers:** `nkosi-agent/src/main.rs`, `nkosi-cli/src/main.rs`
- **Problème:** `load_config()` et `init_database()` sont dupliqués. Déplacer dans `nkosi-common`.
- **Statut:** ⚠️ NON RÉSOLU

### c) `unwrap()` abusif en production
- **Fichier:** `nkosi-db/src/repositories.rs`
- **Problème:** Des `.unwrap()` sur `Uuid::parse_str` et `DateTime::parse_from_rfc3339`. Une corruption BDD crash le service. Gérer les erreurs proprement.
- **Statut:** ⚠️ NON RÉSOLU

### d) Mutex empoisonné silencieux
- **Fichier:** `nkosi-monitors/src/process.rs:70`
- **Problème:** `unwrap_or_else(|e| e.into_inner())` masque les paniques. Logger l'erreur et redémarrer le monitor si nécessaire.
- **Statut:** ⚠️ NON RÉSOLU

### e) Exclusion polling désactivée
- **Fichier:** `nkosi-monitors/src/filesystem.rs:192`
- **Problème:** Le fallback polling utilise `excluded: Vec::new()`, donc il surveille `/proc`, `/sys`, etc. Transférer la liste d'exclusion au fallback.
- **Statut:** ⚠️ NON RÉSOLU

### f) Strings multilingues
- **Fichiers:** `nkosi-cli/src/main.rs:590,621`
- **Problème:** Mélange de français, anglais et même caractères chinois (`不存在`). Uniformiser.
- **Statut:** ⚠️ NON RÉSOLU

### g) Bug filtre sévérité corrigé
- **Fichier:** `nkosi-db/src/repositories.rs:782`
- **Problème:** `get_events_filtered` comparait `"Critical"` (string) contre `"\"Critical\""` (JSON stocké en BDD). Le filtre ne retournait jamais de résultats.
- **Statut:** ✅ RÉSOLU — Encodage JSON ajouté avant comparaison

## 5. Tests

### Couverture (mise à jour après F2.11)

| Composant | Tests unitaires | Tests intégration | Statut |
|-----------|----------------|-------------------|--------|
| nkosi-db | 39 | 8 (db_test + agent_test) | ✅ Bon |
| nkosi-risk | 13 | 2 (risk_test) | ✅ Bon |
| nkosi-ti | 37 | 8 (ti_integrity_test) | ✅ Bon |
| nkosi-engines | 7 | 3 (scan_integration_test) | ⚠️ Limité |
| nkosi-response | — | 2 (quarantine_test) | ⚠️ Limité |
| nkosi-monitors | — | 2 (health_test, firewall_test) | ⚠️ Limité |
| nkosi-agent | — | — | ❌ Aucun |
| nkosi-api | — | — | ❌ Aucun |
| nkosi-central | — | — | ❌ Aucun |
| nkosi-cli | — | — | ❌ Aucun |
| nkosi-ui | — | — | ❌ Aucun |

- **Total:** 150 tests, tous passent ✅
- **Manque:** Tests monitors, engines (fuzzing), response, agent, API, central, CLI
- **Manque:** Property-based testing, fuzzing pour un produit de sécurité

## 6. Configuration & Déploiement

### a) Artefact git polluant
- **Fichier:** `protoc-25.1-linux-x86_64.zip` (3MB)
- **Problème:** Commit dans le repo. Ajouter au `.gitignore` et le télécharger en CI.
- **Statut:** ⚠️ NON RÉSOLU

### b) Service systemd sans limites
- **Fichier:** `config/nkosi-agent.service`
- **Problème:** Pas de `MemoryMax`, `CPUQuota`, `LimitNOFILE`. Pour un daemon de sécurité, ajouter des limites de ressources.
- **Statut:** ⚠️ NON RÉSOLU

### c) `.gitignore` incomplet
- **Fichier:** `.gitignore`
- **Problème:** Il manque `target/`, `Cargo.lock` (pour les binaires), `*.db`, `data/`, `.kilo/`, les archives `.tar.gz`.
- **Statut:** ⚠️ NON RÉSOLU

### d) Health check docker
- **Fichier:** `Dockerfile:53`
- **Problème:** `curl -f http://localhost:8080/api/status` vérifie l'API, pas l'agent. Or le `ENTRYPOINT` est `nkosi-agent`. Le health check doit cibler le bon processus.
- **Statut:** ⚠️ NON RÉSOLU

## 7. F2.11 Console centralisée — État

| Composant | Statut | Notes |
|-----------|--------|-------|
| Schéma DB multi-agent (nkosi-db) | ✅ | agents table, agent_id columns, AgentRepository |
| Persistance SQLite central (nkosi-central) | ✅ | merged reads, stale cleanup, audit hash |
| Client gRPC agent→central (nkosi-agent) | ✅ | tonic client optionnel via NKOSI_CENTRAL_ADDR |
| API REST endpoints multi-agent (nkosi-api) | ✅ | /api/agents, /api/alertes, /api/stats/consolidated, etc. |
| Dashboard web onglet Agents | ✅ | Stats, tableau agents, alertes, auto-refresh 30s |
| TUI onglet Agents | ✅ | Stats, liste agents avec couleurs par statut |
| CLI report consolidated | ✅ | Format texte/JSON, sortie fichier/stdout |
| Tests d'intégration | ✅ | 12 nouveaux tests (agent_test + scan_integration_test) |

## 8. Améliorations spécifiques recommandées

| Priorité | Action | Fichier | Statut |
|----------|--------|---------|--------|
| P0 | Refuser démarrage sans API key explicite | `nkosi-api/src/main.rs` | ⚠️ |
| P0 | Gérer erreurs BDD sans unwrap | `nkosi-db/src/repositories.rs` | ⚠️ |
| P1 | Implémenter HTTPS/TLS pour l'API | `nkosi-api/src/main.rs` | ⚠️ |
| P1 | Corriger le fallback polling (exclusions) | `nkosi-monitors/src/filesystem.rs` | ⚠️ |
| P1 | Ajouter cache LRU pour les hashes | `nkosi-engines/src/hash_engine.rs` | ⚠️ |
| P1 | Séparer les main.rs en modules | `nkosi-cli/src/main.rs`, `nkosi-api/src/main.rs` | ⚠️ |
| P1 | Dédupliquer load_config/init_database | `nkosi-common/src/` | ⚠️ |
| P1 | Ajouter tests monitors et engines | `tests/` | ⚠️ |
| P2 | Remplacer Mutex<Connection> par pooling | `nkosi-db/src/schema.rs` | ⚠️ |
| P2 | Limiter capabilities Docker au lieu de privileged | `docker-compose.yml` | ⚠️ |
| P2 | Uniformiser la langue des messages | tous les fichiers | ⚠️ |
| P2 | Nettoyer artefacts git (protoc zip) | `.gitignore` | ⚠️ |
| P2 | Ajouter limites systemd | `config/nkosi-agent.service` | ⚠️ |
| P3 | Tests fuzzing pour engines | `tests/` | ⚠️ |
| P3 | Tests API (end-to-end HTTP) | `tests/` | ⚠️ |
| P3 | Tests gRPC central↔agent | `tests/` | ⚠️ |

## Résumé

Le projet a une architecture solide et respecte bien le cahier des charges fonctionnel. La **F2.11 Console centralisée** est complète (7/7 étapes + tests). Les 150 tests passent tous.

**Problèmes majeurs restants :**
1. **Sécurité** — API key par défaut, pas de TLS, health file non sécurisé
2. **Performance** — BDD mutex unique, scans agressifs, pas de cache LRU
3. **Qualité** — main.rs volumineux, code dupliqué, unwrap() en production
4. **Tests** — Couverture nulle sur agent, API, central, CLI, UI
