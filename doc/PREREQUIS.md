# NKOSI — Prérequis système externes

NKOSI est un antivirus/EDR écrit en Rust (workspace de 16 crates).
Cargo gère toutes les dépendances Rust, mais il ne peut **pas** installer
certains binaires et bibliothèques système requis pour la compilation et au
runtime. Ce document liste ces prérequis et explique comment les installer.

## 1. protoc (protobuf compiler) — OBLIGATOIRE

`tonic_build::compile_protos()` est appelé par le `build.rs` de
`nkosi-central`, `nkosi-console` et `nkosi-agent`. Sans `protoc`, ces crates
ne compilent pas.

## 2. libyara-dev (moteur YARA réel) — OBLIGATOIRE

Le moteur YARA réel (feature `real-yara`) est **activé par défaut** dans
`nkosi-agent` et `nkosi-cli`, car il garantit le bon fonctionnement du scan de
fichiers. Sans `libyara`, ces crates ne compilent pas.

- `nkosi-agent/Cargo.toml` : `nkosi-engines = { features = ["real-yara"] }`
- `nkosi-cli/Cargo.toml` : `nkosi-engines = { features = ["real-yara"] }`

Côté code, le moteur utilise le constructeur adaptatif `new_prefer_real()` :

- feature `real-yara` activée  → vrai moteur YARA (`YaraEngine::new_with_real_yara()`)
- feature désactivée            → fallback heuristique (règles `YaraRule` en regex)

La feature reste toggleable dans `nkosi-engines` (`default = []`), mais les
points d'entrée de production l'activent.

## 3. iptables / ip6tables — OBLIGATOIRE (runtime)

Le module `nkosi-scanner/firewall` bloque les IP via iptables pour la réponse
automatique aux menaces.

## 4. Outils de build

Nécessaires pour compiler certaines crates natives (bundled sqlite, yara, etc.) :
`build-essential` (gcc, make), `pkg-config`, `cmake`, `unzip`, `curl`.

## Installation automatique

```bash
sudo ./scripts/install-deps.sh          # tout le requis (protoc + libyara + outils)
sudo ./scripts/install-deps.sh --skip-protoc  # si protoc déjà présent
sudo ./scripts/install-deps.sh --skip-yara    # dernier recours (pas de moteur YARA)
```

Le script détecte le gestionnaire de paquets (apt/dnf/yum/pacman/zypper/apk/brew)
et installe les paquets correspondants. Il installe aussi un binaire `protoc`
précompilé si aucun gestionnaire n'est disponible.

## Vérification

```bash
protoc --version            # ≥ 3.15
pkg-config --exists yara && echo OK
cargo build --workspace
```
