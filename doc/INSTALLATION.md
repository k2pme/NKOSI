# NKOSI — Guide d'installation

NKOSI est un antivirus/EDR (linux) écrit en Rust, organisé en workspace de
16 crates. Ce guide couvre l'installation complète : prérequis système,
compilation, déploiement des binaires, services systemd et désinstallation.

## 1. Prérequis

Voir `doc/PREREQUIS.md` pour le détail. En résumé, Cargo gère les dépendances
Rust, mais quelques outils/bibliothèques système sont nécessaires :

- **protoc** (protobuf compiler) — obligatoire (build des crates gRPC)
- **libyara-dev** — obligatoire (moteur YARA réel, feature `real-yara`)
- **iptables / ip6tables** — obligatoire au runtime (firewall)
- **outils de build** : build-essential (gcc/make), pkg-config, cmake, unzip, curl

Installez-les automatiquement avec :

```bash
sudo ./scripts/install-deps.sh
```

Options utiles :

```bash
sudo ./scripts/install-deps.sh --skip-protoc  # si protoc déjà présent
sudo ./scripts/install-deps.sh --skip-yara    # dernier recours (sans moteur YARA)
```

Le script détecte le gestionnaire de paquets du système
(apt/dnf/yum/pacman/zypper/apk/brew).

## 2. Compilation

```bash
cargo build --workspace        # compilation en développement
cargo build --release          # compilation optimisée (recommandée pour installer)
```

Binaires produits dans `target/release/` :

| Binaire                  | Rôle                                        |
|--------------------------|---------------------------------------------|
| `nkosi-agent`            | Agent EDR local (surveillance, scan)        |
| `nkosi-cli`              | Interface en ligne de commande              |
| `nkosi-central`          | Serveur central (collecte gRPC, registry)   |
| `nkosi-console`          | Console de supervision / dashboard          |
| `nkosi-ui`               | Interface graphique                         |

## 3. Installation (binaires + service)

Si la distribution fournit des `services systemd` (dossier `config/`), le
Makefile automatise le déploiement :

```bash
make install
```

Ce qui installe :

- les binaires dans `/usr/local/bin/`
- la configuration dans `/etc/nkosi/`
- les unités systemd (`nkosi-agent.service`, `nkosi-ti-update.timer`, ...)
- les données dans `/var/lib/nkosi/` et les logs dans `/var/log/nkosi/`

Puis démarrez le service :

```bash
sudo systemctl start nkosi-agent
sudo systemctl status nkosi-agent
```

## 4. Installation manuelle

```bash
sudo mkdir -p /etc/nkosi /var/lib/nkosi /var/log/nkosi
sudo cp target/release/nkosi-agent /usr/local/bin/
sudo cp target/release/nkosi-cli   /usr/local/bin/
sudo cp target/release/nkosi-ui    /usr/local/bin/
sudo cp config/nkosi.toml /etc/nkosi/
```

## 5. Désinstallation

```bash
make uninstall
```

Arrête et désactive les services, supprime les binaires et les unités systemd.

## 6. Vérification

```bash
nkosi-cli --version
nkosi-agent --version
systemctl status nkosi-agent
```

Consultez les logs :

```bash
journalctl -u nkosi-agent -f
```
