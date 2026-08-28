# NKOSI — Installation Guide

NKOSI is a Linux antivirus/EDR written in Rust, organized as a workspace of
16 crates. This guide covers full installation: system prerequisites,
compilation, binary deployment, systemd services, and uninstallation.

## 1. Prerequisites

See `doc/PREREQUIS.md` for details. In summary, Cargo manages Rust
dependencies, but a few system tools/libraries are required:

- **protoc** (protobuf compiler) — required (builds gRPC crates)
- **libyara-dev** — required (real YARA engine, `real-yara` feature)
- **iptables / ip6tables** — required at runtime (firewall)
- **build tools**: build-essential (gcc/make), pkg-config, cmake, unzip, curl

Install them automatically with:

```bash
sudo ./scripts/install-deps.sh
```

Useful options:

```bash
sudo ./scripts/install-deps.sh --skip-protoc  # if protoc is already installed
sudo ./scripts/install-deps.sh --skip-yara    # last resort (no YARA engine)
```

The script detects the system package manager
(apt/dnf/yum/pacman/zypper/apk/brew).

## 2. Compilation

```bash
cargo build --workspace        # development build
cargo build --release          # optimized build (recommended for installation)
```

Binaries produced in `target/release/`:

| Binary                  | Role                                        |
|--------------------------|---------------------------------------------|
| `nkosi-agent`            | Local EDR agent (monitoring, scanning)      |
| `nkosi-cli`              | Command-line interface                      |
| `nkosi-central`          | Central server (gRPC collection, registry)  |
| `nkosi-console`          | Monitoring console / dashboard              |
| `nkosi-ui`               | Graphical user interface                    |

## 3. Installation (binaries + service)

If the distribution provides `systemd services` (folder `config/`), the
Makefile automates deployment:

```bash
make install
```

This installs:

- binaries in `/usr/local/bin/`
- configuration in `/etc/nkosi/`
- systemd units (`nkosi-agent.service`, `nkosi-ti-update.timer`, ...)
- data in `/var/lib/nkosi/` and logs in `/var/log/nkosi/`

Then start the service:

```bash
sudo systemctl start nkosi-agent
sudo systemctl status nkosi-agent
```

## 4. Manual installation

```bash
sudo mkdir -p /etc/nkosi /var/lib/nkosi /var/log/nkosi
sudo cp target/release/nkosi-agent /usr/local/bin/
sudo cp target/release/nkosi-cli   /usr/local/bin/
sudo cp target/release/nkosi-ui    /usr/local/bin/
sudo cp config/nkosi.toml /etc/nkosi/
```

## 5. Uninstallation

```bash
make uninstall
```

Stops and disables services, removes binaries and systemd units.

## 6. Verification

```bash
nkosi-cli --version
nkosi-agent --version
systemctl status nkosi-agent
```

Check logs:

```bash
journalctl -u nkosi-agent -f
```

## 7. Recommended server deployment

To protect the host, prefer the systemd service: the container is suitable for
demonstration and centralized components, but it does not mount the host
filesystems to monitor. Expose the API and console only through an HTTPS
reverse proxy, with network firewall and a strong `NKOSI_API_KEYS` key.
The central server should remain on a private network or behind a proxy that
authenticates agents. Set `NKOSI_TRUST_PROXY=1` only if direct API access is
blocked by the firewall; this allows the reverse proxy's
`X-Forwarded-For` headers for rate limiting.

To protect the agent-central channel at the application level, set the same
`NKOSI_CENTRAL_TOKEN` secret value on the central server, each agent, and the
console. If it is absent, the behavior remains compatible with existing local
installations; do not leave the central server exposed.

The Docker Compose agent is a demonstration of the centralized ecosystem: it
does not protect host files. For endpoint protection, install `nkosi-agent`
as a systemd service on each server.
