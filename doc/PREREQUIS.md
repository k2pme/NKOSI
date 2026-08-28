# NKOSI — External System Prerequisites

NKOSI is an antivirus/EDR written in Rust (workspace of 16 crates).
Cargo manages all Rust dependencies, but it cannot **not** install
certain system binaries and libraries required for compilation and at
runtime. This document lists these prerequisites and explains how to install them.

## 1. protoc (protobuf compiler) — REQUIRED

`tonic_build::compile_protos()` is called by the `build.rs` of
`nkosi-central`, `nkosi-console` and `nkosi-agent`. Without `protoc`, these crates
do not compile.

## 2. libyara-dev (real YARA engine) — REQUIRED

The real YARA engine (feature `real-yara`) is **enabled by default** in
`nkosi-agent` and `nkosi-cli`, as it guarantees proper file scanning. Without `libyara`, these crates do not compile.

- `nkosi-agent/Cargo.toml`: `nkosi-engines = { features = ["real-yara"] }`
- `nkosi-cli/Cargo.toml`: `nkosi-engines = { features = ["real-yara"] }`

In code, the engine uses the adaptive constructor `new_prefer_real()`:

- feature `real-yara` enabled  → real YARA engine (`YaraEngine::new_with_real_yara()`)
- feature disabled            → heuristic fallback (regex-based `YaraRule` rules)

The feature remains toggleable in `nkosi-engines` (`default = []`), but the
production entry points enable it.

## 3. iptables / ip6tables — REQUIRED (runtime)

The `nkosi-scanner/firewall` module blocks IPs via iptables for automatic
threat response.

## 4. Build tools

Required to compile some native crates (bundled sqlite, yara, etc.):
`build-essential` (gcc, make), `pkg-config`, `cmake`, `unzip`, `curl`.

## Automatic installation

```bash
sudo ./scripts/install-deps.sh          # full requirements (protoc + libyara + tools)
sudo ./scripts/install-deps.sh --skip-protoc  # if protoc is already installed
sudo ./scripts/install-deps.sh --skip-yara    # last resort (no YARA engine)
```

The script detects the package manager (apt/dnf/yum/pacman/zypper/apk/brew)
and installs the corresponding packages. It also installs a precompiled
`protoc` binary if no package manager is available.

## Verification

```bash
protoc --version            # >= 3.15
pkg-config --exists yara && echo OK
cargo build --workspace
```
