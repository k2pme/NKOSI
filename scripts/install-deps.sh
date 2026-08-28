#!/usr/bin/env bash
#
# install-deps.sh — Installe les prérequis système externes de NKOSI.
#
# NKOSI est un antivirus/EDR écrit en Rust. Cargo gère toutes les
# dépendances Rust, mais il NE PEUT PAS installer certains binaires et
# bibliothèques systèmes requis pour la compilation et au runtime :
#
#   Protocole requin - protoc (protobuf compiler)
#       Requis (OBLIGATOIRE) : tonic_build::compile_protos() est appelé
#       par les build.rs de nkosi-central, nkosi-console et nkosi-agent.
#       Sans protoc, ces crates ne compilent pas.
#   libyara-dev
#       Requis (OBLIGATOIRE) : le moteur YARA réel (feature `real-yara`)
#       est activé par défaut dans nkosi-agent et nkosi-cli pour le bon
#       fonctionnement du scan de fichiers. Sans libyara, ces crates ne
#       compilent pas. L'option --skip-yara est disponible en dernier recours.
#   iptables / ip6tables
#       Requis au RUNTIME : le module nkosi-scanner/firewall bloque les IP
#       via iptables. Utile pour la réponse automatique aux menaces.
#   Outils de build (apt build-essential, gcc, pkg-config, cmake) :
#       nécessaire pour compiler certaines crates natives (bundled sqlite,
#       yara, etc.).
#
# Le script détecte automatiquement le gestionnaire de paquets du système
# (APT/DNF/PACMAN/Zypper/PKG) et installe les paquets correspondants.
#
# Usage :
#   sudo ./scripts/install-deps.sh          # tout le requis (protoc + libyara + outils)
#   sudo ./scripts/install-deps.sh --skip-protoc  # si protoc déjà présent
#   sudo ./scripts/install-deps.sh --skip-yara    # dernier recours (pas de moteur YARA)
#
# Vérifie aussi la présence de protoc sur le PATH et guide l'installation
# d'un binaire protoc si le paquet système n'est pas disponible.
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Options / configuration
# ---------------------------------------------------------------------------
WITH_YARA=0
SKIP_PROTOC=0
SKIP_YARA=0
PROTOC_MIN_VERSION="3.15"

# ---------------------------------------------------------------------------
# Couleurs
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_CYAN=$'\e[36m'; C_OFF=$'\e[0m'
else
    C_GREEN=; C_YELLOW=; C_RED=; C_CYAN=; C_OFF=
fi
info()  { printf '%s[INFO]%s %s\n' "$C_CYAN" "$C_OFF" "$*"; }
ok()    { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_OFF" "$*"; }
warn()  { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_OFF" "$*"; }
fail()  { printf '%s[ERREUR]%s %s\n' "$C_RED" "$C_OFF" "$*"; exit 1; }

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

# ---------------------------------------------------------------------------
# Parsing des arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --yara) WITH_YARA=1 ;;
        --with-yara) WITH_YARA=1 ;;
        --skip-protoc) SKIP_PROTOC=1 ;;
        --skip-yara) SKIP_YARA=1 ;;
        -h|--help) usage ;;
        *) warn "Argument ignoré : $arg" ;;
    esac
done

# ---------------------------------------------------------------------------
# Détection du gestionnaire de paquets
# ---------------------------------------------------------------------------
detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then echo "apt"
    elif command -v dnf >/dev/null 2>&1; then echo "dnf"
    elif command -v yum >/dev/null 2>&1; then echo "yum"
    elif command -v pacman >/dev/null 2>&1; then echo "pacman"
    elif command -v zypper >/dev/null 2>&1; then echo "zypper"
    elif command -v apk >/dev/null 2>&1; then echo "apk"
    elif command -v brew >/dev/null 2>&1; then echo "brew"
    else echo "unknown"; fi
}

# ---------------------------------------------------------------------------
# Helper : installer une liste de paquets selon le gestionnaire
# ---------------------------------------------------------------------------
PKG_MGR="$(detect_pkg_mgr)"
QUIET=${QUIET:-0}

install_pkgs() {
    # $@ = liste de paquets
    info "Installation via ${PKG_MGR} : $*"
    case "$PKG_MGR" in
        apt)
            [ "$(id -u)" -eq 0 ] || fail "Lancez ce script avec sudo (apt exige root)."
            DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        dnf)
            dnf install -y "$@"
            ;;
        yum)
            yum install -y "$@"
            ;;
        pacman)
            pacman -Sy --noconfirm "$@"
            ;;
        zypper)
            zypper --non-interactive install "$@"
            ;;
        apk)
            apk add --no-cache "$@"
            ;;
        brew)
            brew install "$@"
            ;;
        unknown)
            warn "Gestionnaire de paquets inconnu. Installez manuellement : $*"
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# 1) Vérification / installation de protoc
# ---------------------------------------------------------------------------
protoc_ok() {
    if command -v protoc >/dev/null 2>&1; then
        local v
        v="$(protoc --version 2>/dev/null | awk '{print $2}')"
        info "protoc présent : $(command -v protoc) (v${v})"
        return 0
    fi
    return 1
}

install_protoc() {
    if [ "$PKG_MGR" = "unknown" ]; then
        # Pas de gestionnaire : installer un binaire protoc générique
        install_protoc_binary
        return
    fi
    local pkg
    case "$PKG_MGR" in
        apt) pkg="protobuf-compiler" ;;
        dnf|yum) pkg="protobuf-compiler" ;;
        pacman) pkg="protobuf" ;;
        zypper) pkg="protobuf-devel" ;;
        apk) pkg="protobuf" ;;
        brew) pkg="protobuf" ;;
    esac
    install_pkgs "$pkg" || install_protoc_binary
}

install_protoc_binary() {
    warn "Tentative d'installation d'un binaire protoc précompilé (paquet système indisponible)."
    local arch rel url dst
    arch="$(uname -m)"
    case "$arch" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch_64" ;;
        *) fail "Architecture non supportée pour protoc binaire : $arch" ;;
    esac
    rel="v27.3"
    url="https://github.com/protocolbuffers/protobuf/releases/download/${rel}/protoc-${rel#v}-linux-${arch}.zip"
    dst="$(mktemp -d)"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dst/protoc.zip"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$dst/protoc.zip"
    else
        fail "Ni curl ni wget n'est disponible pour télécharger protoc."
    fi
    info "Décompression de protoc dans /usr/local (racine requise)."
    mkdir -p /usr/local/include
    (cd "$dst" && unzip -o protoc.zip >/dev/null && cp bin/protoc /usr/local/bin/ \
        && cp -r include/google /usr/local/include/ 2>/dev/null || true)
    rm -rf "$dst"
    ok "protoc installé dans /usr/local/bin"
}

# ---------------------------------------------------------------------------
# 2) Installation de libyara-dev (obligatoire, feature real-yara)
# ---------------------------------------------------------------------------
install_yara() {
    case "$PKG_MGR" in
        apt) install_pkgs "libyara-dev" ;;
        dnf|yum) install_pkgs "yara-devel" ;;
        pacman) install_pkgs "yara" ;;
        zypper) install_pkgs "yara-devel" ;;
        apk) install_pkgs "yara-dev" ;;
        brew) install_pkgs "yara" ;;
        unknown) fail "Aucun gestionnaire détecté : installez libyara-dev manuellement." ;;
    esac
}

# ---------------------------------------------------------------------------
# 3) installation des outils de build + iptables (runtime)
# ---------------------------------------------------------------------------
install_build_tools() {
    case "$PKG_MGR" in
        apt) install_pkgs "build-essential" "pkg-config" "cmake" "iptables" "ip6tables" "unzip" "curl" ;;
        dnf|yum) install_pkgs "gcc" "gcc-c++" "make" "pkgconfig" "cmake" "iptables" "unzip" "curl" ;;
        pacman) install_pkgs "base-devel" "pkg-config" "cmake" "iptables" "unzip" "curl" ;;
        zypper) install_pkgs "gcc" "gcc-c++" "make" "pkg-config" "cmake" "iptables" "unzip" "curl" ;;
        apk) install_pkgs "build-base" "pkgconf" "cmake" "iptables" "unzip" "curl" ;;
        brew) install_pkgs "pkg-config" "cmake" ;;
        unknown) warn "Installez manuellement : compilateur C, pkg-config, cmake, iptables, unzip, curl." ;;
    esac
}

# ---------------------------------------------------------------------------
# EXÉCUTION
# ---------------------------------------------------------------------------
info "Gestionnaire détecté : ${PKG_MGR:-inconnu}"

# 1) protoc (obligatoire sauf --skip-protoc)
if [ "$SKIP_PROTOC" = "0" ]; then
    if ! protoc_ok; then
        info "protoc absent du PATH — installation en cours..."
        install_protoc
    fi
else
    warn "--skip-protoc : vérification de protoc ignorée."
fi

# 2) outils de build / runtime (iptables)
install_build_tools

# 3) yara (obligatoire pour le moteur YARA réel)
if [ "$SKIP_YARA" = "1" ]; then
    warn "--skip-yara : libyara non installé. Le build des crates nkosi-agent/nkosi-cli échouera sans libyara."
else
    info "Installation de libyara (feature real-yara)..."
    install_yara
fi

# ---------------------------------------------------------------------------
# Vérification finale
# ---------------------------------------------------------------------------
ok "Prérequis installés."
if command -v protoc >/dev/null 2>&1; then
    info "protoc : $(protoc --version 2>/dev/null)"
else
    warn "protoc n'est pas sur le PATH. Le build des crates gRPC (central/console/agent) nécessitera protoc."
fi
if [ "$SKIP_YARA" = "0" ] && ! ldconfig -p 2>/dev/null | grep -q libyara && ! grep -q yara /proc/self/maps 2>/dev/null; then
    warn "libyara introuvable — vérifiez l'installation (paquet native library)."
fi
info "Ensuite : cargo build --workspace"
