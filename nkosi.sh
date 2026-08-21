#!/usr/bin/env bash
set -euo pipefail

PROJ_DIR="/home/clodlin/NKOSI"
PROTOC_DIR="/tmp/protoc/bin"

export PATH="$PROTOC_DIR:$PATH"
export NKOSI_API_KEYS="${NKOSI_API_KEYS:-cle123}"
export NKOSI_RATE_LIMIT="${NKOSI_RATE_LIMIT:-20}"

cd "$PROJ_DIR"

case "${1:-help}" in
    build)
        echo "=== Building NKOSI ==="
        PROTOC=$PROTOC_DIR/protoc cargo build
        echo "Build OK"
        ;;
    api)
        echo "=== Starting API on http://localhost:8080 ==="
        echo "API Key: $NKOSI_API_KEYS"
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-api
        ;;
    central)
        echo "=== Starting Central gRPC on port 50051 ==="
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-central
        ;;
    cli)
        shift
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-cli -- "$@"
        ;;
    scan)
        shift
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-cli -- scan "$@"
        ;;
    rootkit)
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-cli -- rootkit
        ;;
    kernel)
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-cli -- kernel
        ;;
    ssh)
        shift
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-cli -- ssh "$@"
        ;;
    firewall)
        shift
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-cli -- firewall "$@"
        ;;
    backup)
        shift
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-cli -- backup "$@"
        ;;
    test)
        echo "=== Running tests ==="
        PROTOC=$PROTOC_DIR/protoc cargo test
        ;;
    all)
        echo "=== Starting API + Central ==="
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-api &
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-central &
        echo "API: http://localhost:8080"
        echo "gRPC: localhost:50051"
        wait
        ;;
    help|*)
        cat <<EOF
NKOSI - Antivirus Linux
Usage: $0 <command> [args]

  build     Build all binaries
  api       Start REST API + Dashboard (port 8080)
  central   Start gRPC Central server (port 50051)
  all       Start API + Central together

  cli       Run nkosi-cli with args
  scan      Scan a path (--dry-run available)
  rootkit   Rootkit scan
  kernel    Kernel module scan
  ssh       SSH brute-force scan (--block to block IPs)
  firewall  Firewall management (init/block/unblock/save/load)
  backup    Backup management (create/list/restore/prune)

  test      Run all tests
  help      Show this help

Env vars:
  NKOSI_API_KEYS      API key(s) comma-separated (default: cle123)
  NKOSI_RATE_LIMIT    Requests/sec limit (default: 20)

Examples:
  $0 api
  $0 scan /home --dry-run
  $0 firewall block 1.2.3.4
  $0 ssh --block
  NKOSI_API_KEYS=secret123 $0 api
EOF
        ;;
esac
