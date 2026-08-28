#!/usr/bin/env bash
set -euo pipefail

PROJ_DIR="/home/clodlin/NKOSI"
PROTOC_DIR="/tmp/protoc/bin"
RUN_DIR="${NKOSI_RUN_DIR:-/tmp/nkosi-run}"
LOG_DIR="${NKOSI_LOG_DIR:-/tmp/nkosi-logs}"

export PATH="$PROTOC_DIR:$PATH"
export NKOSI_API_KEYS="${NKOSI_API_KEYS:-cle123}"
export NKOSI_RATE_LIMIT="${NKOSI_RATE_LIMIT:-20}"

mkdir -p "$RUN_DIR" "$LOG_DIR"
cd "$PROJ_DIR"

CENTRAL_BIND="${NKOSI_CENTRAL_BIND:-0.0.0.0:50051}"
CENTRAL_ADDR="${NKOSI_CENTRAL_ADDR:-127.0.0.1:50051}"
CONSOLE_BIND="${NKOSI_CONSOLE_BIND:-0.0.0.0:9090}"

# Composeurs de l'écosystème complet : nom -> (binaire, description, port)
services() {
    cat <<'EOF'
agent    nkosi-agent     Agent de protection locale (moniteurs + moteurs)  -
central  nkosi-central   Serveur central gRPC multi-serveurs               50051
console  nkosi-console   Console web centralisée multi-serveurs            9090
api      nkosi-api       API REST + dashboard local                        8080
EOF
}

# Reserved words: ne pas traiter ces sous-commandes comme noms de service
_reserved() {
    case "$1" in
        build|list|start|stop|restart|status|logs|all|test|help) return 0 ;;
        *) return 1 ;;
    esac
}

is_running() {
    [ -f "$RUN_DIR/$1.pid" ] && kill -0 "$(cat "$RUN_DIR/$1.pid")" 2>/dev/null
}

start_one() {
    local svc="$1"
    local bin meta desc port
    meta="$(services | awk -v s="$svc" '$1==s')"
    [ -n "$meta" ] || { echo "Service inconnu: $svc"; return 1; }
    bin=$(echo "$meta" | awk '{print $2}')
    desc=$(echo "$meta" | awk '{for(i=3;i<NF;i++)printf "%s ",$i}')
    port=$(echo "$meta" | awk '{print $NF}')

    if is_running "$svc"; then
        echo "[$svc] déjà en cours d'exécution (pid $(cat "$RUN_DIR/$svc.pid"))"
        return 0
    fi

    local exe="$PROJ_DIR/target/debug/$bin"
    if [ ! -x "$exe" ]; then
        echo "[$svc] binaire absent ($exe) — lancez d'abord 'build'"
        return 1
    fi

    local logfile="$LOG_DIR/$svc.log"
    case "$svc" in
        central) env RUST_LOG=info NKOSI_CENTRAL_BIND="$CENTRAL_BIND" setsid "$exe" >>"$logfile" 2>&1 & ;;
        console) env RUST_LOG=info NKOSI_CENTRAL_ADDR="$CENTRAL_ADDR" NKOSI_CONSOLE_BIND="$CONSOLE_BIND" setsid "$exe" >>"$logfile" 2>&1 & ;;
        api)     env RUST_LOG=info setsid "$exe" >>"$logfile" 2>&1 & ;;
        agent)   env RUST_LOG=info NKOSI_CENTRAL_ADDR="${NKOSI_AGENT_CENTRAL_ADDR:-$CENTRAL_ADDR}" setsid "$exe" >>"$logfile" 2>&1 & ;;
    esac

    echo "$!" > "$RUN_DIR/$svc.pid"
    echo "[$svc] démarré (pid $(cat "$RUN_DIR/$svc.pid")) — logs: $logfile"
    if [ "$port" != "-" ]; then
        echo "        → http://localhost:$port"
    fi
    sleep 1
}

stop_one() {
    local svc="$1"
    if is_running "$svc"; then
        kill "$(cat "$RUN_DIR/$svc.pid")" 2>/dev/null || true
        rm -f "$RUN_DIR/$svc.pid"
        echo "[$svc] arrêté"
    else
        rm -f "$RUN_DIR/$svc.pid"
        echo "[$svc] non en cours d'exécution"
    fi
}

status_one() {
    local svc="$1"
    local meta port
    meta="$(services | awk -v s="$svc" '$1==s')"
    port=$(echo "$meta" | awk '{print $NF}')
    if is_running "$svc"; then
        echo "● $svc — en cours (pid $(cat "$RUN_DIR/$svc.pid"))${port:+\tport $port}"
    else
        echo "○ $svc — arrêté"
    fi
}

status_all() {
    echo "État des services NKOSI :"
    for s in central console api agent; do
        status_one "$s"
    done
}

logs() {
    local svc="${1:-}"
    if [ -n "$svc" ]; then
        tail -f "$LOG_DIR/$svc.log" 2>/dev/null || echo "Pas de log pour $svc"
    else
        echo "logs disponibles:"
        ls -1 "$LOG_DIR"/*.log 2>/dev/null || echo "aucun"
    fi
}

case "${1:-help}" in
    build)
        echo "=== Building NKOSI (écosystème complet) ==="
        PROTOC=$PROTOC_DIR/protoc cargo build --workspace
        echo "Build OK"
        ;;
    list)
        echo "Composants de l'écosystème NKOSI :"
        services | while read -r name bin desc port; do
            [ -n "$name" ] || continue
            printf "  %-9s %-13s %s\n" "$name" "$bin" "$(echo "$desc" | sed "s/ $port$//")"
        done
        ;;

    start)
        shift
        if [ $# -eq 0 ]; then
            echo "Démarrage de tout l'écosystème (central, console, api, agent)…"
            for s in central console api agent; do start_one "$s"; done
            echo "---"
            status_all
            echo
            echo "Consoles: centralisée http://localhost:9090 · local http://localhost:8080"
        else
            for s in "$@"; do
                _reserved "$s" && { echo "Usage: start <central|console|api|agent>"; break; }
                start_one "$s"
            done
        fi
        ;;

    stop)
        shift
        if [ $# -eq 0 ]; then
            echo "Arrêt de tout l'écosystème…"
            for s in agent api console central; do stop_one "$s"; done
        else
            for s in "$@"; do stop_one "$s"; done
        fi
        ;;

    restart)
        shift
        if [ $# -eq 0 ]; then
            set -- central console api agent
        fi
        for svc in "$@"; do
            stop_one "$svc"
            start_one "$svc"
        done
        ;;

    status)
        status_all
        ;;

    logs)
        shift
        logs "${1:-}"
        ;;

    # --- sous-commandes directes existantes (amuse-gueule) ---
    api)
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-api
        ;;
    central)
        PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-central
        ;;
    console)
        inext="${NKOSI_CENTRAL_ADDR:-127.0.0.1:50051}"
        NKOSI_CENTRAL_ADDR="$inext" PROTOC=$PROTOC_DIR/protoc cargo run -p nkosi-console
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
        PROTOC=$PROTOC_DIR/protoc cargo test
        ;;
    all)
        echo "=== Démarrage de tout l'écosystème ==="
        start_one central
        start_one console
        start_one api
        start_one agent
        status_all
        ;;

    help|*)
        cat <<EOF
NKOSI - Antivirus Linux — Gestion de l'écosystème

  build              Builder tous les composants
  list               Lister les composants de l'écosystème

  start [composants] Démarrer tout l'écosystème (par défaut)
                     ou seulement les composants cités
                     ex: start central console
  stop [composants]  Arrêter tout (ou composants cités)
  restart [comps]    Redémarrer
  status             État de tous les services
  logs [composant]   Suivre les logs

  Composants:
    central   serveur gRPC multi-serveurs   (port 50051)
    console   console web centralisée        (port 9090)
    api       API REST + dashboard local     (port 8080)
    agent     agent de protection locale

  CLI / scans (mode interactif, sans daemon):
    cli <args>   scan <path>   rootkit   kernel
    ssh [--block]   firewall <cmd>   backup <cmd>

  test    lancer les tests

Env:
  NKOSI_CENTRAL_BIND    adresse du central (défaut 0.0.0.0:50051)
  NKOSI_CENTRAL_ADDR    adresse vue par la console (défaut 127.0.0.1:50051)
  NKOSI_CONSOLE_BIND    adresse de la console (défaut 0.0.0.0:9090)
  NKOSI_API_KEYS        clé(s) API (défaut cle123)
  NKOSI_RATE_LIMIT      limite req/s (défaut 20)

Exemples:
  $0 build && $0 start
  $0 start central console
  $0 status
  $0 logs console
  $0 stop
EOF
        ;;
esac
