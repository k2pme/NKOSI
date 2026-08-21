_nkosi() {
    local cur prev commands firewall_cmds quarantine_cmds backup_cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    commands="status scan quick full rootkit integrity kernel ssh firewall quarantine backup update logs process network"
    firewall_cmds="status init flush block unblock whitelist unwhitelist ratelimit save load"
    quarantine_cmds="list restore delete purge"
    backup_cmds="create restore list prune"
    
    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- $cur) )
        return 0
    fi
    
    case "${COMP_WORDS[1]}" in
        firewall)
            COMPREPLY=( $(compgen -W "$firewall_cmds" -- $cur) )
            ;;
        quarantine)
            COMPREPLY=( $(compgen -W "$quarantine_cmds" -- $cur) )
            ;;
        backup)
            COMPREPLY=( $(compgen -W "$backup_cmds" -- $cur) )
            ;;
        scan)
            COMPREPLY=( $(compgen -f -- $cur) )
            ;;
        process)
            COMPREPLY=( $(compgen -W "$(ps -e --no-headers -o pid)" -- $cur) )
            ;;
        ssh)
            COMPREPLY=( $(compgen -W "--threshold --block-threshold --block -t -b -B" -- $cur) )
            ;;
        integrity)
            COMPREPLY=( $(compgen -W "--baseline -b" -- $cur) )
            ;;
    esac
}

complete -F _nkosi nkosi
