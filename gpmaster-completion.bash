# Bash completion for gpmaster
# Install: source this file or copy to /etc/bash_completion.d/

_gpmaster() {
    local cur prev words cword
    _init_completion || return

    local commands="create add get rename delete dump info note validate rekey"
    local global_opts="-l --lockbox -q --quiet -h --help"

    # If we're at the first argument position (after gpmaster)
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands $global_opts" -- "$cur") )
        return 0
    fi

    # Find the command (skip global options)
    local cmd=""
    local i
    for ((i=1; i < cword; i++)); do
        case "${words[i]}" in
            -l|--lockbox)
                ((i++))
                ;;
            -q|--quiet)
                ;;
            create|add|get|rename|delete|dump|info|note|validate|rekey)
                cmd="${words[i]}"
                break
                ;;
        esac
    done

    # Complete based on the command
    case "$cmd" in
        create)
            # Complete GPG key IDs
            if [[ $cword -eq $((i + 1)) ]]; then
                local keys=$(gpg --list-keys --with-colons 2>/dev/null | awk -F: '/^pub/ {print $5}')
                COMPREPLY=( $(compgen -W "$keys" -- "$cur") )
            fi
            ;;
        add)
            case "$prev" in
                --key-id)
                    local keys=$(gpg --list-keys --with-colons 2>/dev/null | awk -F: '/^pub/ {print $5}')
                    COMPREPLY=( $(compgen -W "$keys" -- "$cur") )
                    ;;
                add)
                    COMPREPLY=( $(compgen -W "--totp --key-id" -- "$cur") )
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=( $(compgen -W "--totp --key-id" -- "$cur") )
                    fi
                    ;;
            esac
            ;;
        get)
            case "$prev" in
                get)
                    # Complete secret names from lockbox
                    _gpmaster_complete_secrets
                    ;;
                *)
                    if [[ "$cur" == -* ]]; then
                        COMPREPLY=( $(compgen -W "--totp-code" -- "$cur") )
                    else
                        _gpmaster_complete_secrets
                    fi
                    ;;
            esac
            ;;
        rename)
            if [[ $cword -eq $((i + 1)) ]]; then
                # Complete old name
                _gpmaster_complete_secrets
            fi
            ;;
        delete)
            if [[ $cword -eq $((i + 1)) ]]; then
                # Complete secret name
                _gpmaster_complete_secrets
            fi
            ;;
        rekey)
            if [[ $cword -eq $((i + 1)) ]]; then
                # Complete new GPG key ID
                local keys=$(gpg --list-keys --with-colons 2>/dev/null | awk -F: '/^pub/ {print $5}')
                COMPREPLY=( $(compgen -W "$keys" -- "$cur") )
            fi
            ;;
        info|note|validate)
            # These commands have no additional arguments
            COMPREPLY=()
            ;;
        *)
            # No command yet, show global options and commands
            COMPREPLY=( $(compgen -W "$commands $global_opts" -- "$cur") )
            ;;
    esac

    return 0
}

# Helper function to complete secret names from the lockbox
_gpmaster_complete_secrets() {
    local lockbox_path="${GPMASTER_LOCKBOX_PATH:-$HOME/.local/state/gpmaster.gpb}"

    # Check if --lockbox option was specified
    local i
    for ((i=1; i < cword; i++)); do
        if [[ "${words[i]}" == "-l" || "${words[i]}" == "--lockbox" ]]; then
            lockbox_path="${words[i+1]}"
            break
        fi
    done

    # Try to get secret names from the lockbox
    if [[ -f "$lockbox_path" ]]; then
        local secrets=$(gpmaster -l "$lockbox_path" info 2>/dev/null | sed -n '/^Secrets/,/^$/p' | grep '^\s\+' | awk '{print $1}')
        COMPREPLY=( $(compgen -W "$secrets" -- "$cur") )
    fi
}

# Register the completion function
complete -F _gpmaster gpmaster
