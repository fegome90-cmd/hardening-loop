#!/usr/bin/env bash
# Bash completion for hardening-loop CLI

_hardening_loop_completions() {
    local cur prev words cword
    _init_completion || return

    local subcommands="run review"
    local phases="all question delete simplify verify codify"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${subcommands}" -- "$cur") )
        return 0
    fi

    case "${words[1]}" in
        run)
            case "$prev" in
                --target)
                    _filedir
                    return 0
                    ;;
                --phase)
                    COMPREPLY=( $(compgen -W "${phases}" -- "$cur") )
                    return 0
                    ;;
                --output)
                    _filedir -d
                    return 0
                    ;;
            esac
            local opts="--target --phase --output --json --quiet -q -h --help"
            COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
            return 0
            ;;
        review)
            case "$prev" in
                --reviewer|--notes)
                    return 0
                    ;;
            esac
            local opts="--admit --reject --reviewer --notes --json --quiet -q -h --help"
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
            else
                _filedir
            fi
            return 0
            ;;
    esac
}

complete -F _hardening_loop_completions hardening-loop
