#!/usr/bin/env bash
# Bash completion for hardening-loop CLI

_hardening_loop_completions() {
    local cur prev words cword
    _init_completion || return

    local subcommands="run review inspect validate"
    local phases="all question delete simplify verify codify"
    local schemas="evidence_envelope knowledge_candidate work_unit"

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
                --output|--workspace-root)
                    _filedir -d
                    return 0
                    ;;
            esac
            local opts="--target --phase --output --workspace-root --json --quiet -q -h --help"
            COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
            return 0
            ;;
        review)
            case "$prev" in
                --reviewer|--notes)
                    return 0
                    ;;
                --workspace-root)
                    _filedir -d
                    return 0
                    ;;
            esac
            local opts="--admit --reject --reviewer --notes --workspace-root --json --quiet -q -h --help"
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
            else
                _filedir
            fi
            return 0
            ;;
        inspect)
            case "$prev" in
                --workspace-root)
                    _filedir -d
                    return 0
                    ;;
            esac
            local opts="--workspace-root --json --quiet -q -h --help"
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
            else
                _filedir -d
            fi
            return 0
            ;;
        validate)
            case "$prev" in
                --schema)
                    COMPREPLY=( $(compgen -W "${schemas}" -- "$cur") )
                    return 0
                    ;;
                --workspace-root)
                    _filedir -d
                    return 0
                    ;;
            esac
            local opts="--schema --workspace-root --json --quiet -q -h --help"
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
