#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.11+ is required.'
    if command -v apt-get >/dev/null 2>&1; then
        printf '%s' 'Install python3, python3-venv and python3-pip with apt-get? [y/N] '
        read -r answer
        case "$answer" in
            y|Y|yes) sudo apt-get update && sudo apt-get install python3 python3-venv python3-pip ;;
            *) exit 2 ;;
        esac
    else
        printf '%s\n' 'Install Python 3.11+, venv and pip using your package manager, then restart.'
        exit 2
    fi
fi
exec python3 bootstrap.py
