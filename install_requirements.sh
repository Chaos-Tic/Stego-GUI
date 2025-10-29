#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ_FILE="${SCRIPT_DIR}/requirements.txt"

if [[ ! -f "${REQ_FILE}" ]]; then
    echo "Fichier requirements.txt introuvable dans ${SCRIPT_DIR}" >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "Cette installation automatique nécessite apt-get." >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "Merci d'exécuter ce script avec sudo : sudo $0" >&2
    exit 1
fi

apt-get update
xargs -a "${REQ_FILE}" -r apt-get install -y
