#!/usr/bin/env bash
set -eu
AUDIT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export INSOMNIA_DATA_PATH="$AUDIT_DIR/.insomnia-a01"
export INSOMNIA_DISABLE_AUTOMATIC_UPDATES=1
exec /usr/bin/insomnia
