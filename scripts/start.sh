#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
umask 077
if [[ ! -x .venv/bin/python || ! -f frontend/dist/index.html ]]; then
  "$PROJECT_DIR/scripts/setup.sh"
fi
echo "ScopeForge dashboard: http://127.0.0.1:8000"
echo "Local data: ${SCOPEFORGE_DB:-data/scopeforge.sqlite3}"
exec .venv/bin/python -m uvicorn scopeforge.main:app --host 127.0.0.1 --port 8000 --workers 1
