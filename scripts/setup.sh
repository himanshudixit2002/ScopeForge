#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
command -v python3 >/dev/null || { echo "Python 3.11 or later is required."; exit 1; }
command -v npm >/dev/null || { echo "Node.js 22.12 or later and npm are required."; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or later is required"'
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install -c backend/requirements.lock -e './backend[dev]'
npm --prefix frontend ci
npm --prefix frontend run build
echo "ScopeForge is ready. Start it with ./scripts/start.sh"
