# Running ScopeForge

A step-by-step guide to installing, running, configuring and testing ScopeForge on a local machine. For the operating boundary, recovery procedures and release practice, see [operations](OPERATIONS.md).

ScopeForge is a single-user local application. It binds to loopback by design. Do not forward its port or expose it on a LAN.

## 1. Prerequisites

| Requirement | Minimum | Used in CI |
| --- | --- | --- |
| Python | 3.11 | 3.14 |
| Node.js | 22.12 | 24 |
| npm | ships with Node | ships with Node |

Check what you have:

```bash
python3 --version && node --version && npm --version
```

Everything installs inside the project — `.venv/` for Python and `frontend/node_modules/` for Node. Nothing is installed system-wide and no scanning toolkits are required.

## 2. Install

From the repository root:

```bash
./scripts/setup.sh
```

That script is not a black box. It:

1. Verifies `python3` and `npm` exist and that Python is 3.11 or later.
2. Creates `.venv/` if it is missing.
3. Installs the backend from the pinned lockfile: `pip install -c backend/requirements.lock -e './backend[dev]'`.
4. Installs frontend dependencies with `npm ci` (exact lockfile versions).
5. Builds the production dashboard into `frontend/dist/`.

It is safe to re-run. Installation contacts PyPI and the npm registry; it does not contact any scan target.

## 3. Start

```bash
./scripts/start.sh
```

Then open **http://127.0.0.1:8000**.

`start.sh` sets `umask 077` so new files are private, re-runs setup automatically if `.venv/` or `frontend/dist/` is missing, and launches Uvicorn bound to `127.0.0.1:8000` with a single worker. Stop it with `Ctrl+C`.

Records persist in `data/scopeforge.sqlite3` between runs.

### Confirm it is healthy

```bash
curl -s http://127.0.0.1:8000/api/health
```

Expected:

```json
{"status":"ok","version":"0.2.0","mode":"local","worker":"running"}
```

`worker` reports the background scan thread. If it is not `running`, no queued scan will progress.

### First thing to try

Choose **Explore demo** in the dashboard. It exercises the full scan-to-report workflow against synthetic response fixtures — no target connection, no DNS lookup. Every demo finding is labelled synthetic.

Do not point ScopeForge at a real target until you have read [the assessment workflow in the README](../README.md#a-real-assessment) and confirmed the program's policy permits automated GET requests.

## 4. Configuration

Both settings are environment variables. There is no config file.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCOPEFORGE_DB` | `data/scopeforge.sqlite3` | Database path, relative to the repository root. |
| `SCOPEFORGE_FRONTEND_DIR` | `./frontend/dist` | Directory of built dashboard assets. |

Keep separate engagements in separate databases:

```bash
SCOPEFORGE_DB=data/assessment.sqlite3 ./scripts/start.sh
```

Reuse that same value for every later start, backup and restore, or you will silently open a different database. Run exactly one application process per database file, keep `--workers 1`, and never place the database on NFS or a sync folder — see [operations](OPERATIONS.md#supported-local-deployment) for why.

### Ports

| Port | Used by | Notes |
| --- | --- | --- |
| 8000 | Backend and built dashboard | Also used by the browser test server |
| 5173 | Vite dev server | `strictPort` — fails rather than shifting |
| 4173 | `npm run preview` | `strictPort` |

## 5. Development mode

Use this when editing frontend source and you want hot reload. Two terminals, both from the repository root.

Terminal 1 — backend:

```bash
.venv/bin/python -m uvicorn scopeforge.main:app --host 127.0.0.1 --port 8000 --workers 1
```

Terminal 2 — frontend dev server:

```bash
npm --prefix frontend run dev
```

Open **http://127.0.0.1:5173**. Vite proxies `/api` to the backend on port 8000, so both must be running.

The Vite dev server is a development tool, not a way to expose the workspace remotely.

For backend-only changes, the built dashboard on port 8000 is enough. After changing frontend source and wanting it served from port 8000, rebuild and restart the backend:

```bash
npm --prefix frontend run build
```

## 6. Tests

### Backend and production build

```bash
./scripts/check.sh
```

Runs the backend suite (**347 tests**) and the production frontend build. Takes a few seconds.

### Browser end-to-end

**Stop the running app first.** The e2e server reserves port 8000 with a disposable temporary database and refuses to reuse an existing service.

```bash
cd frontend
npx playwright install chromium
npx playwright test
```

**8 tests** across `e2e/workbench.spec.ts` and `e2e/research.spec.ts`, covering scope recording, excluded-URL rejection, permission revocation, the research lab, and mobile layout with keyboard dialog navigation.

Browser tests use offline fixtures against an isolated local server. Neither the tests nor setup scans any third-party target.

## 7. Optional: container

Docker is not required for local use.

```bash
docker compose up --build
```

Compose publishes port 8000 on `127.0.0.1` only, runs as non-root uid 10001, drops all capabilities, sets `no-new-privileges`, mounts the root filesystem read-only with a 16 MB tmpfs, and persists `/app/data` in the named volume `scopeforge-data`.

Note that the container image sets `SCOPEFORGE_DB=/app/data/scopeforge.sqlite3`, so container data lives in that volume and is separate from your host `data/` directory. The container configuration has not been build-verified on a machine with Docker.

## 8. Backups

```bash
.venv/bin/python scripts/backup.py backups/scopeforge-backup.sqlite3
```

Uses SQLite's online backup API so it is safe while the app is running, runs `PRAGMA integrity_check`, creates the file with `0600` permissions, and refuses to overwrite an existing destination. It reads `SCOPEFORGE_DB` when set.

Never copy the `.sqlite3` file alone while the app is running — committed data may still be in the WAL sidecar. Backups contain authorization records, target details and findings; protect them like the working directory. Restore only while the server is stopped, following [operations](OPERATIONS.md#backup-and-restore).

## 9. Troubleshooting

**`Address already in use` on start.** Something already holds port 8000 — often a previous ScopeForge or a stopped-but-not-exited e2e server. Find and stop it:

```bash
lsof -nP -iTCP:8000 -sTCP:LISTEN
```

**Dashboard shows JSON instead of the UI.** The response `{"application":"ScopeForge","message":"Build the frontend to serve the dashboard here..."}` means `frontend/dist/index.html` is missing. Rebuild:

```bash
npm --prefix frontend run build
```

**Vite fails instead of picking another port.** Both `dev` and `preview` use `strictPort`, so a busy 5173 or 4173 is a hard failure. Free the port rather than changing the proxy expectation.

**`.venv` has the wrong Python.** Upgrading system Python leaves a stale virtual environment. Remove and rebuild it:

```bash
rm -rf .venv && ./scripts/setup.sh
```

**`npm ci` fails on lockfile mismatch.** `npm ci` requires `package-lock.json` to match `package.json` exactly. Do not switch to `npm install` to work around it — that silently changes pinned versions.

**Scans stay queued.** Check that `/api/health` reports `"worker":"running"`. A single slow DNS or HTTP operation occupies the one worker; DNS waits 5 seconds and the request deadline is 10 seconds.

**A job fails policy validation.** Review the program origin, scheme, excluded paths, authorization state and expiry. Private DNS answers are rejected deliberately. Correct the scope record only when the real program permission supports it — never weaken transport checks to reach a target.

## 10. Stopping

`Ctrl+C` in the terminal running `start.sh`. Queued jobs survive the restart; jobs that were mid-flight are marked `failed` with an interruption warning and are not replayed automatically. Review those before scheduling new work — a request may have reached a target even when its result could not be saved.
