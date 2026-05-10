# ScopeForge local operations and production readiness

Use the repository [README](../README.md) for prerequisites. From the repository root, run `./scripts/setup.sh`, then `./scripts/start.sh` and open `http://127.0.0.1:8000`. This document covers the operating boundary, recovery, and the checks needed before any future shared deployment. The architecture is intentionally one local application process with one worker thread and SQLite WAL.

## Supported local deployment

Run under your normal unprivileged OS account and bind the application to loopback. Use the project's Python virtual environment and npm lockfile so setup does not alter system Python or require installing scanning toolkits. The packaged frontend is static; FastAPI serves it with the API. The Vite development server is for development, not a way to expose the workspace remotely.

The default database is `data/scopeforge.sqlite3`, relative to the repository root. Set `SCOPEFORGE_DB` to use another path, for example `SCOPEFORGE_DB=data/assessment.sqlite3 ./scripts/start.sh`. Retain that setting for backup, restore, and subsequent starts so you do not accidentally open a different database.

Keep exactly one application process for a database. Do not increase `--workers` beyond `1`, place the SQLite file on NFS or a network/synchronization mount, or run several app copies against the same database. A background thread is started by the application process, and its state does not become a distributed scheduler merely by running more ASGI processes. [FastAPI process model](https://fastapi.tiangolo.com/deployment/concepts/), [SQLite WAL restrictions](https://www.sqlite.org/wal.html).

The local request marker is not authentication. Do not forward the port publicly or share it over a LAN. The team-hosting design requires identity, workspace access control, isolated workers, and egress enforcement before it is supported. Protect the machine with an OS login and disk encryption; the application database and exported reports do not have their own encryption or per-user permissions.

Before a real check, use a program with current, explicit authorization and select one ordinary URL that permits automated GET requests. Inspect exclusions and expiry. A demo is suitable for checking the application without any target network activity. GET mode is low-impact but still sends a request; it does not establish that every selected endpoint is side-effect free.

## Day-to-day checks

- Open the dashboard and confirm it can load the saved programs and job history. `/api/health` reports basic application/worker status; this is not a probe of every target, database recovery guarantee, or readiness check for a hosted deployment.
- Review failed and cancelled jobs and their error messages before retrying. Authorization, excluded paths, DNS denial, and expiry are policy failures to resolve, not reasons to bypass validation.
- Observe request pacing and the actual program policy. Avoid repeated clicks creating duplicate work; the local release does not promise cross-request admission idempotency.
- Treat evidence and notes as private program data. Review downloaded Markdown before sharing, particularly URLs, cookies, headers, or identifiers.
- Revoke old programs when work ends. After an abnormal shutdown, inspect queued/running history before scheduling new real work. A request may have reached a target even when its result could not be saved.

Startup preserves queued jobs and marks previously running jobs `failed` with an interruption warning. It does not automatically replay those ambiguous attempts. Review a failed job before manually starting another scan. Pacing reservations persist across restarts, and `requests_made` counts a reserved attempt even if connection or TLS fails before a GET reaches the target. A repeated scan or import may refresh an existing finding; analyst notes/status are preserved and a sanitized occurrence snapshot is appended. The history viewer shows the latest 100. A missing observation does not automatically resolve a finding.

## Offline research and input handling

In **Research lab**, choose the evidence program and exact URL, select HTTP capture or OpenAPI JSON, and paste or select a file up to 256 KiB. Loading a synthetic example selects the training program. Imported documents cause zero target requests or DNS lookups. A successful result records selected observations and summary metadata; it does not save the original capture or prove deployed behavior. Keep an authorized original separately when needed for reproduction. Clear the editor when finished.

OpenAPI accepts JSON 3.0/3.1/3.2, not YAML. Review warnings for unresolved references, complex schemas, and parser bounds. HTTP imports expect a JSON status, name/value header array and optional body, not a HAR or raw HTTP transcript. Manual findings are stored as entered: remove credentials and personal information before saving and exporting. Program JSON bundles include the program’s authorization record and findings; review both before sharing.

**Stop all active** cancels queued/running scans across the local workspace. Program revocation cancels that program’s queued/running work and blocks subsequent live/import/manual admissions. Neither action can undo a GET already sent or a completed analysis.

## Backup and restore

The local release does not provide a managed backup service. Choose a backup location protected like the original findings and outside the live database directory. Define a retention policy appropriate to the program. A proposed personal target is a daily backup and a restore drill before relying on the database for important work; this is an operating practice to establish, not an automatic guarantee.

A live WAL database may have committed data in its WAL file. Do not copy only the main database file while the app is running. Use SQLite's online backup facility through `sqlite3.Connection.backup`, or stop the application and preserve a consistent database state. Python documents a backup API that can copy a database while it is being accessed. [Python SQLite backup](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup).

The shipped [backup script](../scripts/backup.py) uses that API, creates a private destination, runs `PRAGMA integrity_check`, and refuses to overwrite an existing file. From the repository root, choose a new backup filename:

```bash
.venv/bin/python scripts/backup.py backups/scopeforge-2026-09-12.sqlite3
```

It reads `SCOPEFORGE_DB` when set, otherwise the default path. To name the source explicitly, use `.venv/bin/python scripts/backup.py backups/assessment-2026-09-12.sqlite3 --database data/assessment.sqlite3`. Backup scheduling and guided restoration are future work; running the app does not automatically run this script.

To restore, stop the application, preserve the existing data directory unchanged, and restore into a new isolated data location. Use a compatible application version and verify integrity, record counts, and a sample exported finding before switching the normal startup configuration. Prevent target traffic during a restore drill because restored queued work may otherwise become eligible on startup. Preserve the pre-restore copy until the restored dataset has been verified. Never combine a restored database with stale `-wal` or `-shm` sidecars from another state.

Keep backup instructions alongside the actual configuration path and application version. A report download is not a complete database backup. A successful integrity check detects structural issues but does not prove that every expected record or external artifact is present.

## Failure handling

**App does not start:** Confirm the intended virtual environment, supported runtime, built frontend, port availability, and database-directory permissions. Read the error without pasting private evidence into a public issue. Re-run the documented setup/build steps only for the relevant dependency or asset failure.

**Job fails policy validation:** Review the exact program origin, scheme, excluded path, authorization state, and expiry. A private DNS answer is intentionally rejected. Fix the scope record only when the actual program permission supports the change; do not weaken transport checks to make a target reachable.

**Job seems stalled:** Check worker health and target timeout/error status. A slow DNS or network operation can occupy the single worker. Cancel queued work when appropriate; cancellation cannot retract a request in flight. Avoid starting a second process as a workaround. Preserve the database before investigating a repeated crash.

The DNS result wait is 5 seconds and the HTTP request deadline is 10 seconds. An underlying OS resolver call can outlive its timeout in the two-thread resolver pool; its late result is not used. Response reads are capped at 256 KiB. The permitted web profile inspects at most 128 KiB of uncompressed HTML/XHTML in memory, and saves no raw body. Redirects are not followed or analyzed as HTML. Compressed, non-HTML, and ambiguous content types skip body rules. A failed DNS/IP validation should not be retried through an insecure fallback.

**Disk is full or SQLite is busy:** Stop creating new jobs, preserve recoverable data, and inspect disk use and extra running app instances. Do not delete WAL files to free space. Use a supported backup and controlled retention process; repeated busy errors are a signal to revisit concurrency or graduate the deployment.

**Unexpected target activity:** Revoke the affected program, cancel pending jobs, and stop the local application if immediate containment is needed. Record the scan IDs, timestamps, policy state, and observed request counts. Preserve local evidence, determine the cause, and follow the program's incident/disclosure channel when required by its rules. The application does not contact anyone automatically.

## Upgrade and rollback practice

Before an upgrade, finish/cancel work, back up data, note the application revision, and retain the previous runnable version. Install from the project lockfiles, run the backend checks and frontend build, then verify the demo workflow. Version 0.2 upgrades schema 0/1 to 2 in one transaction, preserves records and notes, and seeds occurrence history from the latest saved legacy observation. Existing real programs retain headers-only permission; the synthetic program gains both profiles. Unsupported newer schemas are refused. There is no downgrade migration: rollback requires the prior runnable application and a pre-upgrade backup in a separate data location. Do not open a schema-2 database with 0.1.

`./scripts/check.sh` runs the backend suite and production frontend build. Browser workflow verification is documented separately in the README. An optional non-root Dockerfile and Compose configuration publish only to host loopback and persist `/app/data` in a named volume. Docker was unavailable in the implementation environment, so the container configuration has not been build/run verified. Its container packaging does not provide the proposed isolated target-worker/egress architecture.

For a production pilot, use immutable versioned builds, staging with synthetic/owned targets, migration dry runs, a canary API/worker release, and a documented stop/rollback path. Keep scan admission disabled until database, policy, worker, egress, and identity readiness checks pass. A rollback that changes worker versions must also account for queued job and rule schema compatibility.

## Required production work

The following is proposed readiness work, not functionality in the local release:

- OIDC login, workspace roles, per-object authorization, secure session handling, and account offboarding.
- PostgreSQL migrations, short transactions, leased jobs with fencing, idempotent results, shared budgets, fair scheduling, and dead-letter review.
- Worker isolation, network-denial tests, validated egress proxy, secret management, and a stop control effective across workers.
- Encrypted evidence objects, redaction before ingestion, export access logging, retention, key recovery/rotation, and deletion workflows.
- Structured telemetry, privacy-safe trace correlation, queue/lease alerts, capacity tests, and an assigned on-call owner.
- Database base backups plus archived WAL, protected configuration/secrets backups, object-version retention, and restore drills into an isolated environment. PostgreSQL's recovery guidance requires the associated WAL sequence; a logical dump alone does not provide point-in-time recovery. [PostgreSQL recovery](https://www.postgresql.org/docs/current/continuous-archiving.html).

Do not describe the system as production-ready until the [team pilot acceptance criteria](DELIVERY-PLAN.md#phase-3--shared-team-pilot) are demonstrated and the resulting limitations are documented.
