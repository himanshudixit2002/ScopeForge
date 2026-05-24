# Local verification — 12 September 2026

ScopeForge 0.2 was built and verified locally on macOS with Python 3.14.6 and Node.js 26.5.0. These results describe the local release, not a production security certification or measured distributed capacity.

## Automated checks

- **347 backend tests passed.** Coverage includes scope/parser escapes, policy-reference validation, reserved and mixed DNS answers, address pinning and original TLS hostname, request/read bounds, header-rule fixtures, redaction, authorization expiry/revocation through the request-write boundary, browser request boundaries, request-body limits, durable queue transitions, pacing after TLS handshakes, cancellation, interrupted-job recovery, finding deduplication, triage and report generation.
- **Eight Chromium browser workflows passed.** Demo → synthetic evidence → saved triage → Markdown download → reload persistence; program creation → excluded-path rejection → revocation; keyboard dialog focus and 390px layout; HTTP import → repeated occurrences → preserved triage → redacted report; OpenAPI file import and catalog filtering; manual evidence and program export; atomic batch rejection; oversized file rejection and mobile lab use.
- **TypeScript and Vite production build passed.** The app serves the compiled assets through FastAPI.
- Shell syntax checks and Python dependency consistency check passed.
- The online backup utility was exercised against committed data in a live WAL database. Restored content, integrity, private file permissions and overwrite refusal were verified.

The v0.2 suite additionally covers bounded HTML parsing/reads, CSP policy interactions, form ownership/submit overrides, cookie deduplication, redaction, atomic concurrent batch capacity, stop-all and profile revalidation, zero-network HTTP/OpenAPI imports, secret-free validation errors, OpenAPI inheritance/references/composed schemas, occurrence persistence, manual provenance, program exports, and transactional migration rollback/idempotence.

The actual pre-upgrade database backup was migrated in an isolated temporary copy: one program, two scans, eight findings, and seven audit events were preserved. Finding IDs, notes, status, evidence and created timestamps matched exactly; eight legacy occurrences were created; a second open did not duplicate them; integrity passed. The backup remains untouched for rollback. The actual local database was then upgraded and the same preservation/integrity checks passed before further demo work. The running service reports version 0.2.0 and a running worker. A web-profile synthetic demo produced 23 observations and an OpenAPI example produced two, both with zero target requests. Desktop and mobile screenshots were inspected, with no browser JavaScript errors.

The scanner tests use fixtures, mocks and an owned local HTTP server. No third-party target was scanned. Browser tests use a temporary database that is removed when their local server shuts down.

## Dependency review

No runtime dependencies were added for v0.2. During the initial 0.1 build on the same date, `npm audit` returned zero known vulnerabilities for the installed frontend dependency tree. The [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/) returned no advisory matches for the 21 installed Python application/test dependencies checked. `pip check` found no broken requirements. These are point-in-time package-advisory checks and do not establish absence of unknown vulnerabilities.

Backend direct and transitive versions are recorded in `backend/pyproject.toml` and `backend/requirements.lock`; frontend versions are resolved in `frontend/package-lock.json`. Setup applies the Python constraints and uses `npm ci`.

## Remaining validation boundaries

- Docker is not installed on this machine. The optional Dockerfile and Compose configuration have not been built or run here.
- CI configuration is included; no hosted GitHub Actions run was performed in this task.
- No authorized live public target was supplied, so real-target behavior was tested with controlled transport fixtures. Program permission and finding impact still require the operator's review.
- The suite emits upstream Starlette/httpx and AnyIO deprecation warnings. They do not cause current failures; revisit the test-client dependencies during the next upgrade.
- Production features and their acceptance gates remain proposed in the [delivery plan](DELIVERY-PLAN.md).

To repeat the checks, run `./scripts/check.sh`, then from `frontend/` run `npx playwright install chromium` and `npx playwright test`. Stop the normal app first: browser tests reserve local port 8000 and refuse to reuse an existing service.
