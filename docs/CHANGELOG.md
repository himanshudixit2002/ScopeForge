# ScopeForge changes

## 0.2.0 — 12 September 2026

Expanded the local workbench from 10 header-oriented families to 52 documented check families: 24 headers, 13 static HTML, and 15 OpenAPI design rules. Header/web profiles are explicitly recorded in program permission. Live checks keep one GET per URL, exact-origin scope, public-address pinning, verified TLS, no redirects and bounded reads.

Added offline HTTP/OpenAPI JSON analysis with file input, synthetic examples, zero-network provenance, bounded parsing and no raw-content retention. The live check catalog documents inputs, CWE, severity, references and limitations. It reports actual implemented rules, not promised exploit coverage.

Added atomic batches of up to 20 explicit URLs, a stop-all control, manual findings, first/last-seen timestamps, occurrence snapshots, preserved triage on repeat observations, and program Markdown/JSON exports. Reports distinguish imported evidence, live observations and analyst-entered claims.

Schema 2 migrates previous records transactionally and creates one occurrence for the saved legacy evidence. Existing real programs remain headers-only; synthetic training supports both profiles. A pre-upgrade backup is required for rollback; there is no downgrade migration. Local authorization records do not themselves establish legal permission, and findings remain subject to contextual validation.

The React dashboard, installation scripts, architecture and operations documentation are updated. No additional runtime dependencies or external scanner binaries were needed. See [verification](VERIFICATION.md) for actual test results and unverified deployment boundaries.

## 0.1.0 — Local foundation

Initial React/FastAPI/SQLite application, exact program scope, offline demo, 10 response-header families, durable local queue, finding triage, Markdown drafts, authorization gates, bounded pinned transport, backup command and proposed team-scale architecture.
