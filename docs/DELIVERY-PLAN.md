# ScopeForge delivery plan

Build a dependable personal research workflow first, then graduate to a shared platform through explicit gates. Version 0.2 is an expanded local application with a web dashboard; the production capabilities below are planned work. The [architecture](ARCHITECTURE.md) records technology choices and their consequences, and the [API contract](API-CONTRACT.md) is the implementation boundary for this release.

## First user journey

1. **Learn without target traffic.** Start the local application and run the labelled training demo. The seed program and its findings are synthetic. Review a finding, add a note, change its status, and download a draft report. The dashboard must show honest empty states before the demo is run.
2. **Record a real permitted program.** Read its current policy outside the scanner, verify automation is allowed, and enter the policy URL, meaningful authorization note, exact origins, excluded paths, future expiry, and allowed pacing. A policy URL is never an implicit target. Wildcards and inferred subdomains are not accepted in v1.
3. **Choose one ordinary URL.** Start a real HTTP observation for a known permitted page. The UI shows the mode, target, and request boundary. Requests to excluded paths, revoked programs, expired authorization, non-public destinations, or the synthetic program must fail visibly.
4. **Understand the result.** Inspect the checks that ran, request count, timestamps, evidence, and limitations. A successful scan with zero findings means these checks found no observations; it does not establish target security.
5. **Triage before submission.** Use the program's eligibility rules to dismiss irrelevant best-practice warnings, add contextual evidence, and mark a finding validated only after appropriate manual review. Export a draft and submit through the program's chosen channel manually. ScopeForge does not submit reports, contact organizations, or promise a reward.
6. **End or revise permission.** Revoke a program or let authorization expire. Queued real work must be rejected at execution once permission is no longer active. Cancellation prevents further work when observed, but cannot retract an already-sent request.

## Phase 0 — Scope and policy foundation

**Outcome:** A small, auditable boundary for what the application may do. This is part of the v1 release scope.

**Deliverables:** Exact-origin and path validation; authorization metadata and expiry; independent backend validation; separate offline demo; rejection messages that explain the failed boundary; API contract and threat model.

**Acceptance criteria:**

- A new real program cannot be saved without explicit authorization, an explanatory note, scope, future expiry, and pacing.
- HTTPS and HTTP, sibling hosts, and arbitrary ports do not inherit permission from another origin. Credentials, IP targets, wildcards, malformed hosts, unsupported schemes, and unsafe path representations are rejected.
- Encoded-path and origin confusion tests cover the same canonical form used for both authorization and actual requests.
- Demo mode sends zero network requests, including DNS. Real mode rejects the demo origin/program.
- The product makes no statement that a saved declaration guarantees legality or bounty eligibility.

## Phase 1 — Local working release

**Outcome:** The user can move from program scope to observation to reviewed report inside the dashboard. This is the implemented v1 target.

**Deliverables:** React dashboard; FastAPI API and static serving; SQLite persistence; durable queued scans; one bounded HTTP worker; job status and cancellation; conservative finding rules; notes/status changes; audit list; Markdown export; repeatable installation and local start instructions.

**Acceptance criteria:**

- A clean setup follows the README using isolated project dependencies; the built app is served locally and survives a normal restart with saved records intact.
- The offline demo traverses the full program → job → finding → notes/status → export flow, and synthetic labels appear wherever results are displayed or exported.
- A test-controlled transport proves one admitted real scan sends at most its allowed single target GET and never follows redirects. Do not use an unapproved public site as a test fixture.
- DNS answers containing a private or otherwise disallowed address fail before connection. Transport uses the validated address and retains correct hostname verification.
- Authorization is rechecked at execution; revocation, expiry, out-of-scope paths, and cancellation produce visible, consistent states.
- Restart preserves queued work and marks previously running scans failed/interrupted without automatically repeating an ambiguous request. A finding repeated by a later manually requested scan keeps analyst notes/status while updating its current evidence.
- Failed targets, malformed headers, timeout, invalid JSON, and empty responses do not crash the dashboard or leave the user with false success.
- A finding is an observation with explicit limitations. Missing headers do not receive unsupported high-severity or proven-exploit language.
- Backend policy/worker/API tests pass and the TypeScript production build completes. Browser verification covers the full demo journey, validation feedback, reload persistence, keyboard use, and a narrow viewport.

**Release boundary:** Single local user only. No hosted deployment, credentials vault, automatic program discovery, crawler, fuzzing, plugin execution, scheduled fleet, or external report submission.

## Delivered in 0.2

The local application now implements transactional schema upgrades, finding occurrences and recurrence, explicit header/web permissions, 37 header/static-HTML check families, 15 OpenAPI design checks, offline HTTP/OpenAPI JSON imports, manual findings, program Markdown/JSON drafts, atomic batches and stop-all. See [coverage](COVERAGE.md) and [verification](VERIFICATION.md). This delivers part of phase 2 and the offline review portion of phase 4; it does not complete the shared-team or operational gates.

## Phase 2 — Harden the personal research workspace

**Outcome:** Improve research quality, history, and recoverability before expanding network capability.

**Remaining deliverables:** Cursor pagination and complete searchable history; scope revision history; explicit policy acknowledgement timestamps; configured retention; managed backup scheduling and guided restoration; rule-pack versioning and evidence comparison; measured local workload benchmarks. Continue regression coverage for the schema migration, occurrence history, exports, and restricted imports delivered in 0.2.

**Acceptance criteria:**

- Migration tests cover supported old databases, rollback compatibility, interrupted upgrades, and corrupted-input refusal.
- Backup restore produces the expected programs, scan records, findings, and audit history in an isolated location without silently replaying target traffic.
- Sensitive sample tokens, cookies, personal data, and query parameters are removed or masked according to a tested evidence policy before export or telemetry.
- Deduplication uses stable identities with rule and scope context; repeated observations preserve occurrence history rather than overwriting analyst notes.
- Imported files have size/type limits, parse deadlines, and rejection tests; content cannot execute HTML, scripts, commands, or arbitrary deserialization.
- A documented baseline measures database size, p95 list latency, and queue behavior under the local planning workload. This evidence determines pagination/retention defaults.

**Exit condition:** A second maintainer can install, upgrade, restore, explain a failed scan, and produce an accurate report draft from the documentation alone.

## Phase 3 — Shared team pilot

**Outcome:** Multiple researchers work in distinct workspaces with safe execution and durable scheduling. No remote deployment should precede this gate.

**Proposed deliverables:** PostgreSQL; migration tooling; stateless API replicas; dedicated leased workers; shared program/workspace budgets; OIDC; workspace roles; encrypted object evidence; redaction on ingestion; append-only external audit sink; restricted execution; egress proxy; centralized secrets; OpenTelemetry; CI release artifacts; tested restore procedure.

**Acceptance criteria:**

- Workspace A cannot enumerate, view, mutate, enqueue against, export, or download workspace B's records, including guessed IDs and signed object links. Role tests cover both positive and negative access.
- Two workers can race for jobs without simultaneous ownership. Lease expiry, stale completions, process kill, queue replay, acknowledgement loss, and database unavailability have explicit outcomes.
- All attempts share a program request budget. Multiple workspaces cannot accidentally bypass a program-wide ceiling when they reference the same governed target; ownership and budget aggregation rules are documented.
- The real worker runtime cannot reach private, link-local, cloud metadata, control-plane, or arbitrary out-of-scope destinations through direct sockets or proxy bypass. Proxy outage fails closed.
- Cancellation and scope revocation are checked before every new request and retry. Scope revisions and per-attempt decisions can reconstruct why each request was permitted.
- Evidence is private by default; a former workspace member loses access, including expired download links. Key rotation and retention/deletion are exercised.
- Pilot load and restore drills meet the proposed SLOs in the architecture document before those goals are published as an operating commitment.

**Rollout:** Start with synthetic fixtures in staging, then an internally owned authorized target, then a small opt-in team. Use an explicit worker enable switch, small request budgets, canary rule releases, and a global stop control. Increase concurrency only after target impact and queue behavior are reviewed.

## Phase 4 — Advanced analyst workflows

**Outcome:** Improve coverage and analyst productivity with policy-aware capabilities that preserve human review.

**Proposed deliverables:** Versioned rule packs; read-only imports from authorized proxy captures/SARIF; owned OpenAPI inventory and change detection; evidence comparison; program-specific report templates; collaboration and reviewer assignment; optional typed integrations with explicit credentials and scopes. Any future crawler or active verification module is a separately reviewed feature with a declared request budget, permission model, and isolation tests.

**Acceptance criteria:**

- Every integration describes its data access, outbound behavior, maximum work, supported authorization restrictions, and evidence handling. A program can disable it independently.
- A rule update is evaluated against labelled positive and negative fixtures. Track false-positive rate, duplicate rate, and reviewer acceptance; a higher finding count alone is not a success metric.
- An evidence diff states what changed and how it was observed without inflating severity or suggesting an unverified exploit.
- Active verification, if later requested and implemented, requires the corresponding permitted test class. General asset scope does not silently enable invasive testing.
- Reports contain reproducible observations, timestamps, affected scope, actual demonstrated impact, and remediation. The analyst controls final submission and disclosure.

## Phase 5 — Scale on measured demand

**Outcome:** Operate a reliable service at a demonstrated workload, not a theoretical number of targets.

**Proposed deliverables:** Broker/outbox only if needed; autoscaled worker pools bounded by authorization budgets; fair scheduling; regional execution where authorized; resource quotas; partitioning/archival when justified; cost attribution; incident and recovery exercises; optional Kubernetes if the operating team can support it.

**Acceptance criteria:**

- Capacity tests use owned or synthetic infrastructure and include slow targets, bursts, large evidence, retry storms, and one failed dependency.
- Autoscaling responds to eligible queue age while respecting shared rate limits and tenant fairness; adding workers cannot increase a target beyond its authorized budget.
- Database, queue, object store, and identity-provider failures produce controlled degraded states. Restore from a clean environment recovers the agreed data and audit lineage.
- A cost review identifies per-workspace worker time, retained evidence, database load, egress, and telemetry volume. Real provider quotes are collected only when a deployment region and workload are chosen.

## Test strategy

Prioritize the policy and transport boundary because an incorrect allow decision can cause unintended network activity. Unit tests should cover canonical URLs, default ports, IDNA/host validation, credentials, reserved IP classes, mixed A/AAAA answers, encoded exclusions, expiry, and revocation. Use property/fuzz tests for URL transformations as the parser grows.

Contract/API tests cover authorization persistence, mode separation, status transitions, error shape, report export, and same-origin mutation defenses. Worker tests control DNS, clock, socket/HTTP responses, and cancellation so they can assert exactly which connection was attempted without scanning outside the test environment. UI tests focus on the primary demo journey, program form errors, loading/error/empty states, synthetic labels, and evidence rendered as inert text.

Production-only suites add cross-workspace authorization, duplicate delivery, fencing, shared rate-limit races, restoration, migration, untrusted artifact parsing, and sandbox egress tests. Security checks should include dependency review, lockfile reproducibility, secret scanning, and a targeted independent review of policy/transport changes. Validate accessibility with keyboard navigation, visible focus, labels, and contrast. Record actual results in the release rather than marking planned tests as passed.

## Ownership, sequencing, and costs

For v1, one full-stack maintainer can own the app with an independent reviewer concentrating on URL policy and transport. A hosted pilot needs an owner for identity/data isolation, one for worker/network operations, and someone accountable for response and restore drills; these can be roles held by the same people, but must not be unassigned. Estimate calendar dates after reviewing team availability and measured v1 results. Phase gates are more reliable than unsupported delivery dates.

The local release uses the operator's compute and disk and needs no paid cloud service. Hosted cost drivers are API and worker runtime, database availability and backups, evidence size and retention, network egress/proxy traffic, identity provider plans, telemetry volume, and engineering/incident time. There are no fabricated vendor prices in this plan. Request rate is constrained by permission; paying for a larger worker fleet does not justify increasing it.

Success means an authorized researcher can produce fewer unsupported reports, preserve reliable evidence, respect scope changes, and recover their work. Bounty payouts depend on the program, eligibility, novelty, and demonstrated impact; they are not a system SLO.
