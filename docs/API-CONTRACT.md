# ScopeForge 0.2 API contract

Local base `/api`, snake_case JSON, UTC ISO timestamps. The served machine-readable schema is `/api/openapi.json`. Mutations require `X-ScopeForge-Client: dashboard`; this is a browser boundary marker, not authentication. Host must be localhost/127.0.0.1; same-origin requests and explicit loopback Vite development origins are supported. Keep the service bound to loopback.

Errors use `{"detail":"message"}` or a sanitized validation array (location/message/type, no rejected input). Scope/validation: 422; request boundary: 400/403/408/413; missing record: 404; full queue: 429. Default request cap is 32 KiB and five seconds to receive the body. `/imports/analyze` permits a 1 MiB JSON envelope with imported `content` limited to 256 KiB UTF-8. No filesystem path inputs or URL fetching.

## Programs and scope

- `GET /health`: `{status,version:"0.2.0",mode:"local",worker}`.
- `GET /overview`: program/asset/open-finding/completed-scan counts, severity totals, recent scans/findings.
- `GET /programs`: program array.
- `POST /programs` → 201: `{name,policy_url,authorization_note,scope_origins,excluded_paths,request_interval_ms,authorization_expires_at,authorized:true,allowed_profiles?:["headers"]}`. Profiles are unique `headers|web`, at least one. Only exact HTTP/HTTPS origins at default ports; no wildcards, IP targets or scope inference from policy URL. Request interval 1,000–60,000 ms; expiry must be future. Reference URLs are stored, never fetched automatically.
- `POST /programs/{id}/revoke`: updated program; cancels queued/running work and prevents subsequent live/import/manual analysis.
- `GET /assets`: explicitly recorded program origins.
- `GET /programs/{id}/report?format=markdown|json`: local program findings bundle; JSON additionally includes the full program permission record. Review before sharing.

Program fields include ID, name, policy/authorization record, origins, exclusions, interval, expiry, allowed profiles, authorized/demo flags and created timestamp. Expanding an existing program’s live profile permission requires a new record; there is no program editing endpoint.

## Scans

- `GET /scans`: latest 500.
- `GET /scans/{id}`: one scan.
- `POST /scans` → 202: `{program_id,target_url,mode:"demo"|"passive",profile?:"headers"}`. `passive` is the historical API name for one actual GET. `web` additionally analyzes bounded static HTML. Demo sends no network traffic.
- `POST /scans/batch` → 202: `{program_id,target_urls:[1..20 distinct URLs],profile?:"headers"}`; returns `{scans,submitted,request_budget}`. Real program only, all-or-none admission under the 100 active-job cap. Canonical duplicates, any excluded/out-of-scope URL or permission failure reject the whole batch.
- `POST /scans/{id}/cancel`: updated scan.
- `POST /scans/cancel-all`: `{program_id?:string}` → `{cancelled:number}`.

Scan fields: ID, program ID/name, target, mode (`demo|passive|import|manual`), status (`queued|running|completed|failed|cancelled`), profile, source (`scan|http-import|openapi|manual`), timestamps, requests_made, findings_count, error, executed check IDs and analysis summary. Only `demo|passive` can enter the network queue. Imports/manual entries are completed zero-request records. A request count represents reserved attempts, not proof of remote receipt. Cancellation cannot retract a sent GET.

## Offline analysis and rules

- `GET /checks`: implemented definition array `{id,title,category,profiles,severity,cwe,description,limitations,reference_url}`. 52 families in 0.2, no duplicated OpenAPI entries.
- `POST /imports/analyze` → 201: `{program_id,target_url,format:"http"|"openapi",content:string}`; returns `{scan,findings_count,warnings}`. This does not contact targets, DNS, references or subresources. Scope and current authorization are checked at admission and commit. Demo remains synthetic. Raw input is not saved or echoed in validation errors.

See [coverage](COVERAGE.md) for JSON formats, schema/reference limits, and skipped-analysis behavior. Do not infer deployed runtime behavior from an imported document.

## Findings and reports

- `GET /findings`: latest 2,000.
- `POST /findings` → 201: `{program_id,target_url,title,severity,confidence,description,impact,remediation,evidence,cwe?,notes?}`. Creates an analyst-entered record and associated completed zero-request scan. Scope/expiry/revocation apply; demo remains synthetic. Manual evidence is retained as supplied.
- `PATCH /findings/{id}`: `{status:"open"|"validated"|"dismissed"|"reported",notes?:string}`. This only records triage; it submits nothing externally.
- `GET /findings/{id}/occurrences`: latest 100 `{id,scan_id,observed_at,severity,evidence,source}` snapshots.
- `GET /findings/{id}/report`: downloadable Markdown text with provenance, source-specific reproduction, timestamps, recurrence, notes and limitations.
- `GET /audit`: latest 500 local audit events `{id,action,detail,created_at}`.

Findings carry program/scan IDs, target, check ID, title, severity (`info|low|medium|high`), confidence, description, potential impact, remediation, evidence, status, notes, synthetic flag, created/first/last timestamps, occurrence count, source and optional CWE. Identity is `(program_id,target_url,check_id)`; repeated automated observations preserve analyst notes/status and append occurrence history. Imported HTTP rule IDs are prefixed `import-http:` and OpenAPI IDs `openapi:`. Manual records have independent IDs. Absence on a later scan does not automatically resolve an earlier observation.

List limits apply to recent-list routes, not record retention; cursor pagination is future work. Program exports include all that program’s stored findings. The seeded **ScopeForge Training Lab** uses `https://lab.scopeforge.test`, allows both profiles, starts without findings, and can never be used for real networking.
