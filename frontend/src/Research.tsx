import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Check,
  FileJson2,
  FlaskConical,
  History,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  Plus,
  Search,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { api } from "./types";
import type {
  CheckDefinition,
  Finding,
  FindingSource,
  ImportResult,
  Occurrence,
  Profile,
  Program,
} from "./types";

const MAX_IMPORT_BYTES = 256 * 1024;
export const allowedProfiles = (program?: Program): Profile[] =>
  program?.allowed_profiles?.length ? program.allowed_profiles : ["headers"];
export const profileLabel = (profile: string) =>
  profile === "web"
    ? "Web posture · headers + HTML"
    : profile === "headers"
      ? "Response headers"
      : profile === "openapi"
        ? "OpenAPI document"
        : profile;
export const sourceLabel = (source?: FindingSource) =>
  ({
    scan: "HTTP observation",
    "http-import": "Imported HTTP capture",
    openapi: "OpenAPI review",
    manual: "Analyst-entered",
  })[source || "scan"];
const authorized = (program: Program) =>
  program.authorized && new Date(program.authorization_expires_at) > new Date();
const timestamp = (value: string) => new Date(value).toLocaleString();

export function ProfileSelect({
  program,
  value,
  onChange,
}: {
  program?: Program;
  value: Profile;
  onChange: (value: Profile) => void;
}) {
  return (
    <label>
      Check profile
      <select
        value={value}
        onChange={(event) => onChange(event.target.value as Profile)}
      >
        {allowedProfiles(program).map((profile) => (
          <option key={profile} value={profile}>
            {profileLabel(profile)}
          </option>
        ))}
      </select>
      <span className="field-hint">
        {value === "web"
          ? "One GET; inspect up to 128 KiB of uncompressed HTML in memory. No scripts run, links followed, or raw body saved."
          : "One GET; inspect response headers without analyzing the page body."}{" "}
        Only profiles recorded in this program’s permission are available.
      </span>
    </label>
  );
}

function syntheticSample(format: "http" | "openapi", origin: string) {
  return JSON.stringify(
    format === "http"
      ? {
          status: 200,
          headers: [
            { name: "Content-Type", value: "text/html; charset=utf-8" },
            { name: "Server", value: "SyntheticTrainingServer/2.0" },
            {
              name: "Set-Cookie",
              value: "training_session=SYNTHETIC_NOT_A_SECRET; Path=/",
            },
            { name: "Access-Control-Allow-Origin", value: "*" },
          ],
          body: `<!doctype html><html><head><title>Synthetic training page</title></head><body><form method="get" action="${origin.replace("https:", "http:")}/login"><label>Training password <input type="password" name="password"></label><button>Sign in</button></form><img src="${origin.replace("https:", "http:")}/training.png" alt="Synthetic image"></body></html>`,
        }
      : {
          openapi: "3.1.0",
          info: {
            title: "Synthetic training API — no endpoints contacted",
            version: "1.0.0",
          },
          servers: [{ url: origin }],
          paths: {
            "/accounts/{id}": {
              get: {
                summary: "Synthetic account record",
                parameters: [
                  {
                    name: "id",
                    in: "path",
                    required: true,
                    schema: { type: "string" },
                  },
                ],
                responses: {
                  "200": {
                    description: "Synthetic response",
                    content: {
                      "application/json": {
                        schema: {
                          type: "object",
                          properties: { id: { type: "string" } },
                        },
                      },
                    },
                  },
                },
              },
            },
            "/session": {
              post: {
                summary: "Synthetic sign in",
                security: [],
                requestBody: {
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: { password: { type: "string" } },
                      },
                    },
                  },
                },
                responses: {
                  "200": { description: "Synthetic session response" },
                },
              },
            },
          },
        },
    null,
    2,
  );
}

export function ResearchLab({
  programs,
  onAnalyze,
  onFindings,
  busy,
}: {
  programs: Program[];
  onAnalyze: (body: unknown) => Promise<ImportResult | null>;
  onFindings: () => void;
  busy: boolean;
}) {
  const eligible = programs.filter(authorized);
  const demo = eligible.find((program) => program.is_demo);
  const [programId, setProgramId] = useState(demo?.id || eligible[0]?.id || "");
  const program = eligible.find((item) => item.id === programId);
  const [target, setTarget] = useState(program?.scope_origins[0] || "");
  const [format, setFormat] = useState<"http" | "openapi">("http");
  const [content, setContent] = useState("");
  const [formError, setFormError] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const [resultSynthetic, setResultSynthetic] = useState(false);
  const [fileBusy, setFileBusy] = useState(false);
  const resultRef = useRef<HTMLDivElement>(null);
  const bytes = new TextEncoder().encode(content).length;
  const loadSample = (nextFormat: "http" | "openapi") => {
    if (!demo) {
      setFormError("An active training lab is required for synthetic samples.");
      return;
    }
    setProgramId(demo.id);
    setTarget(demo.scope_origins[0]);
    setFormat(nextFormat);
    setContent(syntheticSample(nextFormat, demo.scope_origins[0]));
    setFormError("");
    setResult(null);
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setFormError("");
    setResult(null);
    if (bytes > MAX_IMPORT_BYTES) {
      setFormError(
        "The JSON input exceeds 256 KiB of UTF-8 text. Choose a smaller capture or specification.",
      );
      return;
    }
    if (!program) {
      setFormError("Select a program with current authorization.");
      return;
    }
    try {
      JSON.parse(content);
    } catch {
      setFormError(
        "The editor must contain valid JSON. YAML, raw HTTP messages, and external URLs are not supported.",
      );
      return;
    }
    const response = await onAnalyze({
      program_id: programId,
      target_url: target.trim(),
      format,
      content,
    });
    if (response) {
      setResult(response);
      setResultSynthetic(program.is_demo);
      window.setTimeout(() => resultRef.current?.focus(), 0);
    }
  };
  return (
    <div className="research-layout">
      <section className="panel lab-editor-panel">
        <div className="research-panel-heading">
          <div>
            <span className="eyebrow">OFFLINE ANALYSIS</span>
            <h2>Bring your own evidence.</h2>
            <p>
              Review an HTTP capture or OpenAPI document against the scope you
              recorded.
            </p>
          </div>
          <FileJson2 size={27} />
        </div>
        <form onSubmit={(event) => void submit(event)}>
          <div className="form-body">
            <div className="inline-note">
              <LockKeyhole size={17} />
              <span>
                Zero target requests or DNS lookups. Raw input is processed in
                memory by your local service and is not stored. Sanitized
                observations are saved to this workspace.
              </span>
            </div>
            <div
              className="sample-actions"
              role="group"
              aria-label="Synthetic examples"
            >
              <button
                type="button"
                className="button secondary small"
                onClick={() => loadSample("http")}
                disabled={busy || !demo}
              >
                <FlaskConical size={15} /> Load synthetic HTTP
              </button>
              <button
                type="button"
                className="button secondary small"
                onClick={() => loadSample("openapi")}
                disabled={busy || !demo}
              >
                <FlaskConical size={15} /> Load synthetic OpenAPI
              </button>
            </div>
            <div className="form-grid">
              <label>
                Import program
                <select
                  value={programId}
                  onChange={(event) => {
                    setProgramId(event.target.value);
                    setTarget(
                      eligible.find((item) => item.id === event.target.value)
                        ?.scope_origins[0] || "",
                    );
                    setResult(null);
                  }}
                  required
                  disabled={busy}
                >
                  {!eligible.length && (
                    <option value="">No authorized programs</option>
                  )}
                  {eligible.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                      {item.is_demo ? " · Synthetic" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Input format
                <select
                  value={format}
                  onChange={(event) => {
                    setFormat(event.target.value as "http" | "openapi");
                    setResult(null);
                  }}
                  disabled={busy}
                >
                  <option value="http">HTTP capture JSON</option>
                  <option value="openapi">OpenAPI JSON</option>
                </select>
              </label>
            </div>
            <label>
              Evidence target URL
              <input
                type="url"
                value={target}
                onChange={(event) => {
                  setTarget(event.target.value);
                  setResult(null);
                }}
                placeholder="https://your-authorized-origin.com/"
                maxLength={2048}
                required
                disabled={busy}
              />
              <span className="field-hint">
                Associates the evidence with one exact in-scope URL. Described
                API paths and servers are never contacted or added to scope.
              </span>
            </label>
            {program?.is_demo && (
              <div className="inline-note demo-note">
                <FlaskConical size={16} />
                <span>
                  This program produces synthetic training evidence. It does not
                  describe a real target.
                </span>
              </div>
            )}
            <div className="editor-toolbar">
              <span>
                {format === "http"
                  ? "status · headers · optional body"
                  : "OpenAPI 3.0 / 3.1 / 3.2 · JSON only"}
              </span>
              <label className="file-picker">
                <Upload size={14} />
                <span>Import JSON file</span>
                <input
                  aria-label="Import JSON file"
                  type="file"
                  accept=".json,application/json"
                  disabled={busy || fileBusy}
                  onChange={async (event) => {
                    const file = event.target.files?.[0];
                    event.target.value = "";
                    if (!file) return;
                    setFormError("");
                    setResult(null);
                    if (file.size > MAX_IMPORT_BYTES) {
                      setFormError(
                        "The selected file exceeds 256 KiB. Nothing was uploaded.",
                      );
                      return;
                    }
                    setFileBusy(true);
                    try {
                      const text = await file.text();
                      if (
                        new TextEncoder().encode(text).length > MAX_IMPORT_BYTES
                      )
                        throw new Error(
                          "The file exceeds the 256 KiB UTF-8 limit.",
                        );
                      setContent(text);
                    } catch (cause) {
                      setFormError(
                        cause instanceof Error
                          ? cause.message
                          : "The selected file could not be read.",
                      );
                    } finally {
                      setFileBusy(false);
                    }
                  }}
                />
              </label>
            </div>
            <label className="json-editor-label">
              <span className="sr-only">JSON evidence editor</span>
              <textarea
                className="json-editor mono"
                aria-label="JSON evidence editor"
                value={content}
                onChange={(event) => {
                  setContent(event.target.value);
                  setResult(null);
                }}
                rows={18}
                spellCheck={false}
                autoComplete="off"
                placeholder={
                  format === "http"
                    ? '{ "status": 200, "headers": [{ "name": "Content-Type", "value": "text/html" }], "body": "" }'
                    : '{ "openapi": "3.1.0", "info": { "title": "Your API", "version": "1.0.0" }, "paths": {} }'
                }
                required
                disabled={busy || fileBusy}
              />
            </label>
            <div
              className={`editor-size ${bytes > MAX_IMPORT_BYTES ? "over-limit" : ""}`}
              aria-live="polite"
            >
              <span>{(bytes / 1024).toFixed(1)} / 256 KiB</span>
              <span>Local memory only · no remote references fetched</span>
            </div>
            {formError && (
              <div className="form-error" role="alert">
                {formError}
              </div>
            )}
            <div className="lab-submit">
              <button
                className="button primary"
                disabled={
                  busy ||
                  fileBusy ||
                  !program ||
                  !content.trim() ||
                  bytes > MAX_IMPORT_BYTES
                }
              >
                {busy || fileBusy ? (
                  <LoaderCircle className="spin" size={16} />
                ) : (
                  <ShieldCheck size={16} />
                )}{" "}
                {busy ? "Analyzing…" : "Analyze offline"}
              </button>
              <button
                type="button"
                className="text-button"
                onClick={() => {
                  setContent("");
                  setResult(null);
                  setFormError("");
                }}
                disabled={busy || !content}
              >
                Clear input
              </button>
            </div>
          </div>
        </form>
      </section>
      <aside className="lab-side">
        <section className="panel research-guide">
          <BookOpen size={22} />
          <h3>Evidence, with context.</h3>
          <p>
            Imports describe material you provide. They do not verify a live
            service, credentials, authorization behavior, or exploitability.
          </p>
          <ol>
            <li>Choose the program and exact evidence URL.</li>
            <li>Paste or open a JSON capture or specification.</li>
            <li>Review limitations and saved observations.</li>
          </ol>
          <div className="guide-rule">
            <strong>HTTP capture</strong>
            <p>
              A status code, a list of name/value headers, and optional HTML. No
              scripts execute.
            </p>
          </div>
          <div className="guide-rule">
            <strong>OpenAPI review</strong>
            <p>
              Local JSON structure and security declarations. No YAML, external
              references, or endpoint execution.
            </p>
          </div>
          <div className="guide-rule">
            <strong>Before sharing</strong>
            <p>
              Redact private information in your source. Review saved evidence
              and report drafts before disclosure.
            </p>
          </div>
        </section>
        {result ? (
          <section
            className="panel analysis-result"
            ref={resultRef}
            tabIndex={-1}
            aria-label="Offline analysis result"
          >
            <div className="result-icon">
              <Check size={24} />
            </div>
            <span className="eyebrow">ANALYSIS COMPLETE</span>
            <h3>{result.findings_count} observations</h3>
            <p>
              {sourceLabel(result.scan.source)}
              {resultSynthetic
                ? " · Synthetic training evidence"
                : " · User-provided evidence"}
            </p>
            <div className="result-budget">
              <strong>{result.scan.requests_made}</strong>
              <span>target requests</span>
            </div>
            {result.warnings.length > 0 && (
              <div className="analysis-warnings">
                <strong>Review limitations</strong>
                <ul>
                  {result.warnings.map((warning, index) => (
                    <li key={index}>{warning}</li>
                  ))}
                </ul>
              </div>
            )}
            {Object.keys(result.scan.summary || {}).length > 0 && (
              <details className="analysis-summary" open>
                <summary>Analysis summary</summary>
                <dl>
                  {Object.entries(result.scan.summary).map(([key, value]) => (
                    <div key={key}>
                      <dt>{key.replaceAll("_", " ")}</dt>
                      <dd>
                        {typeof value === "object"
                          ? JSON.stringify(value)
                          : String(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </details>
            )}
            <button className="button primary" onClick={onFindings}>
              Review saved findings <ArrowRight size={15} />
            </button>
            <span className="field-hint">
              Scan {result.scan.id.slice(0, 8)} · Drafts are never submitted
              automatically.
            </span>
          </section>
        ) : (
          <section className="panel result-placeholder">
            <Layers3 size={27} />
            <h3>Your review starts here.</h3>
            <p>
              Run an offline analysis to see its context, warnings, and saved
              observations.
            </p>
          </section>
        )}
      </aside>
    </div>
  );
}

export function CheckCatalog() {
  const [checks, setChecks] = useState<CheckDefinition[]>([]);
  const [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  const [query, setQuery] = useState(""),
    [category, setCategory] = useState("all"),
    [profile, setProfile] = useState("all");
  const reload = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setChecks(await api<CheckDefinition[]>("/checks"));
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "The check catalog could not be loaded.",
      );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void reload();
  }, [reload]);
  const categories = [...new Set(checks.map((item) => item.category))].sort();
  const profiles = [...new Set(checks.flatMap((item) => item.profiles))].sort();
  const filtered = checks.filter(
    (item) =>
      (category === "all" || item.category === category) &&
      (profile === "all" || item.profiles.includes(profile)) &&
      `${item.id} ${item.title} ${item.description} ${item.cwe || ""}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  return (
    <>
      <div className="catalog-intro panel">
        <div className="catalog-total">
          <strong>{loading ? "…" : error ? "—" : checks.length}</strong>
          <span>implemented rules</span>
        </div>
        <div>
          <h2>Know what a check can tell you.</h2>
          <p>
            These definitions come from the running engine. Coverage and
            severity describe observations; they are not proof of exploitable
            vulnerabilities.
          </p>
        </div>
        <span className={`badge ${error ? "warning" : "success"}`}>
          {error ? "Catalog unavailable" : "Live engine catalog"}
        </span>
      </div>
      <div className="catalog-toolbar">
        <label className="search-input">
          <Search size={16} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search checks, descriptions, or CWE…"
            aria-label="Search check catalog"
          />
        </label>
        <label>
          <span className="sr-only">Filter check category</span>
          <select
            aria-label="Filter check category"
            value={category}
            onChange={(event) => setCategory(event.target.value)}
          >
            <option value="all">All categories</option>
            {categories.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        </label>
        <label>
          <span className="sr-only">Filter check profile</span>
          <select
            aria-label="Filter check profile"
            value={profile}
            onChange={(event) => setProfile(event.target.value)}
          >
            <option value="all">All profiles</option>
            {profiles.map((item) => (
              <option key={item} value={item}>
                {profileLabel(item)}
              </option>
            ))}
          </select>
        </label>
      </div>
      {loading ? (
        <div className="loading-state" role="status">
          <LoaderCircle className="spin" />
          <p>Loading implemented checks…</p>
        </div>
      ) : error ? (
        <div className="form-error" role="alert">
          {error}
          <button className="text-button" onClick={() => void reload()}>
            Retry catalog
          </button>
        </div>
      ) : (
        <>
          <p className="catalog-count" aria-live="polite">
            {filtered.length} of {checks.length} rules shown
          </p>
          <div className="catalog-grid">
            {filtered.map((check) => (
              <article className="panel check-card" key={check.id}>
                <div className="detail-badges">
                  <span className={`badge ${check.severity}`}>
                    {check.severity}
                  </span>
                  <span className="badge">{check.category}</span>
                  {check.cwe && <span className="badge">{check.cwe}</span>}
                </div>
                <h3>{check.title}</h3>
                <code>{check.id}</code>
                <p>{check.description}</p>
                <div className="check-limits">
                  <strong>What this does not establish</strong>
                  <p>{check.limitations}</p>
                </div>
                <div className="check-card-footer">
                  <span>{check.profiles.map(profileLabel).join(" · ")}</span>
                  {/^https?:\/\//i.test(check.reference_url) && (
                    <a
                      className="text-link"
                      href={check.reference_url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Reference <ArrowUpRight size={13} />
                    </a>
                  )}
                </div>
              </article>
            ))}
          </div>
          {!filtered.length && (
            <div className="empty">
              <BookOpen size={24} />
              <h3>No matching checks</h3>
              <p>
                Try a different term or reset the category and profile filters.
              </p>
              <button
                className="button secondary small"
                onClick={() => {
                  setQuery("");
                  setCategory("all");
                  setProfile("all");
                }}
              >
                Reset filters
              </button>
            </div>
          )}
        </>
      )}
    </>
  );
}

export function BatchScanForm({
  programs,
  busy,
  onCancel,
  onSubmit,
}: {
  programs: Program[];
  busy: boolean;
  onCancel: () => void;
  onSubmit: (body: unknown) => Promise<boolean>;
}) {
  const eligible = programs.filter((item) => authorized(item) && !item.is_demo);
  const [programId, setProgramId] = useState(eligible[0]?.id || "");
  const selected = eligible.find((item) => item.id === programId);
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState<Profile>(allowedProfiles(selected)[0]);
  const [error, setError] = useState("");
  const urls = targets
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const unique = new Set(urls).size === urls.length;
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    if (!urls.length || urls.length > 20 || !unique) {
      setError(
        "Enter 1–20 distinct URLs, one per line. Duplicate URLs are not accepted.",
      );
      return;
    }
    await onSubmit({ program_id: programId, target_urls: urls, profile });
  };
  return (
    <form onSubmit={(event) => void submit(event)}>
      <div className="form-body">
        {eligible.length ? (
          <>
            <label>
              Batch program
              <select
                value={programId}
                onChange={(event) => {
                  setProgramId(event.target.value);
                  setProfile(
                    allowedProfiles(
                      eligible.find((item) => item.id === event.target.value),
                    )[0],
                  );
                }}
                required
              >
                {eligible.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <ProfileSelect
              program={selected}
              value={profile}
              onChange={setProfile}
            />
            <label>
              Explicit target URLs
              <textarea
                className="mono"
                value={targets}
                onChange={(event) => setTargets(event.target.value)}
                rows={7}
                required
                maxLength={42000}
                placeholder={`${selected?.scope_origins[0] || "https://example.com"}/\n${selected?.scope_origins[0] || "https://example.com"}/about`}
              />
              <span className="field-hint">
                1–20 distinct URLs, one per line. No wildcard expansion,
                discovery, crawling, or redirect following.
              </span>
            </label>
            <div className="batch-budget">
              <div>
                <strong>{urls.length}</strong>
                <span>explicit URLs</span>
              </div>
              <div>
                <strong>{urls.length}</strong>
                <span>maximum GET attempts</span>
              </div>
              <div>
                <strong>
                  {(selected?.request_interval_ms || 1000) / 1000}s
                </strong>
                <span>minimum request interval</span>
              </div>
            </div>
            <div className="inline-note">
              <ShieldCheck size={16} />
              <span>
                The entire batch is rejected if any target, profile,
                authorization, or queue limit fails. No partial batch is queued.
                Each accepted URL uses one request attempt.
              </span>
            </div>
            {(!unique || urls.length > 20) && (
              <div className="form-error" role="alert">
                {!unique
                  ? "Remove duplicate URLs before submitting."
                  : "A batch can contain at most 20 URLs."}
              </div>
            )}
            {error && (
              <div className="form-error" role="alert">
                {error}
              </div>
            )}
          </>
        ) : (
          <div className="empty">
            <ShieldCheck size={25} />
            <h3>Add an authorized real program</h3>
            <p>
              Batch requests require current permission for a real program. The
              training lab remains offline.
            </p>
          </div>
        )}
      </div>
      <div className="modal-footer">
        <button type="button" className="button secondary" onClick={onCancel}>
          Cancel
        </button>
        <button
          className="button primary"
          disabled={
            busy || !selected || !urls.length || urls.length > 20 || !unique
          }
        >
          {busy ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Layers3 size={16} />
          )}{" "}
          Queue batch · {urls.length} requests
        </button>
      </div>
    </form>
  );
}

export function ManualFindingForm({
  programs,
  busy,
  onCancel,
  onSubmit,
}: {
  programs: Program[];
  busy: boolean;
  onCancel: () => void;
  onSubmit: (body: unknown) => Promise<boolean>;
}) {
  const eligible = programs.filter(authorized);
  const [programId, setProgramId] = useState(
    eligible.find((item) => !item.is_demo)?.id || eligible[0]?.id || "",
  );
  const selected = eligible.find((item) => item.id === programId);
  const [target, setTarget] = useState(selected?.scope_origins[0] || "");
  const [formError, setFormError] = useState("");
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError("");
    const form = new FormData(event.currentTarget);
    const body = Object.fromEntries(
      [
        "title",
        "severity",
        "confidence",
        "description",
        "impact",
        "remediation",
        "evidence",
        "notes",
      ].map((key) => [key, String(form.get(key) || "").trim()]),
    );
    const cwe = String(form.get("cwe") || "").trim();
    const payload = {
      ...body,
      program_id: programId,
      target_url: target.trim(),
      ...(cwe ? { cwe } : {}),
    };
    if (new TextEncoder().encode(JSON.stringify(payload)).length > 32 * 1024) {
      setFormError(
        "This record is too large. Shorten the evidence or notes before saving.",
      );
      return;
    }
    await onSubmit(payload);
  };
  return (
    <form onSubmit={(event) => void submit(event)}>
      <div className="form-body">
        <div className="inline-note">
          <LockKeyhole size={16} />
          <span>
            Analyst-entered evidence is saved locally as provided. Redact
            credentials, personal data, and private values before saving. This
            record sends no target requests and does not verify the claim.
          </span>
        </div>
        {eligible.length ? (
          <>
            <div className="form-grid">
              <label>
                Finding program
                <select
                  value={programId}
                  onChange={(event) => {
                    setProgramId(event.target.value);
                    setTarget(
                      eligible.find((item) => item.id === event.target.value)
                        ?.scope_origins[0] || "",
                    );
                  }}
                  required
                >
                  {eligible.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                      {item.is_demo ? " · Synthetic" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Finding target URL
                <input
                  type="url"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  maxLength={2048}
                  required
                />
              </label>
            </div>
            {selected?.is_demo && (
              <div className="inline-note demo-note">
                <FlaskConical size={16} />
                <span>
                  This finding will be labelled synthetic because it belongs to
                  the training program.
                </span>
              </div>
            )}
            <label>
              Finding title
              <input
                name="title"
                required
                minLength={3}
                maxLength={200}
                placeholder="Describe the observed behavior precisely"
              />
            </label>
            <div className="form-grid">
              <label>
                Analyst severity
                <select name="severity" defaultValue="info">
                  <option value="info">Informational</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </label>
              <label>
                Analyst confidence
                <select name="confidence" defaultValue="low">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </label>
            </div>
            <label>
              Description
              <textarea
                name="description"
                rows={3}
                minLength={10}
                maxLength={4000}
                required
                placeholder="What was observed, under which conditions?"
              />
            </label>
            <label>
              Observed impact
              <textarea
                name="impact"
                rows={2}
                minLength={10}
                maxLength={4000}
                required
                placeholder="State demonstrated impact and what remains unverified."
              />
            </label>
            <label>
              Remediation
              <textarea
                name="remediation"
                rows={2}
                minLength={10}
                maxLength={4000}
                required
                placeholder="Suggested correction and validation steps"
              />
            </label>
            <label>
              Redacted evidence
              <textarea
                name="evidence"
                rows={5}
                className="mono"
                minLength={3}
                maxLength={8000}
                required
                placeholder="Include reproducible, sanitized observations. Do not paste secrets."
              />
            </label>
            <label>
              CWE identifier <span className="optional">optional</span>
              <input
                name="cwe"
                placeholder="CWE-200"
                pattern="CWE-[1-9][0-9]{0,5}"
                maxLength={10}
              />
            </label>
            <label>
              Analyst notes <span className="optional">optional</span>
              <textarea
                name="notes"
                rows={2}
                maxLength={4000}
                placeholder="Permission context and next review steps"
              />
            </label>
          </>
        ) : (
          <div className="empty">
            <h3>An authorized program is required</h3>
            <p>Record current permission before creating findings.</p>
          </div>
        )}
      </div>
      {formError && (
        <div className="manual-form-error form-error" role="alert">
          {formError}
        </div>
      )}
      <div className="modal-footer">
        <button type="button" className="button secondary" onClick={onCancel}>
          Cancel
        </button>
        <button className="button primary" disabled={busy || !selected}>
          {busy ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Plus size={16} />
          )}{" "}
          Save manual finding
        </button>
      </div>
    </form>
  );
}

export function OccurrenceHistory({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false),
    [loading, setLoading] = useState(false),
    [error, setError] = useState("");
  const [items, setItems] = useState<Occurrence[]>([]);
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setItems(await api<Occurrence[]>(`/findings/${finding.id}/occurrences`));
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "History could not be loaded.",
      );
    } finally {
      setLoading(false);
    }
  }, [finding.id]);
  useEffect(() => {
    if (open) void load();
  }, [open, load, finding.occurrence_count, finding.last_seen]);
  return (
    <section className="occurrence-history">
      <button
        className="history-toggle"
        aria-expanded={open}
        aria-label={
          open ? "Hide occurrence history" : "View occurrence history"
        }
        aria-controls={`occurrences-${finding.id}`}
        onClick={() => setOpen(!open)}
      >
        <History size={17} />
        <span>
          {open ? "Hide occurrence history" : "View occurrence history"}
        </span>
        <span className="badge">
          {finding.occurrence_count || 1} observations
        </span>
      </button>
      {open && (
        <div className="history-body" id={`occurrences-${finding.id}`}>
          {loading ? (
            <p role="status">
              <LoaderCircle className="spin" size={15} /> Loading saved
              occurrences…
            </p>
          ) : error ? (
            <div role="alert" className="form-error">
              {error}
              <button className="text-button" onClick={() => void load()}>
                Retry history
              </button>
            </div>
          ) : items.length ? (
            <>
              <p className="field-hint">
                Latest {items.length} immutable observation snapshots. Raw
                responses are not stored.
              </p>
              <ol className="occurrence-list">
                {items.map((item) => (
                  <li key={item.id}>
                    <div className="occurrence-heading">
                      <span>{timestamp(item.observed_at)}</span>
                      <span className={`badge ${item.severity}`}>
                        {item.severity}
                      </span>
                    </div>
                    <p>
                      {sourceLabel(item.source)} · Scan{" "}
                      {item.scan_id.slice(0, 8)}
                    </p>
                    <details>
                      <summary>Review saved evidence</summary>
                      <pre className="evidence">{item.evidence}</pre>
                    </details>
                  </li>
                ))}
              </ol>
            </>
          ) : (
            <p>No occurrence snapshots are available for this finding.</p>
          )}
        </div>
      )}
    </section>
  );
}

export function ProgramReports({ program }: { program: Program }) {
  return (
    <div className="program-reports">
      <div>
        <strong>Export this program</strong>
        <p>
          Local report drafts include provenance, review status, and
          limitations.
          {program.is_demo
            ? " Training evidence remains synthetic."
            : " Review before submitting through the program’s channel."}
        </p>
      </div>
      <div>
        <a
          className="button secondary small"
          href={`/api/programs/${program.id}/report?format=markdown`}
          download={`scopeforge-program-${program.id}.md`}
        >
          <ArrowDownToLine size={14} /> Markdown
        </a>
        <a
          className="button secondary small"
          href={`/api/programs/${program.id}/report?format=json`}
          download={`scopeforge-program-${program.id}.json`}
        >
          <ArrowDownToLine size={14} /> JSON
        </a>
      </div>
    </div>
  );
}
