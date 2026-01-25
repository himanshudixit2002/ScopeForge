export type View =
  | "overview"
  | "programs"
  | "assets"
  | "scans"
  | "findings"
  | "lab"
  | "catalog"
  | "architecture";
export type Profile = "headers" | "web";
export type FindingSource = "scan" | "http-import" | "openapi" | "manual";
export type Severity = "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "validated" | "dismissed" | "reported";
export interface Program {
  id: string;
  name: string;
  policy_url: string;
  authorization_note: string;
  allowed_profiles: Profile[];
  scope_origins: string[];
  excluded_paths: string[];
  request_interval_ms: number;
  authorization_expires_at: string;
  authorized: boolean;
  is_demo: boolean;
  created_at: string;
}
export interface Asset {
  id: string;
  program_id: string;
  program_name: string;
  origin: string;
  is_demo: boolean;
}
export interface Scan {
  id: string;
  program_id: string;
  program_name: string;
  target_url: string;
  mode: "demo" | "passive" | "import" | "manual";
  profile: Profile;
  source: FindingSource;
  summary: Record<string, unknown>;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  requests_made: number;
  findings_count: number;
  error: string | null;
  checks: string[];
}
export interface Finding {
  id: string;
  program_id: string;
  program_name: string;
  scan_id: string;
  target_url: string;
  check_id: string;
  source: FindingSource;
  cwe: string | null;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  title: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  description: string;
  impact: string;
  remediation: string;
  evidence: string;
  status: FindingStatus;
  notes: string;
  is_demo: boolean;
  created_at: string;
}
export interface Occurrence {
  id: string;
  scan_id: string;
  observed_at: string;
  severity: Severity;
  evidence: string;
  source: FindingSource;
}
export interface CheckDefinition {
  id: string;
  title: string;
  category: string;
  profiles: string[];
  severity: Severity;
  cwe: string | null;
  description: string;
  limitations: string;
  reference_url: string;
}
export interface ImportResult {
  scan: Scan;
  findings_count: number;
  warnings: string[];
}
export interface AuditEvent {
  id: string;
  action: string;
  detail: string;
  created_at: string;
}
export interface Overview {
  programs: number;
  assets: number;
  open_findings: number;
  completed_scans: number;
  findings_by_severity: Record<Severity, number>;
  recent_scans: Scan[];
  recent_findings: Finding[];
}
export interface Health {
  status: string;
  version: string;
  mode: string;
  worker: string;
}
export interface Data {
  overview: Overview;
  programs: Program[];
  assets: Asset[];
  scans: Scan[];
  findings: Finding[];
  audit: AuditEvent[];
  health: Health;
}
export const EMPTY: Data = {
  overview: {
    programs: 0,
    assets: 0,
    open_findings: 0,
    completed_scans: 0,
    findings_by_severity: { high: 0, medium: 0, low: 0, info: 0 },
    recent_scans: [],
    recent_findings: [],
  },
  programs: [],
  assets: [],
  scans: [],
  findings: [],
  audit: [],
  health: {
    status: "connecting",
    version: "0.2.0",
    mode: "local",
    worker: "connecting",
  },
};
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(method === "GET" ? {} : { "X-ScopeForge-Client": "dashboard" }),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    let detail = "";
    try {
      const error = await response.json();
      detail =
        typeof error.detail === "string"
          ? error.detail
          : JSON.stringify(error.detail);
    } catch {
      detail = response.statusText;
    }
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}
