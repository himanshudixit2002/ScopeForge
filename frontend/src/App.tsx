import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Blocks,
  BookOpen,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  Circle,
  CircleCheck,
  Clock3,
  Code2,
  Crosshair,
  Database,
  FileCheck2,
  FileText,
  FlaskConical,
  FolderLock,
  Globe2,
  Layers3,
  LayoutDashboard,
  ListFilter,
  LoaderCircle,
  LockKeyhole,
  Menu,
  Network,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  ShieldOff,
  Terminal,
  Workflow,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { api, EMPTY } from "./types";
import {
  ResearchLab,
  CheckCatalog,
  BatchScanForm,
  ManualFindingForm,
  OccurrenceHistory,
  ProgramReports,
  ProfileSelect,
  allowedProfiles,
  profileLabel,
  sourceLabel,
} from "./Research";
import type {
  Data,
  Finding,
  FindingStatus,
  ImportResult,
  Profile,
  Program,
  Scan,
  Severity,
  View,
} from "./types";

const NAV: { id: View; label: string; icon: LucideIcon }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "programs", label: "Programs & scope", icon: FolderLock },
  { id: "assets", label: "Assets", icon: Globe2 },
  { id: "scans", label: "Scans", icon: Radar },
  { id: "findings", label: "Findings", icon: ShieldCheck },
  { id: "lab", label: "Research lab", icon: FlaskConical },
  { id: "catalog", label: "Check catalog", icon: BookOpen },
  { id: "architecture", label: "Architecture", icon: Workflow },
];
const SEVERITIES: Severity[] = ["high", "medium", "low", "info"];
const date = (value: string) =>
  new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: "numeric",
  }).format(new Date(value));
const time = (value: string) =>
  new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit" }).format(
    new Date(value),
  );
const relative = (value: string) => {
  const minutes = Math.max(
    0,
    Math.floor((Date.now() - new Date(value).getTime()) / 60000),
  );
  return minutes < 1
    ? "Just now"
    : minutes < 60
      ? `${minutes}m ago`
      : minutes < 1440
        ? `${Math.floor(minutes / 60)}h ago`
        : date(value);
};
const isActive = (scan: Scan) => ["queued", "running"].includes(scan.status);
const isAuthorized = (program: Program) =>
  program.authorized && new Date(program.authorization_expires_at) > new Date();
function Badge({
  children,
  tone = "muted",
  dot = false,
}: {
  children: ReactNode;
  tone?: string;
  dot?: boolean;
}) {
  return (
    <span className={`badge ${tone}`}>
      {dot && <span className="badge-dot" />}
      {children}
    </span>
  );
}
function Empty({
  icon: Icon = Crosshair,
  title,
  description,
  action,
}: {
  icon?: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon size={22} />
      </div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}
function Modal({
  title,
  subtitle,
  children,
  onClose,
  wide = false,
  error,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
  error?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (error) ref.current?.scrollTo({ top: 0, behavior: "instant" });
  }, [error]);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    ref.current
      ?.querySelector<HTMLElement>("input, button, select, textarea")
      ?.focus();
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "Tab") {
        const elements = ref.current?.querySelectorAll<HTMLElement>(
          'button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]',
        );
        if (!elements?.length) return;
        const first = elements[0],
          last = elements[elements.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener("keydown", handler);
      previous?.focus();
    };
  }, [onClose]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className={`modal ${wide ? "wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        ref={ref}
      >
        <div className="modal-heading">
          <div>
            <h2 id="modal-title">{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Close dialog"
          >
            <X size={20} />
          </button>
        </div>
        {error && (
          <div className="modal-action-error" role="alert">
            {error}
          </div>
        )}
        {children}
      </div>
    </div>
  );
}
function ScanTable({
  scans,
  cancel,
  busy,
  compact = false,
  onFinding,
  demoPrograms = [],
}: {
  scans: Scan[];
  cancel: (id: string) => void;
  busy: boolean;
  compact?: boolean;
  onFinding: () => void;
  demoPrograms?: string[];
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Target / program</th>
            <th>Status</th>
            <th>Findings</th>
            {!compact && <th>Requests</th>}
            <th>Started</th>
            <th>
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>
                <div className="table-primary">
                  <span className="small-target">
                    <Globe2 size={15} />
                  </span>
                  <div>
                    <span className="target-url" title={scan.target_url}>
                      {scan.target_url.replace(/^https?:\/\//, "")}
                    </span>
                    <span className="table-secondary">
                      {scan.program_name}
                      {(scan.mode === "demo" ||
                        demoPrograms.includes(scan.program_id)) && (
                        <span className="synthetic-inline">Synthetic</span>
                      )}
                    </span>
                    {!compact && (
                      <span className="table-secondary scan-provenance">
                        {sourceLabel(scan.source)} ·{" "}
                        {scan.mode === "import" || scan.mode === "manual"
                          ? "Offline"
                          : profileLabel(scan.profile || "headers")}
                      </span>
                    )}
                    {scan.error && (
                      <span className="row-error">{scan.error}</span>
                    )}
                  </div>
                </div>
              </td>
              <td>
                <Badge tone={scan.status} dot>
                  {scan.status}
                </Badge>
              </td>
              <td>
                <button
                  className="number-link"
                  onClick={onFinding}
                  disabled={!scan.findings_count}
                >
                  {scan.findings_count.toString().padStart(2, "0")}
                </button>
              </td>
              {!compact && <td className="mono">{scan.requests_made}</td>}
              <td>
                <span className="muted nowrap">
                  {relative(scan.created_at)}
                </span>
              </td>
              <td>
                {isActive(scan) ? (
                  <button
                    className="text-button small"
                    onClick={() => cancel(scan.id)}
                    disabled={busy}
                  >
                    Cancel
                  </button>
                ) : (
                  <span className="muted">
                    <CheckCheck size={15} />
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function App() {
  const initial = window.location.hash.slice(1) as View;
  const [view, setView] = useState<View>(
    NAV.some((item) => item.id === initial) ? initial : "overview",
  );
  const [data, setData] = useState<Data>(EMPTY),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [serviceUnavailable, setServiceUnavailable] = useState(false),
    [actionError, setActionError] = useState(""),
    [busy, setBusy] = useState(false),
    [toast, setToast] = useState(""),
    [mobileNav, setMobileNav] = useState(false);
  const [isMobile, setIsMobile] = useState(
    () => window.matchMedia("(max-width: 720px)").matches,
  );
  useEffect(() => {
    const breakpoint = window.matchMedia("(max-width: 720px)");
    const update = () => setIsMobile(breakpoint.matches);
    breakpoint.addEventListener("change", update);
    return () => breakpoint.removeEventListener("change", update);
  }, []);
  useEffect(() => {
    if (!isMobile || !mobileNav) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMobileNav(false);
        document.querySelector<HTMLButtonElement>(".mobile-menu")?.focus();
      }
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [isMobile, mobileNav]);
  const [programModal, setProgramModal] = useState(false),
    [scanModal, setScanModal] = useState(false),
    [manualModal, setManualModal] = useState(false),
    [scanKind, setScanKind] = useState<"single" | "batch">("single"),
    [selectedProgram, setSelectedProgram] = useState<string | null>(null),
    [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [query, setQuery] = useState(""),
    [severity, setSeverity] = useState("all"),
    [findingStatus, setFindingStatus] = useState("all"),
    [scanStatus, setScanStatus] = useState("all");
  const refresh = useCallback(async () => {
    try {
      const [overview, programs, assets, scans, findings, audit, health] =
        await Promise.all([
          api<Data["overview"]>("/overview"),
          api<Data["programs"]>("/programs"),
          api<Data["assets"]>("/assets"),
          api<Data["scans"]>("/scans"),
          api<Data["findings"]>("/findings"),
          api<Data["audit"]>("/audit"),
          api<Data["health"]>("/health"),
        ]);
      setData({ overview, programs, assets, scans, findings, audit, health });
      setError("");
      setServiceUnavailable(false);
    } catch (cause) {
      setServiceUnavailable(true);
      setError(
        cause instanceof Error
          ? cause.message
          : "Unable to connect to the local service.",
      );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  const active = data.scans.some(isActive);
  useEffect(() => {
    if (!active) return;
    const interval = window.setInterval(() => void refresh(), 2500);
    return () => window.clearInterval(interval);
  }, [active, refresh]);
  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 5500);
    return () => window.clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    const handler = () => {
      const next = window.location.hash.slice(1) as View;
      if (NAV.some((item) => item.id === next)) setView(next);
    };
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);
  const navigate = (next: View) => {
    setView(next);
    window.location.hash = next;
    setQuery("");
    setMobileNav(false);
  };
  async function mutate<T>(
    path: string,
    method: string,
    body: unknown,
    message: string,
  ): Promise<T | null> {
    setBusy(true);
    setActionError("");
    try {
      const result = await api<T>(path, method, body);
      await refresh();
      setToast(message);
      return result;
    } catch (cause) {
      const message =
        cause instanceof Error
          ? cause.message
          : "The action could not be completed.";
      setError(message);
      setActionError(message);
      return null;
    } finally {
      setBusy(false);
    }
  }
  const runDemo = async () => {
    const program = data.programs.find((item) => item.is_demo);
    if (!program) {
      setError(
        "The training lab is unavailable. Restart the local service to restore it.",
      );
      return;
    }
    const result = await mutate(
      "/scans",
      "POST",
      {
        program_id: program.id,
        target_url: program.scope_origins[0],
        mode: "demo",
        profile: "web",
      },
      "Demo queued. All results use offline, synthetic fixtures.",
    );
    if (result) navigate("scans");
  };
  const cancel = (id: string) => {
    void mutate(
      `/scans/${id}/cancel`,
      "POST",
      undefined,
      "Scan cancellation requested.",
    );
  };
  const closeProgramModal = useCallback(() => setProgramModal(false), []),
    closeScanModal = useCallback(() => setScanModal(false), []),
    closeManualModal = useCallback(() => setManualModal(false), []),
    closeProgram = useCallback(() => setSelectedProgram(null), []),
    closeFinding = useCallback(() => setSelectedFinding(null), []);
  useEffect(() => {
    setActionError("");
  }, [
    programModal,
    scanModal,
    manualModal,
    scanKind,
    selectedProgram,
    selectedFinding,
  ]);
  const currentProgram = data.programs.find(
      (item) => item.id === selectedProgram,
    ),
    currentFinding = data.findings.find((item) => item.id === selectedFinding);
  const overview = data.overview;
  const findings = data.findings.filter(
    (item) =>
      (severity === "all" || item.severity === severity) &&
      (findingStatus === "all" || item.status === findingStatus) &&
      `${item.title} ${item.target_url} ${item.program_name} ${item.check_id} ${item.cwe || ""} ${sourceLabel(item.source)}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const programMatches = data.programs.filter((item) =>
    `${item.name} ${item.scope_origins.join(" ")}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const assetMatches = data.assets.filter((item) =>
    `${item.origin} ${item.program_name}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const scanMatches = data.scans.filter(
    (item) =>
      (scanStatus === "all" || item.status === scanStatus) &&
      `${item.target_url} ${item.program_name}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const primaryButton = (
    <button
      className="button primary"
      onClick={() => setScanModal(true)}
      disabled={busy || loading}
    >
      <Plus size={17} /> New scan
    </button>
  );
  return (
    <div className="app-shell">
      {mobileNav && (
        <div className="sidebar-scrim" onClick={() => setMobileNav(false)} />
      )}
      <aside
        id="workspace-navigation"
        className={`sidebar ${mobileNav ? "is-open" : ""}`}
        inert={isMobile && !mobileNav}
        aria-hidden={isMobile && !mobileNav ? true : undefined}
      >
        <a
          className="brand"
          href="#overview"
          onClick={() => navigate("overview")}
          aria-label="ScopeForge overview"
        >
          <span className="brand-mark">
            <i />
            <i />
          </span>
          <span>
            scope<span className="brand-light">forge</span>
            <span className="brand-period">.</span>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-avatar">P</span>
          <div>
            <strong>Personal workspace</strong>
            <span>Local environment</span>
          </div>
          <ChevronDown size={13} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {NAV.filter((item) => item.id !== "architecture").map(
            ({ id, label, icon: Icon }) => (
              <button
                key={id}
                className={`nav-item ${view === id ? "active" : ""}`}
                onClick={() => navigate(id)}
                aria-current={view === id ? "page" : undefined}
              >
                <Icon size={18} />
                <span>{label}</span>
                {id === "findings" && data.findings.length > 0 && (
                  <span className="nav-count">{data.findings.length}</span>
                )}
                {id === "scans" && active && <span className="live-dot" />}
              </button>
            ),
          )}
        </nav>
        <div className="nav-label tools-label">SYSTEM</div>
        <button
          className={`nav-item ${view === "architecture" ? "active" : ""}`}
          onClick={() => navigate("architecture")}
          aria-current={view === "architecture" ? "page" : undefined}
        >
          <Workflow size={18} />
          <span>Architecture</span>
          <ArrowUpRight size={14} />
        </button>
        <div className="sidebar-bottom">
          <div className="trust-card">
            <div className="trust-icon">
              <ShieldCheck size={21} />
            </div>
            <strong>Research with boundaries.</strong>
            <p>Explicit scope. Limited requests. Evidence you can review.</p>
            <button onClick={() => navigate("architecture")}>
              Explore the safeguards <ArrowRight size={13} />
            </button>
          </div>
          <div className="local-profile">
            <span className="profile-icon">
              <Terminal size={17} />
            </span>
            <div>
              <strong>Local researcher</strong>
              <span>ScopeForge v{data.health.version}</span>
            </div>
            <span className="local-indicator" title="Local workspace" />
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-menu"
              aria-label="Open navigation"
              aria-expanded={mobileNav}
              aria-controls="workspace-navigation"
              onClick={() => setMobileNav(true)}
            >
              <Menu size={21} />
            </button>
            <span className="breadcrumb-icon">
              <Layers3 size={16} />
            </span>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{NAV.find((item) => item.id === view)?.label}</strong>
          </div>
          <div className="topbar-actions">
            <span
              className={`connection ${serviceUnavailable ? "offline" : ""}`}
            >
              <span className="live-dot" />
              {serviceUnavailable
                ? "Service unavailable"
                : loading
                  ? "Connecting"
                  : "Local service online"}
            </span>
            <span className="topbar-divider" />
            <button
              className="icon-button"
              aria-label="Refresh workspace"
              title="Refresh workspace"
              onClick={() => void refresh()}
              disabled={loading}
            >
              <RefreshCw size={16} />
            </button>
            <span className="user-avatar">HD</span>
          </div>
        </header>
        <main id="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                <span />
                AUTHORIZED SECURITY RESEARCH
              </div>
              <h1>
                {view === "overview"
                  ? "Your research, in focus."
                  : view === "programs"
                    ? "Programs & scope"
                    : view === "assets"
                      ? "Your attack surface"
                      : view === "scans"
                        ? "Scan operations"
                        : view === "findings"
                          ? "Findings & evidence"
                          : view === "lab"
                            ? "Your offline research lab."
                            : view === "catalog"
                              ? "Every check, explained."
                              : "Built for deliberate research."}
              </h1>
              <p>
                {view === "overview"
                  ? "A clear view of your targets, checks, and what needs a closer look."
                  : view === "programs"
                    ? "Define the boundaries before you begin. Every target belongs to a program."
                    : view === "assets"
                      ? "An exact inventory of origins you have added to program scope."
                      : view === "scans"
                        ? "Run bounded HTTP posture checks and follow their progress."
                        : view === "findings"
                          ? "Review observations, validate their impact, and prepare clear reports."
                          : view === "lab"
                            ? "Turn captured HTTP and OpenAPI JSON into observations without contacting a target."
                            : view === "catalog"
                              ? "Explore the running engine’s rules, coverage, and limitations."
                              : "A local foundation today. A clear path to a distributed platform."}
              </p>
            </div>
            <div className="heading-actions">
              {view === "programs" ? (
                <button
                  className="button primary"
                  onClick={() => setProgramModal(true)}
                >
                  <Plus size={17} /> Add program
                </button>
              ) : view === "findings" ? (
                <button
                  className="button primary"
                  onClick={() => setManualModal(true)}
                  disabled={busy || loading}
                >
                  <Plus size={17} /> Add manual finding
                </button>
              ) : view === "lab" || view === "catalog" ? (
                <Badge tone="muted">
                  <LockKeyhole size={12} />{" "}
                  {view === "lab" ? "No target traffic" : "Engine definitions"}
                </Badge>
              ) : view === "architecture" ? (
                <Badge tone="success" dot>
                  v0.2 · Research workspace
                </Badge>
              ) : (
                primaryButton
              )}
            </div>
          </div>
          {error && (
            <div role="alert" className="error-banner">
              <ShieldOff size={18} />
              <span>{error}</span>
              <button className="text-button" onClick={() => void refresh()}>
                {serviceUnavailable ? "Retry connection" : "Refresh workspace"}
              </button>
              <button
                className="icon-button"
                onClick={() => setError("")}
                aria-label="Dismiss error"
              >
                <X size={16} />
              </button>
            </div>
          )}
          {loading ? (
            <div className="loading-state" role="status">
              <LoaderCircle className="spin" size={30} />
              <h3>Opening your workspace</h3>
              <p>Connecting to the local research service…</p>
            </div>
          ) : (
            <>
              {view === "overview" && (
                <>
                  <section className="hero">
                    <div className="hero-content">
                      <span className="hero-tag">
                        <span /> PURPOSE-BUILT. SCOPE-FIRST.
                      </span>
                      <h2>
                        Find the signal.
                        <br />
                        <span>Respect the scope.</span>
                      </h2>
                      <p>
                        Turn authorized targets into actionable observations.
                        <br className="desktop-break" /> Your next investigation
                        starts with a clear boundary.
                      </p>
                      <div className="hero-actions">
                        <button
                          className="button hero-button"
                          onClick={() => setProgramModal(true)}
                        >
                          {data.programs.some((item) => !item.is_demo)
                            ? "Add a program"
                            : "Add your first program"}{" "}
                          <ArrowUpRight size={17} />
                        </button>
                        <button
                          className="hero-demo"
                          onClick={() => void runDemo()}
                          disabled={busy}
                        >
                          <FlaskConical size={16} /> Explore demo{" "}
                          <ArrowRight size={14} />
                        </button>
                      </div>
                      <div className="hero-footnote">
                        <ShieldCheck size={13} /> Scope enforced at every
                        request
                      </div>
                    </div>
                    <div className="radar-art" aria-hidden="true">
                      <div className="radar-grid" />
                      <div className="radar-ring ring-1" />
                      <div className="radar-ring ring-2" />
                      <div className="radar-ring ring-3" />
                      <div className="radar-crosshair horizontal" />
                      <div className="radar-crosshair vertical" />
                      <div className="radar-sweep" />
                      <div className="radar-center">
                        <Crosshair size={32} />
                      </div>
                      <span className="radar-node node-one" />
                      <span className="radar-node node-two" />
                      <span className="radar-label">
                        <span className="live-dot" /> SCOPE BOUNDARY
                      </span>
                      <div className="radar-card">
                        <ShieldCheck size={17} />
                        <div>
                          Permission first<span>Bounded by design</span>
                        </div>
                        <Check size={14} />
                      </div>
                      <span className="radar-coordinate">
                        01 / RESEARCH WORKSPACE
                      </span>
                    </div>
                  </section>
                  <div className="metrics-grid">
                    <Metric
                      icon={FolderLock}
                      label="Programs"
                      value={overview.programs}
                      sub={`${data.programs.filter((item) => !item.is_demo && isAuthorized(item)).length} authorized · ${data.programs.filter((item) => item.is_demo).length} training lab`}
                      onClick={() => navigate("programs")}
                    />
                    <Metric
                      icon={Globe2}
                      label="In-scope assets"
                      value={overview.assets}
                      sub="Explicitly defined origins"
                      onClick={() => navigate("assets")}
                    />
                    <Metric
                      icon={Radar}
                      label="Completed scans"
                      value={overview.completed_scans}
                      sub={
                        active
                          ? `${data.scans.filter(isActive).length} scan in progress`
                          : "Ready when you are"
                      }
                      onClick={() => navigate("scans")}
                    />
                    <Metric
                      icon={ShieldCheck}
                      label="Open findings"
                      value={overview.open_findings}
                      sub="Observations awaiting review"
                      onClick={() => navigate("findings")}
                      accent
                    />
                  </div>
                  <div className="overview-middle">
                    <section className="panel scans-panel">
                      <PanelHeading
                        title="Recent scans"
                        subtitle="Your latest research activity"
                        action={
                          <button
                            className="text-button"
                            onClick={() => navigate("scans")}
                          >
                            View all <ArrowUpRight size={14} />
                          </button>
                        }
                      />
                      {overview.recent_scans.length ? (
                        <ScanTable
                          scans={overview.recent_scans.slice(0, 4)}
                          demoPrograms={data.programs
                            .filter((program) => program.is_demo)
                            .map((program) => program.id)}
                          cancel={cancel}
                          busy={busy}
                          compact
                          onFinding={() => navigate("findings")}
                        />
                      ) : (
                        <Empty
                          icon={Radar}
                          title="Your first signal is waiting"
                          description="Try the offline training lab to see how checks, evidence, and findings come together."
                          action={
                            <button
                              className="button secondary small"
                              disabled={busy}
                              onClick={() => void runDemo()}
                            >
                              <FlaskConical size={15} /> Run demo scan{" "}
                              <ArrowRight size={14} />
                            </button>
                          }
                        />
                      )}
                    </section>
                    <section className="panel severity-panel">
                      <PanelHeading
                        title="Findings by severity"
                        subtitle="A starting point for manual triage"
                      />
                      <div className="severity-body">
                        <div
                          className="severity-chart"
                          style={{
                            background: severityGradient(
                              overview.findings_by_severity,
                            ),
                          }}
                        >
                          <div>
                            <strong>
                              {Object.values(
                                overview.findings_by_severity,
                              ).reduce((a, b) => a + b, 0)}
                            </strong>
                            <span>observations</span>
                          </div>
                        </div>
                        <div className="severity-legend">
                          {SEVERITIES.map((item) => (
                            <div key={item}>
                              <span className={`severity-dot ${item}`} />
                              <span>{item}</span>
                              <strong>
                                {overview.findings_by_severity[item]}
                              </strong>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="panel-footnote">
                        <Circle size={11} /> Severity does not establish
                        exploitability.
                      </div>
                    </section>
                  </div>
                  <div className="overview-bottom">
                    <section className="panel activity-panel">
                      <PanelHeading
                        title="Workspace activity"
                        subtitle="An audit trail of your actions"
                        action={<Badge tone="muted">LOCAL LOG</Badge>}
                      />
                      {data.audit.length ? (
                        <div className="activity-list">
                          {data.audit.slice(0, 4).map((item, index) => (
                            <div className="activity-row" key={item.id}>
                              <span
                                className={`activity-icon ${index === 0 ? "latest" : ""}`}
                              >
                                <FileCheck2 size={15} />
                              </span>
                              <div>
                                <strong>
                                  {item.action
                                    .replace(/[._]/g, " ")
                                    .replace(/^./, (s) => s.toUpperCase())}
                                </strong>
                                <p>{item.detail}</p>
                              </div>
                              <span>{relative(item.created_at)}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="simple-empty">
                          <Clock3 size={18} />
                          <span>
                            Program changes and scan events will appear here.
                          </span>
                        </div>
                      )}
                    </section>
                    <section className="next-card">
                      <span className="next-eyebrow">
                        <BookOpen size={15} /> RESEARCH WORKFLOW
                      </span>
                      <h3>
                        A good finding starts <br />
                        with good boundaries.
                      </h3>
                      <p>
                        Record authorization. Define exact origins. Review the
                        evidence before reporting.
                      </p>
                      <button
                        className="text-button"
                        onClick={() => navigate("programs")}
                      >
                        Manage program scope <ArrowRight size={15} />
                      </button>
                      <span className="next-watermark" aria-hidden="true">
                        <FolderLock size={112} strokeWidth={0.8} />
                      </span>
                    </section>
                  </div>
                </>
              )}
              {view === "programs" && (
                <>
                  <div className="summary-strip">
                    <span>
                      <span className="live-dot" />
                      {
                        data.programs.filter(
                          (item) => isAuthorized(item) && !item.is_demo,
                        ).length
                      }{" "}
                      authorized programs
                    </span>
                    <span>
                      <FlaskConical size={14} />
                      {data.programs.filter((item) => item.is_demo).length}{" "}
                      offline training lab
                    </span>
                    <span>
                      <LockKeyhole size={14} /> Exact origins only
                    </span>
                  </div>
                  <Toolbar
                    query={query}
                    setQuery={setQuery}
                    placeholder="Search programs or origins…"
                    count={programMatches.length}
                    noun="programs"
                  />
                  <div className="program-grid">
                    {programMatches.map((program) => (
                      <article className="panel program-card" key={program.id}>
                        <div className="program-card-top">
                          <span
                            className={`program-icon ${program.is_demo ? "demo-icon" : ""}`}
                          >
                            {program.is_demo ? (
                              <FlaskConical size={23} />
                            ) : (
                              <FolderLock size={23} />
                            )}
                          </span>
                          <Badge
                            tone={
                              program.is_demo
                                ? "demo"
                                : isAuthorized(program)
                                  ? "success"
                                  : "warning"
                            }
                            dot
                          >
                            {program.is_demo
                              ? "Offline demo"
                              : isAuthorized(program)
                                ? "Authorized"
                                : program.authorized
                                  ? "Expired"
                                  : "Revoked"}
                          </Badge>
                        </div>
                        <h2>{program.name}</h2>
                        <p className="program-description">
                          {program.is_demo
                            ? "A safe place to explore the complete research workflow with synthetic evidence."
                            : program.authorization_note}
                        </p>
                        <div className="program-scope">
                          {program.scope_origins.slice(0, 2).map((origin) => (
                            <span key={origin}>
                              <Globe2 size={13} />
                              {origin}
                            </span>
                          ))}
                          {program.scope_origins.length > 2 && (
                            <span>
                              +{program.scope_origins.length - 2} additional
                              origins
                            </span>
                          )}
                        </div>
                        <div className="program-meta">
                          <span>
                            <Layers3 size={13} />
                            {program.scope_origins.length}{" "}
                            {program.scope_origins.length === 1
                              ? "origin"
                              : "origins"}
                          </span>
                          <span>
                            <Clock3 size={13} />
                            {program.request_interval_ms / 1000}s interval
                          </span>
                          <span>
                            <Shield size={13} />
                            {program.excluded_paths.length} exclusions
                          </span>
                        </div>
                        <div className="program-card-footer">
                          <span>
                            {program.is_demo
                              ? "Fixtures · No network requests"
                              : `Expires ${date(program.authorization_expires_at)}`}
                          </span>
                          <button
                            className="text-button"
                            onClick={() => setSelectedProgram(program.id)}
                          >
                            View scope <ArrowUpRight size={15} />
                          </button>
                        </div>
                      </article>
                    ))}
                    <button
                      className="add-program-card"
                      onClick={() => setProgramModal(true)}
                    >
                      <span>
                        <Plus size={24} />
                      </span>
                      <strong>Add a program</strong>
                      <p>
                        Bring your authorization and define
                        <br />
                        the targets you can research.
                      </p>
                    </button>
                  </div>
                  {query && !programMatches.length && (
                    <p className="muted">No programs match “{query}”.</p>
                  )}
                  <div className="informational">
                    <ShieldCheck size={18} />
                    <div>
                      <strong>Scope is explicit, never inferred.</strong>
                      <p>
                        A policy URL records the source of permission. Only the
                        exact origins you enter become eligible targets;
                        excluded paths remain blocked.
                      </p>
                    </div>
                  </div>
                </>
              )}
              {view === "assets" && (
                <>
                  <Toolbar
                    query={query}
                    setQuery={setQuery}
                    placeholder="Search origins or programs…"
                    count={assetMatches.length}
                    noun="assets"
                  />
                  <section className="panel">
                    {assetMatches.length ? (
                      <div className="table-scroll">
                        <table>
                          <thead>
                            <tr>
                              <th>Origin</th>
                              <th>Program</th>
                              <th>Environment</th>
                              <th>Authorization</th>
                              <th>Scope</th>
                            </tr>
                          </thead>
                          <tbody>
                            {assetMatches.map((asset) => {
                              const program = data.programs.find(
                                (item) => item.id === asset.program_id,
                              );
                              return (
                                <tr key={asset.id}>
                                  <td>
                                    <div className="table-primary">
                                      <span className="small-target">
                                        <Globe2 size={17} />
                                      </span>
                                      <strong className="mono">
                                        {asset.origin}
                                      </strong>
                                    </div>
                                  </td>
                                  <td>{asset.program_name}</td>
                                  <td>
                                    <Badge
                                      tone={asset.is_demo ? "demo" : "muted"}
                                    >
                                      {asset.is_demo
                                        ? "Synthetic lab"
                                        : "External target"}
                                    </Badge>
                                  </td>
                                  <td>
                                    <Badge
                                      tone={
                                        program && isAuthorized(program)
                                          ? "success"
                                          : "warning"
                                      }
                                      dot
                                    >
                                      {program && isAuthorized(program)
                                        ? "Active"
                                        : "Inactive"}
                                    </Badge>
                                  </td>
                                  <td>
                                    <button
                                      className="text-button"
                                      onClick={() =>
                                        setSelectedProgram(asset.program_id)
                                      }
                                    >
                                      Review <ArrowUpRight size={14} />
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty
                        icon={Globe2}
                        title={
                          query
                            ? "No matching assets"
                            : "Build your scoped inventory"
                        }
                        description={
                          query
                            ? "Try another origin or program name."
                            : "Add an authorized program to make its exact origins available for checks."
                        }
                        action={
                          !query && (
                            <button
                              className="button primary small"
                              onClick={() => setProgramModal(true)}
                            >
                              <Plus size={15} /> Add program
                            </button>
                          )
                        }
                      />
                    )}
                  </section>
                  <div className="informational">
                    <Crosshair size={18} />
                    <div>
                      <strong>Each origin is a precise boundary.</strong>
                      <p>
                        Subdomains are not automatically included. This release
                        accepts public HTTP and HTTPS hostnames on default
                        ports, with no wildcard scope or IP targets.
                      </p>
                    </div>
                  </div>
                </>
              )}
              {view === "scans" && (
                <>
                  <div className="scan-summary">
                    <div>
                      <span className="status-orb running" />
                      <strong>{data.scans.filter(isActive).length}</strong>
                      <span>In progress</span>
                    </div>
                    <div>
                      <CircleCheck size={18} />
                      <strong>
                        {
                          data.scans.filter(
                            (item) => item.status === "completed",
                          ).length
                        }
                      </strong>
                      <span>Completed</span>
                    </div>
                    <div>
                      <ShieldCheck size={18} />
                      <strong>
                        {data.scans.reduce(
                          (total, item) => total + item.findings_count,
                          0,
                        )}
                      </strong>
                      <span>Observations collected</span>
                    </div>
                    <button
                      className="button secondary small"
                      onClick={() => void runDemo()}
                      disabled={busy}
                    >
                      <FlaskConical size={15} /> Run offline demo
                    </button>
                  </div>
                  <div className="scan-controls">
                    <button
                      className="button secondary small"
                      onClick={() => {
                        setScanKind("batch");
                        setScanModal(true);
                      }}
                      disabled={busy}
                    >
                      <Layers3 size={15} /> Batch URLs
                    </button>
                    <p>
                      Explicit URLs. One request per job. One shared program
                      interval.
                    </p>
                    <button
                      className="button danger small"
                      disabled={busy || !active}
                      onClick={async () => {
                        const result = await mutate<{ cancelled: number }>(
                          "/scans/cancel-all",
                          "POST",
                          {},
                          "Cancellation requested for all active scans. Requests already sent cannot be recalled.",
                        );
                        if (result)
                          setToast(
                            `${result.cancelled} active scans cancelled. In-flight requests cannot be recalled.`,
                          );
                      }}
                    >
                      <ShieldOff size={15} /> Stop all active
                    </button>
                  </div>
                  <Toolbar
                    query={query}
                    setQuery={setQuery}
                    placeholder="Search scan targets…"
                    count={scanMatches.length}
                    noun="scans"
                  >
                    <div className="select-wrapper">
                      <ListFilter size={15} />
                      <select
                        aria-label="Filter scan status"
                        value={scanStatus}
                        onChange={(event) => setScanStatus(event.target.value)}
                      >
                        <option value="all">All statuses</option>
                        {[
                          "queued",
                          "running",
                          "completed",
                          "failed",
                          "cancelled",
                        ].map((status) => (
                          <option key={status} value={status}>
                            {status[0].toUpperCase() + status.slice(1)}
                          </option>
                        ))}
                      </select>
                    </div>
                  </Toolbar>
                  <section className="panel">
                    {scanMatches.length ? (
                      <ScanTable
                        scans={scanMatches}
                        demoPrograms={data.programs
                          .filter((program) => program.is_demo)
                          .map((program) => program.id)}
                        cancel={cancel}
                        busy={busy}
                        onFinding={() => navigate("findings")}
                      />
                    ) : (
                      <Empty
                        icon={Radar}
                        title={
                          query || scanStatus !== "all"
                            ? "No scans match your filters"
                            : "Ready for your first check"
                        }
                        description="Inspect one authorized URL at a time. Or try offline fixtures to explore the workflow."
                        action={
                          <button
                            className="button primary small"
                            onClick={() => setScanModal(true)}
                          >
                            <Plus size={15} /> New scan
                          </button>
                        }
                      />
                    )}
                  </section>
                  <div className="informational">
                    <Network size={18} />
                    <div>
                      <strong>Small footprint. Reviewable evidence.</strong>
                      <p>
                        HTTP posture checks send a limited GET request to your
                        selected URL. No crawling, attack payloads, or redirect
                        following. The scope and authorization are rechecked
                        before execution.
                      </p>
                    </div>
                  </div>
                </>
              )}
              {view === "findings" && (
                <>
                  <div
                    className="finding-tabs"
                    role="group"
                    aria-label="Finding status"
                  >
                    {[
                      { value: "all", label: "All findings" },
                      { value: "open", label: "Open" },
                      { value: "validated", label: "Validated" },
                      { value: "reported", label: "Reported" },
                      { value: "dismissed", label: "Dismissed" },
                    ].map((tab) => (
                      <button
                        key={tab.value}
                        className={
                          findingStatus === tab.value ? "selected" : ""
                        }
                        onClick={() => setFindingStatus(tab.value)}
                      >
                        {tab.label}
                        <span>
                          {tab.value === "all"
                            ? data.findings.length
                            : data.findings.filter(
                                (item) => item.status === tab.value,
                              ).length}
                        </span>
                      </button>
                    ))}
                  </div>
                  <Toolbar
                    query={query}
                    setQuery={setQuery}
                    placeholder="Search titles, targets, or check IDs…"
                    count={findings.length}
                    noun="findings"
                  >
                    <div className="select-wrapper">
                      <ListFilter size={15} />
                      <select
                        aria-label="Filter severity"
                        value={severity}
                        onChange={(event) => setSeverity(event.target.value)}
                      >
                        <option value="all">All severities</option>
                        {SEVERITIES.map((item) => (
                          <option key={item} value={item}>
                            {item[0].toUpperCase() + item.slice(1)}
                          </option>
                        ))}
                      </select>
                    </div>
                  </Toolbar>
                  <section className="panel">
                    {findings.length ? (
                      <div className="table-scroll">
                        <table className="findings-table">
                          <thead>
                            <tr>
                              <th>Observation</th>
                              <th>Severity</th>
                              <th>Status</th>
                              <th>Confidence</th>
                              <th>Detected</th>
                              <th />
                            </tr>
                          </thead>
                          <tbody>
                            {findings.map((finding) => (
                              <tr key={finding.id}>
                                <td>
                                  <button
                                    className="finding-title"
                                    onClick={() =>
                                      setSelectedFinding(finding.id)
                                    }
                                  >
                                    {finding.title}
                                  </button>
                                  <div className="table-secondary">
                                    {finding.target_url.replace(
                                      /^https?:\/\//,
                                      "",
                                    )}
                                    {finding.is_demo && (
                                      <span className="synthetic-inline">
                                        Synthetic
                                      </span>
                                    )}
                                  </div>
                                  <span className="table-secondary finding-provenance">
                                    {sourceLabel(finding.source)}
                                    {finding.cwe
                                      ? ` · ${finding.cwe}`
                                      : ""} · {finding.occurrence_count || 1}{" "}
                                    observations
                                  </span>
                                </td>
                                <td>
                                  <Badge tone={finding.severity} dot>
                                    {finding.severity}
                                  </Badge>
                                </td>
                                <td>
                                  <Badge tone={finding.status}>
                                    {finding.status}
                                  </Badge>
                                </td>
                                <td>
                                  <span className="confidence">
                                    <span
                                      className={`confidence-bars ${finding.confidence}`}
                                    >
                                      <i />
                                      <i />
                                      <i />
                                    </span>
                                    {finding.confidence}
                                  </span>
                                </td>
                                <td className="muted nowrap">
                                  {relative(
                                    finding.last_seen || finding.created_at,
                                  )}
                                </td>
                                <td>
                                  <button
                                    className="icon-button"
                                    aria-label={`View ${finding.title}`}
                                    onClick={() =>
                                      setSelectedFinding(finding.id)
                                    }
                                  >
                                    <ArrowUpRight size={17} />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty
                        icon={ShieldCheck}
                        title={
                          query || severity !== "all" || findingStatus !== "all"
                            ? "No matching observations"
                            : "Evidence will live here"
                        }
                        description={
                          query || severity !== "all" || findingStatus !== "all"
                            ? "Adjust your search or filters to find the observations you need."
                            : "Complete a scan to collect posture observations. Every finding includes evidence and a suggested next step."
                        }
                        action={
                          !data.findings.length && (
                            <button
                              className="button secondary small"
                              onClick={() => void runDemo()}
                              disabled={busy}
                            >
                              <FlaskConical size={15} /> Explore demo findings
                            </button>
                          )
                        }
                      />
                    )}
                  </section>
                  <div className="informational">
                    <FileCheck2 size={18} />
                    <div>
                      <strong>
                        Observation → validation → responsible report.
                      </strong>
                      <p>
                        Missing headers and configuration signals are not proof
                        of an exploitable vulnerability. Review context, confirm
                        impact within program rules, and document your
                        assessment before reporting.
                      </p>
                    </div>
                  </div>
                </>
              )}
              {view === "architecture" && <Architecture />}
              {view === "lab" && (
                <ResearchLab
                  programs={data.programs}
                  busy={busy}
                  onAnalyze={(body) =>
                    mutate<ImportResult>(
                      "/imports/analyze",
                      "POST",
                      body,
                      "Offline analysis saved. No target was contacted.",
                    )
                  }
                  onFindings={() => navigate("findings")}
                />
              )}
              {view === "catalog" && <CheckCatalog />}
            </>
          )}
          <footer className="page-footer">
            <span>
              <span className="brand-mark mini">
                <i />
                <i />
              </span>{" "}
              Built for responsible discovery.
            </span>
            <span>
              Local workspace <span>·</span> ScopeForge v{data.health.version}
            </span>
          </footer>
        </main>
      </div>
      {toast &&
        !programModal &&
        !scanModal &&
        !manualModal &&
        !selectedProgram &&
        !selectedFinding && (
          <div className="toast" role="status">
            <CircleCheck size={18} />
            <span>{toast}</span>
            <button
              className="icon-button"
              onClick={() => setToast("")}
              aria-label="Dismiss notification"
            >
              <X size={15} />
            </button>
          </div>
        )}
      {programModal && (
        <Modal
          title="Add an authorized program"
          subtitle="Record permission and set precise boundaries for your research."
          onClose={closeProgramModal}
          error={actionError}
        >
          <ProgramForm
            busy={busy}
            onCancel={closeProgramModal}
            onSubmit={async (body) => {
              const result = await mutate(
                "/programs",
                "POST",
                body,
                "Program created. Your exact origins are ready for checks.",
              );
              if (result) closeProgramModal();
              return !!result;
            }}
          />
        </Modal>
      )}
      {scanModal && (
        <Modal
          title="Start a new scan"
          subtitle="Explicit targets and permitted profiles. Evidence you can review."
          onClose={closeScanModal}
          error={actionError}
        >
          <div
            className="modal-tabs"
            role="group"
            aria-label="Scan submission mode"
          >
            <button
              className={scanKind === "single" ? "selected" : ""}
              aria-pressed={scanKind === "single"}
              onClick={() => setScanKind("single")}
            >
              Single URL
            </button>
            <button
              className={scanKind === "batch" ? "selected" : ""}
              aria-pressed={scanKind === "batch"}
              onClick={() => setScanKind("batch")}
            >
              Batch URLs
            </button>
          </div>
          {scanKind === "single" ? (
            <ScanForm
              programs={data.programs}
              busy={busy}
              onCancel={closeScanModal}
              onSubmit={async (body) => {
                const result = await mutate(
                  "/scans",
                  "POST",
                  body,
                  "Scan queued. Progress updates automatically.",
                );
                if (result) {
                  closeScanModal();
                  navigate("scans");
                }
                return !!result;
              }}
            />
          ) : (
            <BatchScanForm
              programs={data.programs}
              busy={busy}
              onCancel={closeScanModal}
              onSubmit={async (body) => {
                const result = await mutate<{
                  submitted: number;
                  request_budget: number;
                }>(
                  "/scans/batch",
                  "POST",
                  body,
                  "Batch queued. All targets passed admission together.",
                );
                if (result) {
                  closeScanModal();
                  navigate("scans");
                  setToast(
                    `${result.submitted} scans queued · request budget ${result.request_budget}.`,
                  );
                }
                return !!result;
              }}
            />
          )}
        </Modal>
      )}
      {manualModal && (
        <Modal
          title="Add a manual finding"
          subtitle="Record your own observations with clear provenance."
          onClose={closeManualModal}
          wide
          error={actionError}
        >
          <ManualFindingForm
            programs={data.programs}
            busy={busy}
            onCancel={closeManualModal}
            onSubmit={async (body) => {
              const result = await mutate<Finding>(
                "/findings",
                "POST",
                body,
                "Manual finding saved. No target requests were sent.",
              );
              if (result) {
                closeManualModal();
                setSelectedFinding(result.id);
                navigate("findings");
              }
              return !!result;
            }}
          />
        </Modal>
      )}
      {currentProgram && (
        <Modal
          title={currentProgram.name}
          subtitle="Program boundaries and authorization record"
          onClose={closeProgram}
          wide
          error={actionError}
        >
          <div className="detail-body">
            <div className="detail-badges">
              <Badge
                tone={
                  currentProgram.is_demo
                    ? "demo"
                    : isAuthorized(currentProgram)
                      ? "success"
                      : "warning"
                }
                dot
              >
                {currentProgram.is_demo
                  ? "Offline training lab"
                  : isAuthorized(currentProgram)
                    ? "Authorization active"
                    : "Authorization inactive"}
              </Badge>
              <Badge>
                {currentProgram.request_interval_ms}ms request interval
              </Badge>
            </div>
            <DetailSection title="Authorization record">
              <p>{currentProgram.authorization_note}</p>
              <div className="detail-meta">
                <span>
                  Expires {date(currentProgram.authorization_expires_at)} at{" "}
                  {time(currentProgram.authorization_expires_at)}
                </span>
                {/^https?:\/\//.test(currentProgram.policy_url) && (
                  <a
                    className="text-link"
                    href={currentProgram.policy_url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    View policy source <ArrowUpRight size={13} />
                  </a>
                )}
              </div>
            </DetailSection>
            <DetailSection title="Exact in-scope origins">
              <div className="code-lines">
                {currentProgram.scope_origins.map((origin) => (
                  <div key={origin}>
                    <Globe2 size={14} />
                    <code>{origin}</code>
                  </div>
                ))}
              </div>
            </DetailSection>
            <DetailSection title="Permitted check profiles">
              <div className="detail-badges">
                {allowedProfiles(currentProgram).map((profile) => (
                  <Badge key={profile}>{profileLabel(profile)}</Badge>
                ))}
              </div>
              <p>
                To expand permission, create a new authorization record. Offline
                imports do not contact described targets.
              </p>
            </DetailSection>
            <DetailSection title="Excluded path prefixes">
              {currentProgram.excluded_paths.length ? (
                <div className="code-lines">
                  {currentProgram.excluded_paths.map((path) => (
                    <div key={path}>
                      <ShieldOff size={14} />
                      <code>{path}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <p>No path exclusions recorded. Program rules still apply.</p>
              )}
            </DetailSection>
            <div className="inline-note">
              <ShieldCheck size={16} />
              {currentProgram.is_demo
                ? "Demo mode uses synthetic fixtures and never contacts this origin."
                : "Authorization, exact origin, DNS destination, and excluded paths are enforced before a request."}
            </div>
            <ProgramReports program={currentProgram} />
          </div>
          <div className="modal-footer">
            <span className="muted">
              Added {date(currentProgram.created_at)}
            </span>
            {currentProgram.authorized && !currentProgram.is_demo ? (
              <button
                className="button danger"
                disabled={busy}
                onClick={() =>
                  void mutate(
                    `/programs/${currentProgram.id}/revoke`,
                    "POST",
                    undefined,
                    "Authorization revoked. New checks are blocked.",
                  )
                }
              >
                <ShieldOff size={15} /> Revoke authorization
              </button>
            ) : (
              <button className="button secondary" onClick={closeProgram}>
                Close
              </button>
            )}
          </div>
        </Modal>
      )}
      {currentFinding && (
        <Modal
          title={currentFinding.title}
          subtitle={currentFinding.target_url}
          onClose={closeFinding}
          wide
          error={actionError}
        >
          <FindingDetail
            finding={currentFinding}
            busy={busy}
            onSubmit={async (body) =>
              !!(await mutate(
                `/findings/${currentFinding.id}`,
                "PATCH",
                body,
                "Finding assessment saved.",
              ))
            }
          />
        </Modal>
      )}
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  sub,
  onClick,
  accent = false,
}: {
  icon: LucideIcon;
  label: string;
  value: number;
  sub: string;
  onClick: () => void;
  accent?: boolean;
}) {
  return (
    <button
      className={`metric-card ${accent ? "accent" : ""}`}
      onClick={onClick}
    >
      <span className="metric-top">
        <span>{label}</span>
        <Icon size={18} />
      </span>
      <strong>{value.toString().padStart(2, "0")}</strong>
      <span className="metric-bottom">
        {sub}
        <ArrowUpRight size={14} />
      </span>
    </button>
  );
}
function PanelHeading({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="panel-heading">
      <div>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
function Toolbar({
  query,
  setQuery,
  placeholder,
  count,
  noun,
  children,
}: {
  query: string;
  setQuery: (value: string) => void;
  placeholder: string;
  count: number;
  noun: string;
  children?: ReactNode;
}) {
  return (
    <div className="toolbar">
      <div className="search-input">
        <Search size={17} />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={placeholder}
          aria-label={placeholder.replace("…", "")}
        />
        {query && (
          <button
            className="icon-button"
            aria-label="Clear search"
            onClick={() => setQuery("")}
          >
            <X size={14} />
          </button>
        )}
      </div>
      <div className="toolbar-right">
        {children}
        <span className="results-count">
          {count} {noun}
        </span>
      </div>
    </div>
  );
}
function severityGradient(values: Record<Severity, number>) {
  const total = Object.values(values).reduce((a, b) => a + b, 0);
  if (!total) return "#2c342b";
  let offset = 0;
  const colors = {
    high: "#ed877f",
    medium: "#e8ba74",
    low: "#c3e997",
    info: "#8ba6be",
  };
  return `conic-gradient(${SEVERITIES.map((severity) => {
    const start = offset;
    offset += (values[severity] / total) * 100;
    return `${colors[severity]} ${start}% ${offset}%`;
  }).join(",")})`;
}
function DetailSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="detail-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function ProgramForm({
  busy,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  onCancel: () => void;
  onSubmit: (body: unknown) => Promise<boolean>;
}) {
  const [formError, setFormError] = useState("");
  const expiresDefault = new Date(
    Date.now() + 30 * 86400000 - new Date().getTimezoneOffset() * 60000,
  )
    .toISOString()
    .slice(0, 16);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError("");
    const form = new FormData(event.currentTarget);
    const origins = String(form.get("origins"))
      .split(/[\n,]+/)
      .map((item) => item.trim())
      .filter(Boolean);
    const exclusions = String(form.get("exclusions"))
      .split(/[\n,]+/)
      .map((item) => item.trim())
      .filter(Boolean);
    try {
      for (const value of origins) {
        const url = new URL(value);
        if (
          !["https:", "http:"].includes(url.protocol) ||
          url.origin !== value.replace(/\/$/, "") ||
          url.username ||
          url.password ||
          url.port
        )
          throw new Error(
            "Enter exact HTTP(S) origins only, for example https://example.com. No paths, wildcards, credentials, or custom ports.",
          );
      }
      if (exclusions.some((path) => !path.startsWith("/")))
        throw new Error("Each excluded path must begin with /.");
      const expiry = new Date(String(form.get("expiry")));
      if (expiry <= new Date())
        throw new Error("Choose a future authorization expiry.");
      const profiles = form.getAll("profiles").map(String);
      if (!profiles.length)
        throw new Error(
          "Select at least one check profile permitted by the program.",
        );
      await onSubmit({
        name: String(form.get("name")).trim(),
        policy_url: String(form.get("policy")).trim(),
        authorization_note: String(form.get("authorization")).trim(),
        scope_origins: origins.map((value) => value.replace(/\/$/, "")),
        excluded_paths: exclusions,
        request_interval_ms: Number(form.get("interval")),
        authorization_expires_at: expiry.toISOString(),
        authorized: form.get("authorized") === "on",
        allowed_profiles: profiles,
      });
    } catch (cause) {
      setFormError(
        cause instanceof Error ? cause.message : "Check your program details.",
      );
    }
  };
  return (
    <form onSubmit={(event) => void submit(event)}>
      <div className="form-body">
        {formError && (
          <div className="form-error" role="alert">
            {formError}
          </div>
        )}
        <label>
          Program name
          <input
            name="name"
            placeholder="e.g. Example security program"
            required
            minLength={2}
            maxLength={120}
          />
        </label>
        <label>
          Program policy URL
          <input
            name="policy"
            type="url"
            placeholder="https://example.com/security"
            required
          />
          <span className="field-hint">
            The published policy or permission record. This does not add scope.
          </span>
        </label>
        <label>
          Authorization record
          <textarea
            name="authorization"
            rows={2}
            placeholder="Who authorized testing, when, and under which program rules?"
            required
            minLength={12}
            maxLength={4000}
          />
        </label>
        <div className="form-grid">
          <label>
            Exact in-scope origins
            <textarea
              className="mono"
              name="origins"
              rows={3}
              placeholder={"https://example.com\nhttps://api.example.com"}
              required
            />
            <span className="field-hint">
              One origin per line. Each subdomain needs an entry.
            </span>
          </label>
          <label>
            Excluded path prefixes <span className="optional">optional</span>
            <textarea
              className="mono"
              name="exclusions"
              rows={3}
              placeholder={"/logout\n/admin"}
            />
            <span className="field-hint">
              One path per line. Applied to every listed origin.
            </span>
          </label>
        </div>
        <div className="form-grid">
          <label>
            Minimum request interval (ms)
            <input
              name="interval"
              type="number"
              min={1000}
              max={60000}
              step={100}
              defaultValue={2000}
              required
            />
          </label>
          <label>
            Authorization expires <span className="optional">local time</span>
            <input
              name="expiry"
              type="datetime-local"
              defaultValue={expiresDefault}
              required
            />
          </label>
        </div>
        <fieldset className="profile-permissions">
          <legend>Permitted check profiles</legend>
          <label className="checkbox-label">
            <input
              type="checkbox"
              name="profiles"
              value="headers"
              defaultChecked
            />
            <span>
              <strong>Response headers</strong>
              <br />
              One GET, header analysis only.
            </span>
          </label>
          <label className="checkbox-label">
            <input type="checkbox" name="profiles" value="web" />
            <span>
              <strong>Web posture</strong>
              <br />
              One GET plus up to 128 KiB of HTML analyzed in memory. No scripts
              or links execute.
            </span>
          </label>
          <p className="field-hint">
            Choose only analysis permitted by the program. Expanding an existing
            program requires a new permission record.
          </p>
        </fieldset>
        <label className="checkbox-label">
          <input name="authorized" type="checkbox" required />
          <span>
            I have explicit permission to test these origins and will follow the
            program’s rules and exclusions.
          </span>
        </label>
        <div className="inline-note">
          <ShieldCheck size={16} />
          <span>
            Checks are blocked if authorization expires or is revoked. Private
            network destinations and IP targets are not accepted.
          </span>
        </div>
      </div>
      <div className="modal-footer">
        <button type="button" className="button secondary" onClick={onCancel}>
          Cancel
        </button>
        <button className="button primary" disabled={busy}>
          {busy ? (
            <LoaderCircle size={16} className="spin" />
          ) : (
            <Plus size={16} />
          )}{" "}
          Create program
        </button>
      </div>
    </form>
  );
}
function ScanForm({
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
  const eligible = programs.filter(isAuthorized);
  const [programId, setProgramId] = useState(
    eligible.find((item) => !item.is_demo)?.id || eligible[0]?.id || "",
  );
  const selected = eligible.find((item) => item.id === programId);
  const [target, setTarget] = useState(selected?.scope_origins[0] || "");
  const [profile, setProfile] = useState<Profile>(
    selected?.is_demo ? "web" : allowedProfiles(selected)[0],
  );
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!selected) return;
    await onSubmit({
      program_id: programId,
      target_url: target.trim(),
      mode: selected.is_demo ? "demo" : "passive",
      profile,
    });
  };
  return (
    <form onSubmit={(event) => void submit(event)}>
      <div className="form-body">
        {eligible.length ? (
          <>
            <label>
              Authorized program
              <select
                value={programId}
                onChange={(event) => {
                  setProgramId(event.target.value);
                  const next = eligible.find(
                    (item) => item.id === event.target.value,
                  );
                  setProfile(next?.is_demo ? "web" : allowedProfiles(next)[0]);
                  setTarget(
                    eligible.find((item) => item.id === event.target.value)
                      ?.scope_origins[0] || "",
                  );
                }}
              >
                {eligible.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                    {item.is_demo ? " · Offline demo" : ""}
                  </option>
                ))}
              </select>
            </label>
            <div className="scan-mode-card">
              <span className="program-icon">
                {selected?.is_demo ? (
                  <FlaskConical size={22} />
                ) : (
                  <Radar size={22} />
                )}
              </span>
              <div>
                <strong>
                  {selected?.is_demo
                    ? "Offline fixture scan"
                    : "HTTP posture check"}
                </strong>
                <p>
                  {selected?.is_demo
                    ? "Synthetic observations. Zero network requests."
                    : "One URL. Limited HTTP GET. No crawling or attack payloads."}
                </p>
              </div>
              <Badge tone={selected?.is_demo ? "demo" : "success"}>
                {selected?.is_demo ? "Demo" : "Low impact"}
              </Badge>
            </div>
            <ProfileSelect
              program={selected}
              value={profile}
              onChange={setProfile}
            />
            <label>
              Target URL
              <input
                type="url"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                required
                readOnly={selected?.is_demo}
                placeholder="https://example.com/"
              />
              <span className="field-hint">
                {selected?.is_demo
                  ? "The training target is fixed for offline fixtures."
                  : "Include a path if needed. The origin must exactly match the program scope."}
              </span>
            </label>
            <div className="allowed-origins">
              <span>ALLOWED ORIGINS</span>
              {selected?.scope_origins.map((origin) => (
                <button
                  className="origin-chip"
                  type="button"
                  key={origin}
                  onClick={() => setTarget(origin)}
                >
                  <Globe2 size={12} />
                  {origin}
                </button>
              ))}
            </div>
            <div className="inline-note">
              <LockKeyhole size={16} />
              <span>
                {selected?.is_demo
                  ? "Demo findings are visibly marked synthetic and are not evidence against a real system."
                  : `The worker enforces authorization, excluded paths, and a minimum ${Number(selected?.request_interval_ms) / 1000}s request interval. Redirects are not followed.`}
              </span>
            </div>
          </>
        ) : (
          <Empty
            icon={FolderLock}
            title="An authorized program is required"
            description="Add a program with current authorization before starting checks."
          />
        )}
      </div>
      <div className="modal-footer">
        <button type="button" className="button secondary" onClick={onCancel}>
          Cancel
        </button>
        <button className="button primary" disabled={busy || !selected}>
          {busy ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <Radar size={16} />
          )}{" "}
          {selected?.is_demo ? "Run demo scan" : "Queue posture check"}
        </button>
      </div>
    </form>
  );
}
function FindingDetail({
  finding,
  busy,
  onSubmit,
}: {
  finding: Finding;
  busy: boolean;
  onSubmit: (body: {
    status: FindingStatus;
    notes: string;
  }) => Promise<boolean>;
}) {
  const [status, setStatus] = useState<FindingStatus>(finding.status),
    [notes, setNotes] = useState(finding.notes || ""),
    [saved, setSaved] = useState(false);
  useEffect(() => {
    setStatus(finding.status);
    setNotes(finding.notes || "");
    setSaved(false);
  }, [finding.id, finding.status, finding.notes]);
  return (
    <>
      <div className="detail-body">
        <div className="detail-badges">
          <Badge tone={finding.severity} dot>
            {finding.severity} severity
          </Badge>
          <Badge>{finding.confidence} confidence</Badge>
          <Badge>{sourceLabel(finding.source)}</Badge>
          {finding.cwe && <Badge>{finding.cwe}</Badge>}
          {finding.is_demo && (
            <Badge tone="demo">
              <FlaskConical size={12} /> Synthetic fixture
            </Badge>
          )}
        </div>
        {finding.is_demo && (
          <div className="inline-note demo-note">
            <FlaskConical size={16} />
            <span>
              This is synthetic training evidence, generated offline. It does
              not describe a real vulnerability on a real target.
            </span>
          </div>
        )}
        <DetailSection title="Observation">
          <p>{finding.description}</p>
        </DetailSection>
        <div className="finding-history-meta">
          <div>
            <span>First seen</span>
            <strong>
              {date(finding.first_seen || finding.created_at)} ·{" "}
              {time(finding.first_seen || finding.created_at)}
            </strong>
          </div>
          <div>
            <span>Last seen</span>
            <strong>
              {date(finding.last_seen || finding.created_at)} ·{" "}
              {time(finding.last_seen || finding.created_at)}
            </strong>
          </div>
          <div>
            <span>Occurrences</span>
            <strong>{finding.occurrence_count || 1}</strong>
          </div>
        </div>
        {finding.source && finding.source !== "scan" && (
          <div className="inline-note">
            <FileText size={16} />
            <span>
              {finding.source === "manual"
                ? "This observation was entered by an analyst. The application did not verify the claim or contact the target."
                : "This observation comes from user-provided material processed offline. No live target was contacted or verified."}
            </span>
          </div>
        )}
        <DetailSection title="Potential impact">
          <p>{finding.impact}</p>
        </DetailSection>
        <DetailSection title="Collected evidence">
          <div className="evidence-heading">
            <span>{finding.check_id}</span>
            <span>SCAN {finding.scan_id.slice(0, 8)}</span>
          </div>
          <pre className="evidence">{finding.evidence}</pre>
        </DetailSection>
        <DetailSection title="Remediation & validation">
          <p>{finding.remediation}</p>
        </DetailSection>
        <OccurrenceHistory finding={finding} />
        <div className="assessment">
          <label>
            Assessment status
            <select
              value={status}
              onChange={(event) => {
                setStatus(event.target.value as FindingStatus);
                setSaved(false);
              }}
            >
              {["open", "validated", "dismissed", "reported"].map((value) => (
                <option key={value} value={value}>
                  {value[0].toUpperCase() + value.slice(1)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Research notes
            <textarea
              rows={4}
              value={notes}
              onChange={(event) => {
                setNotes(event.target.value);
                setSaved(false);
              }}
              maxLength={10000}
              placeholder="Document manual validation, program context, impact, and reporting decisions…"
            />
          </label>
        </div>
        <div className="detail-meta">
          <span>{finding.program_name}</span>
          <span>
            Detected {date(finding.created_at)} · {time(finding.created_at)}
          </span>
        </div>
      </div>
      <div className="modal-footer">
        <a
          className="button secondary"
          href={`/api/findings/${finding.id}/report`}
          download={`scopeforge-${finding.id}.md`}
        >
          <ArrowDownToLine size={15} /> Download report
        </a>
        <button
          className="button primary"
          disabled={busy}
          onClick={async () => {
            if (await onSubmit({ status, notes })) setSaved(true);
          }}
        >
          {busy ? (
            <LoaderCircle className="spin" size={16} />
          ) : saved ? (
            <Check size={16} />
          ) : (
            <FileCheck2 size={16} />
          )}{" "}
          {saved ? "Assessment saved" : "Save assessment"}
        </button>
      </div>
    </>
  );
}
function Architecture() {
  const implemented = [
    {
      icon: ShieldCheck,
      title: "Policy at the boundary",
      text: "Explicit authorization, permitted profiles, expiry, exact origins, path exclusions, and public destination checks before request bytes.",
    },
    {
      icon: Radar,
      title: "Bounded check engine",
      text: "Header and HTML posture profiles, batches of explicit URLs, a shared request interval, and stop-all control. No crawling or redirects.",
    },
    {
      icon: FileText,
      title: "Evidence and audit trail",
      text: "Offline HTTP/OpenAPI review, manual findings, source/CWE metadata, immutable occurrences, and program Markdown/JSON exports.",
    },
  ];
  const stages = [
    {
      step: "01",
      title: "Research workspace",
      state: "IMPLEMENTED",
      text: "React dashboard · FastAPI · versioned SQLite data · one local worker · offline research lab",
      items: [
        "Permission-based profiles",
        "Offline imports & catalog",
        "Evidence history & reports",
      ],
      current: true,
    },
    {
      step: "02",
      title: "Durable execution",
      state: "PROPOSED",
      text: "PostgreSQL · leased job queue · isolated workers · distributed recovery",
      items: [
        "Restart-safe jobs",
        "Per-program concurrency",
        "Worker observability",
      ],
    },
    {
      step: "03",
      title: "Team workspace",
      state: "PROPOSED",
      text: "Workspace tenancy · OIDC authentication · role-based access · encrypted secrets management",
      items: [
        "Review workflows",
        "Access & audit policies",
        "Shared reporting",
      ],
    },
    {
      step: "04",
      title: "Research platform",
      state: "PROPOSED",
      text: "Versioned check plugins · approved tool adapters · passive asset imports · report integrations",
      items: [
        "Isolated execution",
        "Policy-aware adapters",
        "Metrics & deployment",
      ],
    },
  ];
  return (
    <>
      <section className="panel architecture-panel">
        <PanelHeading
          title="The current system"
          subtitle="A single-machine deployment with clear application boundaries"
          action={
            <Badge tone="success" dot>
              Implemented
            </Badge>
          }
        />
        <div className="system-diagram">
          <div className="system-node">
            <span>
              <LayoutDashboard size={25} />
            </span>
            <strong>Web dashboard</strong>
            <p>React · TypeScript · Vite</p>
            <Badge>Loopback interface</Badge>
          </div>
          <div className="system-arrow">
            <span>/api</span>
            <ArrowRight size={22} />
          </div>
          <div className="system-node central">
            <span>
              <ShieldCheck size={25} />
            </span>
            <strong>API + scope gate</strong>
            <p>FastAPI · Validation</p>
            <Badge tone="success">Authorization enforced</Badge>
          </div>
          <div className="system-arrow">
            <span>bounded jobs</span>
            <ArrowRight size={22} />
          </div>
          <div className="system-node">
            <span>
              <Server size={25} />
            </span>
            <strong>Local worker</strong>
            <p>Header / HTML checks · Offline review</p>
            <Badge>Single process</Badge>
          </div>
          <div className="storage-node">
            <Database size={20} />
            <div>
              <strong>SQLite persistence</strong>
              <p>Programs · Jobs · Findings · Occurrences · Audit</p>
            </div>
            <span>LOCAL DISK</span>
          </div>
        </div>
        <div className="architecture-note">
          <LockKeyhole size={15} /> The local release is intended for one
          researcher. Hosted multi-user deployment requires the proposed
          authentication, isolation, and durability work.
        </div>
      </section>
      <div className="safeguards-grid">
        {implemented.map(({ icon: Icon, title, text }) => (
          <article className="panel safeguard" key={title}>
            <Icon size={22} />
            <h3>{title}</h3>
            <p>{text}</p>
          </article>
        ))}
      </div>
      <div className="section-title">
        <div>
          <div className="eyebrow">ENGINEERING ROADMAP</div>
          <h2>Scale the system. Keep the boundaries.</h2>
          <p>
            Phased architecture decisions, with production capabilities clearly
            separated from this release.
          </p>
        </div>
        <Blocks size={28} />
      </div>
      <div className="roadmap-grid">
        {stages.map((stage) => (
          <article
            key={stage.step}
            className={`roadmap-card ${stage.current ? "current" : ""}`}
          >
            <div className="roadmap-top">
              <span>{stage.step}</span>
              <Badge tone={stage.current ? "success" : "muted"}>
                {stage.state}
              </Badge>
            </div>
            <h3>{stage.title}</h3>
            <p>{stage.text}</p>
            <ul>
              {stage.items.map((item) => (
                <li key={item}>
                  {stage.current ? <Check size={13} /> : <Circle size={9} />}{" "}
                  {item}
                </li>
              ))}
            </ul>
          </article>
        ))}
      </div>
      <section className="panel principles-panel">
        <Code2 size={25} />
        <div>
          <h3>Expand through adapters, preserve policy in the core.</h3>
          <p>
            Future tools should use a shared policy gate and bounded execution
            contract. Program authorization, evidence provenance, request
            budgets, and cancellation remain core responsibilities as workers
            scale.
          </p>
        </div>
        <Badge tone="muted">DESIGN PRINCIPLE</Badge>
      </section>
    </>
  );
}
export default App;
