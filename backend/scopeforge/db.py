"""SQLite persistence and transactional job transitions for a single local worker."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time
import uuid

from .security import utcnow


class NotFound(ValueError):
    pass


class QueueFull(ValueError):
    pass


def new_id() -> str:
    return uuid.uuid4().hex


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(mode=0o600, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if schema_version > 2:
                raise RuntimeError("This database uses a newer schema. Open it with a compatible ScopeForge version.")
            # Execute each DDL statement in this transaction. executescript()
            # would implicitly commit before migration and leave partial state.
            schema = """
                CREATE TABLE IF NOT EXISTS programs (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, policy_url TEXT NOT NULL,
                    authorization_note TEXT NOT NULL, scope_origins TEXT NOT NULL,
                    excluded_paths TEXT NOT NULL, request_interval_ms INTEGER NOT NULL,
                    authorization_expires_at TEXT NOT NULL, authorized INTEGER NOT NULL,
                    is_demo INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
                    last_request_at REAL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, program_id TEXT NOT NULL REFERENCES programs(id),
                    target_url TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                    requests_made INTEGER NOT NULL DEFAULT 0, findings_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT, checks TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS scans_queue ON scans(status, created_at);
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY, program_id TEXT NOT NULL REFERENCES programs(id),
                    scan_id TEXT NOT NULL REFERENCES scans(id), target_url TEXT NOT NULL,
                    check_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
                    confidence TEXT NOT NULL, description TEXT NOT NULL, impact TEXT NOT NULL,
                    remediation TEXT NOT NULL, evidence TEXT NOT NULL, status TEXT NOT NULL,
                    notes TEXT NOT NULL DEFAULT '', is_demo INTEGER NOT NULL, created_at TEXT NOT NULL,
                    UNIQUE(program_id, target_url, check_id)
                );
                CREATE INDEX IF NOT EXISTS findings_created ON findings(created_at);
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
                    action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
                )
            """
            for statement in schema.split(";"):
                if statement.strip():
                    connection.execute(statement)
            if schema_version < 2:
                self._migrate_v2(connection)
            if not connection.execute("SELECT 1 FROM programs WHERE is_demo=1 LIMIT 1").fetchone():
                self._insert_program(connection, {
                    "name": "ScopeForge Training Lab", "policy_url": "https://lab.scopeforge.test/policy",
                    "authorization_note": "Built-in synthetic offline fixture. This record grants no permission to contact a real system.",
                    "scope_origins": ["https://lab.scopeforge.test"], "excluded_paths": ["/excluded"],
                    "request_interval_ms": 1500, "allowed_profiles": ["headers", "web"],
                    "authorization_expires_at": (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat().replace("+00:00", "Z"),
                    "authorized": True, "is_demo": True,
                })
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _migrate_v2(connection):
        additions = {
            "programs": [("allowed_profiles", "TEXT NOT NULL DEFAULT '[\"headers\"]'")],
            "scans": [("profile", "TEXT NOT NULL DEFAULT 'headers'"), ("source", "TEXT NOT NULL DEFAULT 'scan'"),
                      ("summary", "TEXT NOT NULL DEFAULT '{}'" )],
            "findings": [("source", "TEXT NOT NULL DEFAULT 'scan'"), ("cwe", "TEXT"),
                         ("first_seen", "TEXT"), ("last_seen", "TEXT"),
                         ("occurrence_count", "INTEGER NOT NULL DEFAULT 1")],
        }
        for table, columns in additions.items():
            existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
            for name, declaration in columns:
                if name not in existing:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        connection.execute("UPDATE programs SET allowed_profiles='[\"headers\",\"web\"]' WHERE is_demo=1")
        connection.execute("UPDATE findings SET first_seen=created_at,last_seen=COALESCE((SELECT finished_at FROM scans WHERE scans.id=findings.scan_id),created_at) WHERE first_seen IS NULL")
        connection.execute("""CREATE TABLE IF NOT EXISTS finding_occurrences (
            id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id),
            scan_id TEXT NOT NULL REFERENCES scans(id), observed_at TEXT NOT NULL,
            severity TEXT NOT NULL, evidence TEXT NOT NULL, source TEXT NOT NULL,
            UNIQUE(finding_id,scan_id)
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS occurrences_finding ON finding_occurrences(finding_id,observed_at DESC)")
        connection.execute("""INSERT OR IGNORE INTO finding_occurrences(id,finding_id,scan_id,observed_at,severity,evidence,source)
            SELECT lower(hex(randomblob(16))),id,scan_id,last_seen,severity,evidence,source FROM findings""")
        connection.execute("PRAGMA user_version=2")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _audit(connection, action, detail):
        connection.execute("INSERT INTO audit(id,action,detail,created_at) VALUES(?,?,?,?)", (new_id(), action, detail, utcnow()))

    @staticmethod
    def _program(row):
        if row is None:
            raise NotFound("Program not found.")
        result = dict(row)
        result["scope_origins"] = json.loads(result["scope_origins"])
        result["excluded_paths"] = json.loads(result["excluded_paths"])
        result["allowed_profiles"] = json.loads(result["allowed_profiles"])
        result["authorized"] = bool(result["authorized"])
        result["is_demo"] = bool(result["is_demo"])
        result.pop("last_request_at", None)
        return result

    @staticmethod
    def _scan(row):
        if row is None:
            raise NotFound("Scan not found.")
        result = dict(row)
        result["checks"] = json.loads(result["checks"])
        result["summary"] = json.loads(result["summary"])
        return result

    @staticmethod
    def _finding(row):
        if row is None:
            raise NotFound("Finding not found.")
        result = dict(row)
        result["is_demo"] = bool(result["is_demo"])
        return result

    def _insert_program(self, connection, program):
        program_id = new_id()
        connection.execute("""INSERT INTO programs (
            id,name,policy_url,authorization_note,scope_origins,excluded_paths,
            request_interval_ms,authorization_expires_at,authorized,is_demo,created_at,allowed_profiles
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
            program_id, program["name"], program["policy_url"], program["authorization_note"],
            json.dumps(program["scope_origins"]), json.dumps(program["excluded_paths"]),
            program["request_interval_ms"], program["authorization_expires_at"], int(program["authorized"]),
            int(program.get("is_demo", False)), utcnow(), json.dumps(program.get("allowed_profiles", ["headers"])),
        ))
        self._audit(connection, "program.created", f"Created {'offline demo' if program.get('is_demo') else 'authorized'} program {program['name']} ({program_id}); {len(program['scope_origins'])} exact origins.")
        return program_id

    def create_program(self, program):
        with self.connect() as connection:
            program_id = self._insert_program(connection, program)
        return self.get_program(program_id)

    def programs(self):
        with self.connect() as connection:
            return [self._program(row) for row in connection.execute("SELECT * FROM programs ORDER BY created_at DESC")]

    def get_program(self, program_id):
        with self.connect() as connection:
            return self._program(connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone())

    def revoke_program(self, program_id):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._program(connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone())
            connection.execute("UPDATE programs SET authorized=0 WHERE id=?", (program_id,))
            connection.execute("UPDATE scans SET status='cancelled',finished_at=?,error=? WHERE program_id=? AND status IN ('queued','running')", (utcnow(), "Program authorization was revoked.", program_id))
            self._audit(connection, "program.revoked", f"Revoked authorization for program {program_id}; pending scans cancelled.")
        return self.get_program(program_id)

    def assets(self):
        return [{"id": f"{program['id']}:{index}", "program_id": program["id"], "program_name": program["name"], "origin": origin, "is_demo": program["is_demo"]}
                for program in self.programs() for index, origin in enumerate(program["scope_origins"])]

    @staticmethod
    def validate_scan(program, target_url, mode, profile="headers"):
        from .security import ScopeError, validate_program
        target = validate_program(program, target_url, mode)
        if mode in {"passive", "demo"} and profile not in program["allowed_profiles"]:
            raise ScopeError("This scan profile is not covered by the recorded authorization.")
        if profile not in {"headers", "web"}:
            raise ScopeError("Unknown analysis profile.")
        return target

    def create_scan(self, program_id, target_url, mode, profile="headers"):
        return self.create_scans(program_id, [target_url], mode, profile)[0]

    def create_scans(self, program_id, target_urls, mode="passive", profile="headers", *, real_only=False):
        from .security import ScopeError
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            program = self._program(connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone())
            if mode not in {"demo", "passive"}:
                raise ScopeError("Only demo and passive scans may enter the network queue.")
            if real_only and program["is_demo"]:
                raise ScopeError("Batch requests require an explicitly authorized real program.")
            if not 1 <= len(target_urls) <= 20:
                raise ScopeError("Submit between 1 and 20 explicit target URLs.")
            targets = [self.validate_scan(program, url, mode, profile).url for url in target_urls]
            if len(set(targets)) != len(targets):
                raise ScopeError("Batch target URLs must be distinct after normalization.")
            active = connection.execute("SELECT COUNT(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]
            if active + len(targets) > 100:
                raise QueueFull("The local queue is full (100 active scans). Wait or cancel existing work.")
            ids = []
            for target in targets:
                scan_id = new_id()
                ids.append(scan_id)
                connection.execute("INSERT INTO scans(id,program_id,target_url,mode,status,created_at,profile,source) VALUES(?,?,?,?,'queued',?,?,'scan')", (scan_id, program_id, target, mode, utcnow(), profile))
                self._audit(connection, "scan.queued", f"Queued {mode} {profile} scan {scan_id} for program {program_id}: {target}")
        return [self.get_scan(scan_id) for scan_id in ids]

    _SCAN_SELECT = "SELECT s.*,p.name AS program_name FROM scans s JOIN programs p ON p.id=s.program_id"
    _FINDING_SELECT = "SELECT f.*,p.name AS program_name FROM findings f JOIN programs p ON p.id=f.program_id"

    def scans(self):
        with self.connect() as connection:
            return [self._scan(row) for row in connection.execute(self._SCAN_SELECT + " ORDER BY s.created_at DESC LIMIT 500")]

    def get_scan(self, scan_id):
        with self.connect() as connection:
            return self._scan(connection.execute(self._SCAN_SELECT + " WHERE s.id=?", (scan_id,)).fetchone())

    def cancel_scan(self, scan_id):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise NotFound("Scan not found.")
            if row["status"] in {"queued", "running"}:
                connection.execute("UPDATE scans SET status='cancelled',finished_at=?,error=? WHERE id=?", (utcnow(), "Cancelled by operator.", scan_id))
                self._audit(connection, "scan.cancelled", f"Cancelled scan {scan_id}. An already-started request may finish; its results will be discarded.")
        return self.get_scan(scan_id)

    def cancel_all(self, program_id=None):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if program_id is not None:
                self._program(connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone())
            where = "status IN ('queued','running')" + (" AND program_id=?" if program_id is not None else "")
            args = (program_id,) if program_id is not None else ()
            count = connection.execute(f"UPDATE scans SET status='cancelled',finished_at=?,error=? WHERE {where}", (utcnow(), "Stopped by operator. Any in-flight results are discarded.", *args)).rowcount
            self._audit(connection, "scan.cancelled_all", f"Stopped {count} active scans for {program_id or 'all programs'}. Already-started requests may finish; their results are discarded.")
        return count

    def recover_jobs(self):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]
            if count:
                connection.execute("UPDATE scans SET status='failed',finished_at=?,error=? WHERE status='running'", (utcnow(), "Interrupted by restart; a request may have been sent. Review before manually retrying."))
                self._audit(connection, "worker.recovered", f"Marked {count} interrupted scan(s) failed without replaying requests. Queued work remains available; review interrupted jobs before manually retrying.")

    def claim_next(self):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT id FROM scans WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if row is None:
                return None
            connection.execute("UPDATE scans SET status='running',started_at=? WHERE id=?", (utcnow(), row["id"]))
            self._audit(connection, "scan.started", f"Started scan {row['id']}; authorization and scope will be rechecked.")
        return self.get_scan(row["id"])

    def request_gate(self, scan_id, program_id):
        """Atomically reserve one request slot, or return its remaining wait."""
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            scan = connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            program = connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone()
            if scan is None or scan["status"] != "running":
                raise ValueError("Scan was cancelled before the request could start.")
            if scan["requests_made"] >= 1:
                raise ValueError("This scan has already reserved its single request attempt.")
            if scan["program_id"] != program_id or scan["mode"] != "passive":
                raise ValueError("Only a matching authorized network scan may reserve a request.")
            self.validate_scan(self._program(program), scan["target_url"], scan["mode"], scan["profile"])
            now = time.time()
            last = program["last_request_at"] or 0
            wait = max(0.0, last + max(1000, program["request_interval_ms"]) / 1000 - now)
            if wait > 0:
                return min(wait, 60.0)
            connection.execute("UPDATE programs SET last_request_at=? WHERE id=?", (now, program_id))
            connection.execute("UPDATE scans SET requests_made=requests_made+1 WHERE id=?", (scan_id,))
            self._audit(connection, "scan.request_reserved", f"Reserved one GET attempt for scan {scan_id}; no redirects or retries.")
            return 0.0

    def before_send(self, scan):
        """Recheck at the HTTP write boundary and account for slow handshakes.

        The initial slot is reserved before connecting. Refreshing its timestamp
        immediately before sending also spaces the next scan from the actual
        request attempt, rather than from an arbitrarily earlier connection.
        """
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT * FROM scans WHERE id=?", (scan["id"],)).fetchone()
            if current is None or current["status"] != "running" or current["requests_made"] != 1:
                raise ValueError("Scan is no longer allowed to send its request.")
            if current["mode"] != "passive":
                raise ValueError("Offline records cannot send network requests.")
            scan = dict(current)
            program = self._program(connection.execute("SELECT * FROM programs WHERE id=?", (scan["program_id"],)).fetchone())
            self.validate_scan(program, scan["target_url"], scan["mode"], scan["profile"])
            connection.execute("UPDATE programs SET last_request_at=? WHERE id=?", (time.time(), scan["program_id"]))
            self._audit(connection, "scan.request_started", f"HTTP write boundary reached for scan {scan['id']}; authorization rechecked and pacing timestamp refreshed.")

    def _persist_observations(self, connection, scan, program, observations, observed_at):
        finding_ids = []
        for observation in observations:
            finding_id = new_id()
            connection.execute("""INSERT INTO findings (
                id,program_id,scan_id,target_url,check_id,title,severity,confidence,
                description,impact,remediation,evidence,status,notes,is_demo,created_at,
                source,cwe,first_seen,last_seen,occurrence_count
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?,?,?,1)
                ON CONFLICT(program_id,target_url,check_id) DO UPDATE SET
                scan_id=excluded.scan_id,title=excluded.title,severity=excluded.severity,
                confidence=excluded.confidence,description=excluded.description,
                impact=excluded.impact,remediation=excluded.remediation,evidence=excluded.evidence,
                source=excluded.source,cwe=excluded.cwe,last_seen=excluded.last_seen,
                occurrence_count=findings.occurrence_count+1
                """, (
                finding_id, scan["program_id"], scan["id"], scan["target_url"],
                observation["check_id"], observation["title"], observation["severity"], observation["confidence"],
                observation["description"], observation["impact"], observation["remediation"], observation["evidence"],
                observation.get("notes", ""), int(program["is_demo"]), observed_at,
                scan["source"], observation.get("cwe"), observed_at, observed_at,
            ))
            finding_id = connection.execute("SELECT id FROM findings WHERE program_id=? AND target_url=? AND check_id=?", (scan["program_id"], scan["target_url"], observation["check_id"])).fetchone()[0]
            finding_ids.append(finding_id)
            connection.execute("INSERT INTO finding_occurrences(id,finding_id,scan_id,observed_at,severity,evidence,source) VALUES(?,?,?,?,?,?,?)", (new_id(), finding_id, scan["id"], observed_at, observation["severity"], observation["evidence"], scan["source"]))
        return finding_ids

    def finish_scan(self, scan, observations, checks, summary=None):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM scans WHERE id=?", (scan["id"],)).fetchone()
            if row is None or row["status"] != "running":
                return
            scan = dict(row)
            program = self._program(connection.execute("SELECT * FROM programs WHERE id=?", (scan["program_id"],)).fetchone())
            # Revalidate stored job fields at completion, after any in-flight changes.
            self.validate_scan(program, scan["target_url"], scan["mode"], scan["profile"])
            observed_at = utcnow()
            self._persist_observations(connection, scan, program, observations, observed_at)
            connection.execute("UPDATE scans SET status='completed',finished_at=?,findings_count=?,checks=?,summary=?,error=NULL WHERE id=?", (observed_at, len(observations), json.dumps(checks), json.dumps(summary or {}), scan["id"]))
            self._audit(connection, "scan.completed", f"Completed scan {scan['id']}: {len(observations)} observations; occurrence snapshots appended and existing triage preserved.")

    def create_offline_result(self, program_id, target_url, source, observations, checks, summary, *, profile="web"):
        from .security import ScopeError
        if source not in {"http-import", "openapi", "manual"}:
            raise ScopeError("Unknown offline analysis source.")
        scan_id = new_id()
        mode = "manual" if source == "manual" else "import"
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            program = self._program(connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone())
            target = self.validate_scan(program, target_url, mode, profile)
            observed_at = utcnow()
            scan = {"id": scan_id, "program_id": program_id, "target_url": target.url, "mode": mode, "source": source}
            connection.execute("""INSERT INTO scans(id,program_id,target_url,mode,status,created_at,started_at,finished_at,
                findings_count,checks,profile,source,summary) VALUES(?,?,?,?,'completed',?,?,?,?,?,?,?,?)""",
                (scan_id, program_id, target.url, mode, observed_at, observed_at, observed_at, len(observations), json.dumps(checks), profile, source, json.dumps(summary)))
            ids = self._persist_observations(connection, scan, program, observations, observed_at)
            self._audit(connection, "analysis.completed", f"Completed {source} record {scan_id} for program {program_id}; zero network requests; {len(observations)} observations. Raw import content is not retained.")
        return self.get_scan(scan_id), ids

    def fail_scan(self, scan_id, error):
        with self.connect() as connection:
            changed = connection.execute("UPDATE scans SET status='failed',finished_at=?,error=? WHERE id=? AND status='running'", (utcnow(), error[:1000], scan_id)).rowcount
            if changed:
                self._audit(connection, "scan.failed", f"Scan {scan_id} failed: {error[:1000]}")

    def findings(self):
        with self.connect() as connection:
            return [self._finding(row) for row in connection.execute(self._FINDING_SELECT + " ORDER BY f.created_at DESC LIMIT 2000")]

    def program_findings(self, program_id):
        with self.connect() as connection:
            self._program(connection.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone())
            return [self._finding(row) for row in connection.execute(self._FINDING_SELECT + " WHERE f.program_id=? ORDER BY f.created_at DESC", (program_id,))]

    def occurrences(self, finding_id):
        with self.connect() as connection:
            if connection.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone() is None:
                raise NotFound("Finding not found.")
            return [dict(row) for row in connection.execute("SELECT id,scan_id,observed_at,severity,evidence,source FROM finding_occurrences WHERE finding_id=? ORDER BY observed_at DESC,rowid DESC LIMIT 100", (finding_id,))]

    def get_finding(self, finding_id):
        with self.connect() as connection:
            return self._finding(connection.execute(self._FINDING_SELECT + " WHERE f.id=?", (finding_id,)).fetchone())

    def update_finding(self, finding_id, status, notes):
        with self.connect() as connection:
            if connection.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone() is None:
                raise NotFound("Finding not found.")
            if notes is None:
                connection.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
            else:
                connection.execute("UPDATE findings SET status=?,notes=? WHERE id=?", (status, notes, finding_id))
            self._audit(connection, "finding.updated", f"Finding {finding_id} marked {status}; operator notes are not copied into the audit log.")
        return self.get_finding(finding_id)

    def audit(self):
        with self.connect() as connection:
            return [{key: row[key] for key in ("id", "action", "detail", "created_at")} for row in connection.execute("SELECT * FROM audit ORDER BY sequence DESC LIMIT 500")]

    def overview(self):
        with self.connect() as connection:
            counts = {row["severity"]: row["total"] for row in connection.execute("SELECT severity,COUNT(*) AS total FROM findings WHERE status IN ('open','validated') GROUP BY severity")}
            total_open = sum(counts.values())
            completed = connection.execute("SELECT COUNT(*) FROM scans WHERE status='completed'").fetchone()[0]
        programs = self.programs()
        return {
            "programs": len(programs), "assets": sum(len(program["scope_origins"]) for program in programs),
            "open_findings": total_open, "completed_scans": completed,
            "findings_by_severity": {severity: counts.get(severity, 0) for severity in ("high", "medium", "low", "info")},
            "recent_scans": self.scans()[:6], "recent_findings": self.findings()[:6],
        }
