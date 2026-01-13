"""Authorization, atomic queueing, provenance, and historical record regressions."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from scopeforge.db import Database, QueueFull
from scopeforge.scanner import demo_snapshot
from test_api import CLIENT_HEADERS, client, create_program, finish_queued_demo, forbid_live_network, payload, run_demo


def batch(client, program, targets, profile="headers"):
    return client.post("/api/scans/batch", headers=CLIENT_HEADERS, json={"program_id": program["id"], "target_urls": targets, "profile": profile})


def manual_payload(program, **changes):
    return {
        "program_id": program["id"], "target_url": program["scope_origins"][0],
        "title": "Analyst documented observation", "severity": "medium", "confidence": "low",
        "description": "Owner-provided evidence requires independent manual verification.",
        "impact": "Impact is a hypothesis awaiting authorized verification.",
        "remediation": "Review the configuration and follow the owner's guidance.",
        "evidence": "Sanitized analyst description without credentials.", "cwe": "CWE-200",
        "notes": "Analyst supplied this record; no automated reproduction.", **changes,
    }


def test_profiles_are_explicit_permission_and_demo_supports_web(client):
    real = create_program(client)
    demo = next(item for item in client.get("/api/programs").json() if item["is_demo"])
    assert real["allowed_profiles"] == ["headers"]
    assert demo["allowed_profiles"] == ["headers", "web"]
    rejected = client.post("/api/scans", headers=CLIENT_HEADERS, json={"program_id": real["id"], "target_url": real["scope_origins"][0], "mode": "passive", "profile": "web"})
    assert rejected.status_code == 422
    assert client.get("/api/scans").json() == []
    allowed = create_program(client, allowed_profiles=["headers", "web"])
    assert batch(client, allowed, ["https://example.com/a"], "web").status_code == 202


@pytest.mark.parametrize("profiles", [[], ["headers", "headers"], ["exploit"], ["headers", "web", "headers"]])
def test_invalid_permission_profiles_rejected(client, profiles):
    assert client.post("/api/programs", headers=CLIENT_HEADERS, json=payload(allowed_profiles=profiles)).status_code == 422
    assert len(client.get("/api/programs").json()) == 1


@pytest.mark.parametrize("stage,attempts", [("reservation", 0), ("send", 1), ("completion", 1)])
def test_profile_permission_rechecked_at_every_boundary(client, monkeypatch, stage, attempts):
    program = create_program(client, allowed_profiles=["headers", "web"])
    database = client.app.state.database
    scan = database.create_scan(program["id"], "https://example.com/", "passive", "web")

    def remove_profile():
        with database.connect() as connection:
            connection.execute("UPDATE programs SET allowed_profiles='[\"headers\"]' WHERE id=?", (program["id"],))

    def fake_fetch(target, *, before_request, before_send, profile):
        assert profile == "web"
        if stage == "reservation":
            remove_profile()
        before_request()
        if stage == "send":
            remove_profile()
        before_send()
        if stage == "completion":
            remove_profile()
        return demo_snapshot(profile="web")

    monkeypatch.setattr("scopeforge.worker.fetch_headers", fake_fetch)
    client.app.state.worker.execute(database.claim_next())
    result = database.get_scan(scan["id"])
    assert result["status"] == "failed"
    assert "profile" in result["error"]
    assert result["requests_made"] == attempts
    assert database.findings() == []


def test_batch_explicit_targets_budget_and_atomic_validation(client):
    program = create_program(client)
    response = batch(client, program, ["https://example.com/a", "https://EXAMPLE.COM:443/b"])
    assert response.status_code == 202
    assert response.json()["submitted"] == response.json()["request_budget"] == 2
    assert [scan["target_url"] for scan in response.json()["scans"]] == ["https://example.com/a", "https://example.com/b"]
    assert all(scan["profile"] == "headers" and scan["source"] == "scan" and scan["requests_made"] == 0 for scan in response.json()["scans"])
    for targets in [[], ["https://example.com/a"] * 2, ["https://example.com", "https://example.com:443/"], ["https://example.com/c", "https://example.com/admin"], ["https://example.com/c", "https://elsewhere.example/"], [f"https://example.com/{i}" for i in range(21)]]:
        assert batch(client, program, targets).status_code == 422
        assert len(client.get("/api/scans").json()) == 2
    demo = next(item for item in client.get("/api/programs").json() if item["is_demo"])
    assert batch(client, demo, demo["scope_origins"]).status_code == 422


def test_batch_queue_capacity_is_all_or_nothing(client):
    database = client.app.state.database
    program = create_program(client)
    for offset in range(0, 80, 20):
        database.create_scans(program["id"], [f"https://example.com/{i}" for i in range(offset, offset + 20)])
    database.create_scans(program["id"], [f"https://example.com/{i}" for i in range(80, 95)])
    assert batch(client, program, [f"https://example.com/next{i}" for i in range(6)]).status_code == 429
    assert len(database.scans()) == 95
    assert batch(client, program, [f"https://example.com/last{i}" for i in range(5)]).status_code == 202
    assert len(database.scans()) == 100


def test_concurrent_admission_never_exceeds_queue_limit(client):
    database = client.app.state.database
    program = create_program(client)
    for offset in range(0, 80, 20):
        database.create_scans(program["id"], [f"https://example.com/{i}" for i in range(offset, offset + 20)])
    database.create_scans(program["id"], [f"https://example.com/{i}" for i in range(80, 99)])

    def submit(index):
        try:
            database.create_scan(program["id"], f"https://example.com/concurrent{index}", "passive")
            return "queued"
        except QueueFull:
            return "full"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, range(2))) == ["full", "queued"]
    assert len(database.scans()) == 100


def test_stop_all_can_filter_program_and_is_idempotent(client):
    demo_scan = run_demo(client)
    program = create_program(client)
    batch(client, program, ["https://example.com/a", "https://example.com/b"])
    response = client.post("/api/scans/cancel-all", headers=CLIENT_HEADERS, json={"program_id": program["id"]})
    assert response.json() == {"cancelled": 2}
    assert client.app.state.database.get_scan(demo_scan["id"])["status"] == "queued"
    response = client.post("/api/scans/cancel-all", headers=CLIENT_HEADERS, json={})
    assert response.json() == {"cancelled": 1}
    assert client.post("/api/scans/cancel-all", headers=CLIENT_HEADERS, json={}).json() == {"cancelled": 0}
    assert client.post("/api/scans/cancel-all", headers=CLIENT_HEADERS, json={"program_id": "missing"}).status_code == 404


def test_emergency_stop_during_response_discards_findings(client, monkeypatch):
    program = create_program(client)
    database = client.app.state.database
    scan = database.create_scan(program["id"], "https://example.com/", "passive")

    def fake_fetch(target, *, before_request, before_send):
        before_request()
        before_send()
        assert database.cancel_all() == 1
        return demo_snapshot()

    monkeypatch.setattr("scopeforge.worker.fetch_headers", fake_fetch)
    client.app.state.worker.execute(database.claim_next())
    assert database.get_scan(scan["id"])["status"] == "cancelled"
    assert database.findings() == []


def test_manual_finding_is_scoped_attributed_and_zero_network(client):
    program = create_program(client)
    response = client.post("/api/findings", headers=CLIENT_HEADERS, json=manual_payload(program))
    assert response.status_code == 201, response.text
    finding = response.json()
    assert finding["source"] == "manual" and finding["check_id"].startswith("manual:")
    assert finding["occurrence_count"] == 1 and finding["first_seen"] == finding["last_seen"]
    assert finding["cwe"] == "CWE-200"
    scan = client.get(f"/api/scans/{finding['scan_id']}").json()
    assert scan["mode"] == scan["source"] == "manual"
    assert scan["status"] == "completed" and scan["requests_made"] == 0
    assert scan["checks"] == [] and scan["summary"]["independently_verified"] is False
    occurrences = client.get(f"/api/findings/{finding['id']}/occurrences").json()
    assert len(occurrences) == 1 and occurrences[0]["source"] == "manual"
    assert occurrences[0]["evidence"] == finding["evidence"]
    report = client.get(f"/api/findings/{finding['id']}/report").text
    assert "Analyst-entered" in report and "ScopeForge did not independently observe" in report
    assert "same URL's response headers with a single GET" not in report
    assert "CWE-200" in report and "Observations recorded: 1" in report
    assert client.app.state.database.claim_next() is None
    demo = next(item for item in client.get("/api/programs").json() if item["is_demo"])
    assert client.post("/api/findings", headers=CLIENT_HEADERS, json=manual_payload(demo)).json()["is_demo"] is True


@pytest.mark.parametrize("changes", [{"target_url": "https://example.com/admin"}, {"target_url": "https://outside.example/"}, {"cwe": "CWE-1<script>"}, {"cwe": "cwe-200"}, {"evidence": "   "}, {"severity": "critical"}, {"source": "scan"}])
def test_manual_invalid_input_does_not_create_records(client, changes):
    program = create_program(client)
    assert client.post("/api/findings", headers=CLIENT_HEADERS, json=manual_payload(program, **changes)).status_code == 422
    assert client.get("/api/findings").json() == []
    assert client.get("/api/scans").json() == []


def test_manual_authorization_rechecked_inside_commit(client, monkeypatch):
    program = create_program(client)
    database = client.app.state.database
    original = database.create_offline_result

    def revoke_then_commit(*args, **kwargs):
        database.revoke_program(program["id"])
        return original(*args, **kwargs)

    monkeypatch.setattr(database, "create_offline_result", revoke_then_commit)
    assert client.post("/api/findings", headers=CLIENT_HEADERS, json=manual_payload(program)).status_code == 422
    assert database.findings() == database.scans() == []


def test_occurrence_snapshots_preserve_evidence_and_operator_triage(client):
    scan = finish_queued_demo(client)
    database = client.app.state.database
    finding = database.findings()[0]
    old_evidence = finding["evidence"]
    database.update_finding(finding["id"], "validated", "Retained analyst notes")
    second = database.create_scan(scan["program_id"], scan["target_url"], "demo")
    observation = {**finding, "evidence": "A changed sanitized response observation", "severity": "low"}
    database.finish_scan(database.claim_next(), [observation], [finding["check_id"]])
    updated = database.get_finding(finding["id"])
    assert updated["id"] == finding["id"]
    assert updated["first_seen"] == finding["first_seen"] and updated["last_seen"] >= finding["last_seen"]
    assert updated["status"] == "validated" and updated["notes"] == "Retained analyst notes"
    assert updated["occurrence_count"] == 2
    history = database.occurrences(finding["id"])
    assert [item["scan_id"] for item in history] == [second["id"], scan["id"]]
    assert history[0]["evidence"] == observation["evidence"] and history[1]["evidence"] == old_evidence
    database.finish_scan(second, [observation], [finding["check_id"]])
    assert len(database.occurrences(finding["id"])) == 2


def test_program_exports_are_complete_and_do_not_mix_programs(client):
    finish_queued_demo(client)
    program = create_program(client)
    finding = client.post("/api/findings", headers=CLIENT_HEADERS, json=manual_payload(program)).json()
    response = client.get(f"/api/programs/{program['id']}/report?format=json")
    assert response.status_code == 200
    assert response.json()["version"] == "0.2.0"
    assert [item["id"] for item in response.json()["findings"]] == [finding["id"]]
    assert ".json" in response.headers["content-disposition"]
    markdown = client.get(f"/api/programs/{program['id']}/report")
    assert ".md" in markdown.headers["content-disposition"]
    assert "Recorded findings: 1" in markdown.text and "Analyst-entered" in markdown.text
    assert "SYNTHETIC OFFLINE DEMO" not in markdown.text
    assert client.get(f"/api/programs/{program['id']}/report?format=html").status_code == 422
    assert client.get("/api/programs/missing/report").status_code == 404
    assert client.get("/api/findings/missing/occurrences").status_code == 404


def test_validation_errors_do_not_echo_operator_secrets(client):
    program = create_program(client)
    secret = "SECRET_CAPTURE_NEVER_ECHO"
    response = client.post("/api/findings", headers=CLIENT_HEADERS, json=manual_payload(program, cwe=secret))
    assert response.status_code == 422 and secret not in response.text
    response = client.post("/api/imports/analyze", headers=CLIENT_HEADERS, json={"program_id": program["id"], "target_url": program["scope_origins"][0], "format": "http", "content": secret * 13000})
    assert response.status_code == 422 and secret not in response.text


def test_only_import_route_has_large_request_wrapper_budget(client):
    for path, size in [("/api/imports/analyze", 1024 * 1024 + 1), ("/api/findings", 32 * 1024 + 1), ("/api/imports/analyze/extra", 32 * 1024 + 1)]:
        for with_length in [True, False]:
            request = client.build_request("POST", path, headers={**CLIENT_HEADERS, "Content-Type": "application/json"}, content=b"x" * size)
            if not with_length:
                del request.headers["content-length"]
            assert client.send(request).status_code == 413


def legacy_database(path):
    """Create the complete v1 schema with representative saved user state."""
    with sqlite3.connect(path) as connection:
        connection.executescript('''
            CREATE TABLE programs(id TEXT PRIMARY KEY,name TEXT NOT NULL,policy_url TEXT NOT NULL,
              authorization_note TEXT NOT NULL,scope_origins TEXT NOT NULL,excluded_paths TEXT NOT NULL,
              request_interval_ms INTEGER NOT NULL,authorization_expires_at TEXT NOT NULL,authorized INTEGER NOT NULL,
              is_demo INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,last_request_at REAL);
            CREATE TABLE scans(id TEXT PRIMARY KEY,program_id TEXT NOT NULL REFERENCES programs(id),target_url TEXT NOT NULL,
              mode TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,started_at TEXT,finished_at TEXT,
              requests_made INTEGER NOT NULL DEFAULT 0,findings_count INTEGER NOT NULL DEFAULT 0,error TEXT,checks TEXT NOT NULL DEFAULT '[]');
            CREATE TABLE findings(id TEXT PRIMARY KEY,program_id TEXT NOT NULL REFERENCES programs(id),scan_id TEXT NOT NULL REFERENCES scans(id),
              target_url TEXT NOT NULL,check_id TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL,
              description TEXT NOT NULL,impact TEXT NOT NULL,remediation TEXT NOT NULL,evidence TEXT NOT NULL,status TEXT NOT NULL,
              notes TEXT NOT NULL DEFAULT '',is_demo INTEGER NOT NULL,created_at TEXT NOT NULL,UNIQUE(program_id,target_url,check_id));
            CREATE TABLE audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,action TEXT NOT NULL,detail TEXT NOT NULL,created_at TEXT NOT NULL);
            PRAGMA user_version=1;
        ''')
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        for pid, demo in [("real", 0), ("demo", 1)]:
            connection.execute("INSERT INTO programs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (pid, "Saved program", "https://example.com/policy", "Saved owner permission", '["https://example.com"]', '[]', 1500, expiry, 1, demo, "2026-01-01T00:00:00Z", 123.4))
        connection.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("old-scan", "real", "https://example.com/", "passive", "completed", "2026-01-02T00:00:00Z", "2026-01-02T00:00:01Z", "2026-01-02T00:00:02Z", 1, 1, None, '["saved-check"]'))
        connection.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("saved-finding", "real", "old-scan", "https://example.com/", "saved-check", "Saved title", "low", "high", "Saved description", "Saved impact", "Saved remediation", "Saved sanitized evidence", "validated", "Keep my notes", 0, "2026-01-01T00:00:00Z"))
        connection.execute("INSERT INTO audit(id,action,detail,created_at) VALUES('audit1','finding.updated','Historical event','2026-01-02T00:00:03Z')")


def test_version1_migration_preserves_records_and_is_idempotent(tmp_path):
    path = tmp_path / "legacy.sqlite"
    legacy_database(path)
    database = Database(path)
    assert len(database.programs()) == 2
    assert database.get_program("real")["allowed_profiles"] == ["headers"]
    assert database.get_program("demo")["allowed_profiles"] == ["headers", "web"]
    finding = database.get_finding("saved-finding")
    assert finding["status"] == "validated" and finding["notes"] == "Keep my notes"
    assert finding["first_seen"] == "2026-01-01T00:00:00Z"
    assert finding["last_seen"] == "2026-01-02T00:00:02Z"
    assert finding["occurrence_count"] == 1 and finding["source"] == "scan"
    assert len(database.occurrences(finding["id"])) == 1
    assert database.occurrences(finding["id"])[0]["evidence"] == "Saved sanitized evidence"
    assert database.get_scan("old-scan")["requests_made"] == 1
    assert database.audit()[0]["id"] == "audit1"
    with database.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute("SELECT last_request_at FROM programs WHERE id='real'").fetchone()[0] == 123.4
    reopened = Database(path)
    assert reopened.get_finding("saved-finding") == finding
    assert len(reopened.occurrences(finding["id"])) == 1


def test_schema_upgrade_is_transactional_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "rollback.sqlite"
    legacy_database(path)
    original = Database._migrate_v2

    def fail_after_ddl(connection):
        original(connection)
        raise RuntimeError("Simulated failure after migration DDL")

    monkeypatch.setattr(Database, "_migrate_v2", staticmethod(fail_after_ddl))
    with pytest.raises(RuntimeError, match="Simulated failure"):
        Database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert "allowed_profiles" not in {row[1] for row in connection.execute("PRAGMA table_info(programs)")}
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='finding_occurrences'").fetchone()
        assert connection.execute("SELECT notes FROM findings WHERE id='saved-finding'").fetchone()[0] == "Keep my notes"


def test_future_schema_is_rejected_without_downgrading(tmp_path):
    path = tmp_path / "future.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=99")
    with pytest.raises(RuntimeError, match="newer schema"):
        Database(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 99


def import_payload(program, *, format="http", document=None, target_url=None):
    import json
    if document is None:
        document = {"status": 200, "headers": [{"name": "Content-Type", "value": "text/html"}, {"name": "Set-Cookie", "value": "session=CAPTURE_SECRET_SHOULD_NOT_PERSIST; Path=/"}, {"name": "Authorization", "value": "Bearer CAPTURE_SECRET_SHOULD_NOT_PERSIST"}], "body": "<form><input name='password' type='password'></form>"}
    return {"program_id": program["id"], "target_url": target_url or program["scope_origins"][0], "format": format, "content": json.dumps(document)}


def test_offline_import_http_and_openapi_have_distinct_provenance_and_no_secrets(client):
    program = create_program(client)
    http = client.post("/api/imports/analyze", headers=CLIENT_HEADERS, json=import_payload(program))
    assert http.status_code == 201, http.text
    scan = http.json()["scan"]
    assert scan["source"] == "http-import" and scan["mode"] == "import"
    assert scan["requests_made"] == 0 and scan["status"] == "completed"
    assert all(identifier.startswith("import-http:") for identifier in scan["checks"])
    records = client.app.state.database.findings()
    assert records and all(record["source"] == "http-import" for record in records)
    assert "CAPTURE_SECRET_SHOULD_NOT_PERSIST" not in str(records)
    assert "CAPTURE_SECRET_SHOULD_NOT_PERSIST" not in str(client.app.state.database.occurrences(records[0]["id"]))
    assert "CAPTURE_SECRET_SHOULD_NOT_PERSIST" not in str(client.app.state.database.audit())
    spec = {"openapi": "3.1.0", "info": {"title": "Synthetic API", "version": "1.0"}, "paths": {"/items": {"post": {"responses": {"200": {"description": "OK"}}}}}}
    response = client.post("/api/imports/analyze", headers=CLIENT_HEADERS, json=import_payload(program, format="openapi", document=spec))
    assert response.status_code == 201, response.text
    assert response.json()["scan"]["source"] == "openapi"
    assert response.json()["scan"]["requests_made"] == 0
    records = client.app.state.database.findings()
    api_record = next(record for record in records if record["source"] == "openapi")
    report = client.get(f"/api/findings/{api_record['id']}/report").text
    assert "No described endpoint was contacted" in report
    assert "same URL's response headers with a single GET" not in report
    assert client.app.state.database.claim_next() is None


def test_import_revalidation_blocks_revocation_between_analysis_and_commit(client, monkeypatch):
    from scopeforge.offline import analyze_import
    program = create_program(client)
    database = client.app.state.database

    def revoke_during_analysis(*args, **kwargs):
        result = analyze_import(*args, **kwargs)
        database.revoke_program(program["id"])
        return result

    monkeypatch.setattr("scopeforge.offline.analyze_import", revoke_during_analysis)
    response = client.post("/api/imports/analyze", headers=CLIENT_HEADERS, json=import_payload(program))
    assert response.status_code == 422
    assert database.scans() == database.findings() == []


def test_import_body_budget_utf8_depth_and_scope_are_enforced(client):
    program = create_program(client)
    large = import_payload(program, document={"status": 200, "headers": [], "body": "x" * (40 * 1024)})
    assert client.post("/api/imports/analyze", headers=CLIENT_HEADERS, json=large).status_code == 201
    before = len(client.app.state.database.scans())
    wrong_scope = import_payload(program, target_url="https://example.com/admin")
    assert client.post("/api/imports/analyze", headers=CLIENT_HEADERS, json=wrong_scope).status_code == 422
    base = import_payload(program)
    for content in ["🧪" * (70 * 1024), '[' * 45 + ']' * 45, '{"status":200,"headers":[],"unknown":"SECRET_BAD_CAPTURE"}', '{"secret":"SECRET_BAD_CAPTURE"']:
        response = client.post("/api/imports/analyze", headers=CLIENT_HEADERS, json={**base, "content": content})
        assert response.status_code == 422
        assert "SECRET_BAD_CAPTURE" not in response.text
    assert len(client.app.state.database.scans()) == before


def test_catalog_has_unique_implemented_rules_and_honest_limitations(client):
    from scopeforge.catalog import CHECK_DEFINITIONS
    from scopeforge.offline import OPENAPI_CHECKS
    response = client.get("/api/checks")
    assert response.status_code == 200
    checks = response.json()
    assert len(checks) == len({check["id"] for check in checks}) == len(CHECK_DEFINITIONS) + len(OPENAPI_CHECKS)
    assert all({"id", "title", "category", "profiles", "severity", "cwe", "description", "limitations", "reference_url"} <= check.keys() for check in checks)
    assert all(check["limitations"] and check["reference_url"].startswith("https://") for check in checks)
    assert any(check["profiles"] == ["web"] for check in checks)
    assert any(check["profiles"] == ["openapi"] for check in checks)
