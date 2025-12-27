from datetime import datetime, timedelta, timezone
import time

from fastapi.testclient import TestClient
import pytest

from scopeforge.db import Database
from scopeforge.catalog import get_checks
from scopeforge.main import create_app
from scopeforge.scanner import demo_snapshot
from scopeforge.worker import Worker

CLIENT_HEADERS = {"X-ScopeForge-Client": "dashboard"}


@pytest.fixture(autouse=True)
def forbid_live_network(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("Tests must not resolve or contact third-party targets")
    monkeypatch.setattr("scopeforge.scanner.resolve_public_addresses", reject)


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "test.sqlite3", start_worker=False), base_url="http://127.0.0.1") as client:
        yield client


def payload(**changes):
    return {
        "name": "Authorized example program", "policy_url": "https://example.com/security-policy",
        "authorization_note": "Owner permission recorded for the exact example origin.",
        "scope_origins": ["https://example.com"], "excluded_paths": ["/admin"],
        "request_interval_ms": 1000,
        "authorization_expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "authorized": True, **changes,
    }


def create_program(client, **changes):
    response = client.post("/api/programs", headers=CLIENT_HEADERS, json=payload(**changes))
    assert response.status_code == 201, response.text
    return response.json()


def run_demo(client):
    demo = next(program for program in client.get("/api/programs").json() if program["is_demo"])
    response = client.post("/api/scans", headers=CLIENT_HEADERS, json={"program_id": demo["id"], "target_url": demo["scope_origins"][0], "mode": "demo"})
    assert response.status_code == 202, response.text
    return response.json()


def finish_queued_demo(client):
    queued = run_demo(client)
    worker = client.app.state.worker
    scan = worker.database.claim_next()
    assert scan["id"] == queued["id"]
    worker.execute(scan)
    return client.get(f"/api/scans/{scan['id']}").json()


@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1.evil.example", "localhost.evil.example", "testserver", "[::1]", "localhost:99999"])
def test_rebinding_hosts_rejected(client, host):
    response = client.get("/api/programs", headers={"Host": host})
    assert response.status_code == 403


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost:9999", "https://localhost:5173", "http://127.0.0.1.evil.example"])
def test_cross_origin_access_rejected(client, origin):
    assert client.get("/api/programs", headers={"Origin": origin}).status_code == 403
    assert client.post("/api/programs", headers={**CLIENT_HEADERS, "Origin": origin}, json=payload()).status_code == 403


@pytest.mark.parametrize("origin", ["http://127.0.0.1", "http://localhost:5173", "http://127.0.0.1:5173"])
def test_own_and_exact_dev_proxy_origin_allowed_without_cors(client, origin):
    response = client.post("/api/programs", headers={**CLIENT_HEADERS, "Origin": origin}, json=payload())
    assert response.status_code == 201
    assert "access-control-allow-origin" not in response.headers


def test_mutations_require_client_header_and_cross_site_blocked(client):
    assert client.post("/api/programs", json=payload()).status_code == 403
    assert client.post("/api/programs", headers={"X-ScopeForge-Client": "wrong"}, json=payload()).status_code == 403
    assert client.get("/api/programs", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert len(client.get("/api/programs").json()) == 1
    response = client.get("/api/health")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_api_body_cap_is_enforced_before_mutation(client):
    response = client.post("/api/programs", headers={**CLIENT_HEADERS, "Content-Type": "application/json"}, content=b"x" * (32 * 1024 + 1))
    assert response.status_code == 413
    assert len(client.get("/api/programs").json()) == 1
    # Suppress Content-Length to exercise cumulative chunk/body enforcement.
    request = client.build_request("POST", "/api/programs", headers={**CLIENT_HEADERS, "Content-Type": "application/json"}, content=b"x" * (32 * 1024 + 1))
    del request.headers["content-length"]
    assert client.send(request).status_code == 413


@pytest.mark.parametrize("changes", [
    {"authorized": False}, {"authorized": "true"}, {"request_interval_ms": 999},
    {"request_interval_ms": 60001}, {"authorization_expires_at": "2020-01-01T00:00:00Z"},
    {"authorization_expires_at": "2099-01-01T00:00:00"}, {"scope_origins": ["https://*.example.com"]},
    {"scope_origins": ["https://example.com/path"]}, {"excluded_paths": ["/a/../admin"]},
    {"policy_url": "javascript:alert(1)"}, {"authorization_note": "            "},
    {"policy_url": "https://@example.com/policy"}, {"policy_url": "https://example.com:bad/policy"},
    {"is_demo": True},
])
def test_program_requires_bounded_explicit_authorization(client, changes):
    response = client.post("/api/programs", headers=CLIENT_HEADERS, json=payload(**changes))
    assert response.status_code == 422, response.text


def test_program_normalizes_scope_without_inferring_policy_host(client):
    program = create_program(client, policy_url="https://policies.example.org/rules?revision=3", scope_origins=["https://EXAMPLE.COM:443/", "https://example.com"])
    assert program["scope_origins"] == ["https://example.com"]
    assert not program["is_demo"]
    assets = client.get("/api/assets").json()
    assert any(asset["origin"] == "https://example.com" for asset in assets)
    assert not any("policies.example.org" in asset["origin"] for asset in assets)


@pytest.mark.parametrize("url", ["https://example.com/admin", "https://example.com/%61dmin", "https://sub.example.com/", "https://example.com/a/../admin", "http://example.com/", "https://example.com/?token=x"])
def test_scan_scope_escape_rejected_before_queueing(client, url):
    program = create_program(client)
    response = client.post("/api/scans", headers=CLIENT_HEADERS, json={"program_id": program["id"], "target_url": url, "mode": "passive"})
    assert response.status_code == 422
    assert client.get("/api/scans").json() == []


def test_demo_mode_cannot_contact_real_targets_and_real_mode_cannot_use_demo(client):
    demo = client.get("/api/programs").json()[0]
    real = create_program(client)
    for program, mode in [(demo, "passive"), (real, "demo")]:
        response = client.post("/api/scans", headers=CLIENT_HEADERS, json={"program_id": program["id"], "target_url": program["scope_origins"][0], "mode": mode})
        assert response.status_code == 422


def test_offline_demo_lifecycle_dedup_triage_report_and_audit(client):
    scan = finish_queued_demo(client)
    assert scan["status"] == "completed"
    assert scan["requests_made"] == 0
    assert scan["findings_count"] >= 6
    assert set(scan["checks"]) == {check["id"] for check in get_checks() if "headers" in check["profiles"]}
    findings = client.get("/api/findings").json()
    assert all(item["is_demo"] for item in findings)
    assert all(item["severity"] in {"low", "info"} for item in findings)
    assert "SYNTHETIC_NOT_A_SECRET" not in str(findings)
    finding = findings[0]
    update = client.patch(f"/api/findings/{finding['id']}", headers=CLIENT_HEADERS, json={"status": "validated", "notes": "Reviewed offline fixture; no real target tested."})
    assert update.status_code == 200
    second = finish_queued_demo(client)
    repeated = client.get("/api/findings").json()
    assert len(repeated) == len(findings)
    same = next(item for item in repeated if item["id"] == finding["id"])
    assert same["status"] == "validated"
    assert same["notes"] == "Reviewed offline fixture; no real target tested."
    assert same["scan_id"] == second["id"]
    report = client.get(f"/api/findings/{finding['id']}/report")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/plain")
    assert ".md" in report.headers["content-disposition"]
    assert "SYNTHETIC OFFLINE DEMO" in report.text
    assert "does not establish exploitability" in report.text
    assert "SYNTHETIC_NOT_A_SECRET" not in report.text
    assert "Reviewed offline fixture" in report.text
    overview = client.get("/api/overview").json()
    assert overview["completed_scans"] == 2
    assert overview["open_findings"] == len(findings)
    assert overview["findings_by_severity"]["high"] == 0
    audit = client.get("/api/audit").json()
    assert {item["action"] for item in audit} >= {"program.created", "scan.queued", "scan.completed", "finding.updated"}


def test_cancellation_is_persistent_and_idempotent(client):
    scan = run_demo(client)
    url = f"/api/scans/{scan['id']}/cancel"
    cancelled = client.post(url, headers=CLIENT_HEADERS).json()
    assert cancelled["status"] == "cancelled"
    assert client.post(url, headers=CLIENT_HEADERS).json()["finished_at"] == cancelled["finished_at"]
    assert client.app.state.database.claim_next() is None
    assert client.get("/api/findings").json() == []


def test_revocation_cancels_pending_jobs_and_blocks_future_jobs(client):
    scan = run_demo(client)
    response = client.post(f"/api/programs/{scan['program_id']}/revoke", headers=CLIENT_HEADERS)
    assert response.status_code == 200
    assert not response.json()["authorized"]
    assert client.get(f"/api/scans/{scan['id']}").json()["status"] == "cancelled"
    response = client.post("/api/scans", headers=CLIENT_HEADERS, json={"program_id": scan["program_id"], "target_url": scan["target_url"], "mode": "demo"})
    assert response.status_code == 422


def test_queue_rechecks_expiry_at_execution(client):
    scan = run_demo(client)
    database = client.app.state.database
    with database.connect() as connection:
        connection.execute("UPDATE programs SET authorization_expires_at='2020-01-01T00:00:00Z' WHERE id=?", (scan["program_id"],))
    claimed = database.claim_next()
    client.app.state.worker.execute(claimed)
    result = client.get(f"/api/scans/{scan['id']}").json()
    assert result["status"] == "failed"
    assert "expired" in result["error"]
    assert result["requests_made"] == 0


def test_queue_rechecks_scope_before_execution(client):
    scan = run_demo(client)
    database = client.app.state.database
    with database.connect() as connection:
        connection.execute("UPDATE programs SET excluded_paths='[\"/\"]' WHERE id=?", (scan["program_id"],))
    client.app.state.worker.execute(database.claim_next())
    result = database.get_scan(scan["id"])
    assert result["status"] == "failed"
    assert "exclusion" in result["error"]


def test_revocation_during_inflight_request_discards_results(client, monkeypatch):
    database = client.app.state.database
    program = create_program(client)
    scan = database.create_scan(program["id"], "https://example.com/", "passive")
    def fake_fetch(target, *, before_request, before_send):
        before_request()
        before_send()
        database.revoke_program(program["id"])
        return demo_snapshot()
    monkeypatch.setattr("scopeforge.worker.fetch_headers", fake_fetch)
    client.app.state.worker.execute(database.claim_next())
    result = database.get_scan(scan["id"])
    assert result["status"] == "cancelled"
    assert result["requests_made"] == 1
    assert database.findings() == []


def test_pacing_is_persistent_per_program(client, monkeypatch):
    database = client.app.state.database
    program = create_program(client)
    first = database.create_scan(program["id"], "https://example.com/", "passive")
    first = database.claim_next()
    monkeypatch.setattr("scopeforge.db.time.time", lambda: 1000.0)
    assert database.request_gate(first["id"], program["id"]) == 0
    second = database.create_scan(program["id"], "https://example.com/second", "passive")
    second = database.claim_next()
    monkeypatch.setattr("scopeforge.db.time.time", lambda: 1000.25)
    assert database.request_gate(second["id"], program["id"]) == pytest.approx(0.75)
    assert database.get_scan(second["id"])["requests_made"] == 0
    reopened = Database(database.path)
    assert reopened.request_gate(second["id"], program["id"]) == pytest.approx(0.75)
    monkeypatch.setattr("scopeforge.db.time.time", lambda: 1001.0)
    assert reopened.request_gate(second["id"], program["id"]) == 0
    assert database.get_scan(second["id"])["requests_made"] == 1


def test_slow_handshake_does_not_compress_actual_request_spacing(client, monkeypatch):
    database = client.app.state.database
    program = create_program(client)
    database.create_scan(program["id"], "https://example.com/", "passive")
    first = database.claim_next()
    monkeypatch.setattr("scopeforge.db.time.time", lambda: 1000.0)
    assert database.request_gate(first["id"], program["id"]) == 0
    # Simulate nine seconds of TCP/TLS establishment before the actual GET.
    monkeypatch.setattr("scopeforge.db.time.time", lambda: 1009.0)
    database.before_send(first)
    database.create_scan(program["id"], "https://example.com/second", "passive")
    second = database.claim_next()
    monkeypatch.setattr("scopeforge.db.time.time", lambda: 1009.25)
    assert database.request_gate(second["id"], program["id"]) == pytest.approx(0.75)
    assert database.get_scan(first["id"])["requests_made"] == 1
    with pytest.raises(ValueError, match="single request"):
        database.request_gate(first["id"], program["id"])


def test_revocation_during_handshake_blocks_http_write(client, monkeypatch):
    database = client.app.state.database
    program = create_program(client)
    scan = database.create_scan(program["id"], "https://example.com/", "passive")
    writes = []
    def fake_fetch(target, *, before_request, before_send):
        before_request()
        database.revoke_program(program["id"])
        before_send()
        writes.append("GET")
        return demo_snapshot()
    monkeypatch.setattr("scopeforge.worker.fetch_headers", fake_fetch)
    client.app.state.worker.execute(database.claim_next())
    assert writes == []
    assert database.get_scan(scan["id"])["status"] == "cancelled"
    assert database.findings() == []


def test_restart_keeps_queue_but_fails_ambiguous_running_jobs_without_replay(tmp_path):
    path = tmp_path / "restart.sqlite3"
    database = Database(path)
    demo = database.programs()[0]
    first = database.create_scan(demo["id"], demo["scope_origins"][0] + "/", "demo")
    database.claim_next()
    second = database.create_scan(demo["id"], demo["scope_origins"][0] + "/next", "demo")
    with TestClient(create_app(path), base_url="http://127.0.0.1") as client:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            completed = client.get(f"/api/scans/{second['id']}").json()
            if completed["status"] == "completed":
                break
            time.sleep(0.01)
        assert completed["status"] == "completed"
        interrupted = client.get(f"/api/scans/{first['id']}").json()
        assert interrupted["status"] == "failed"
        assert "may have been sent" in interrupted["error"]
        assert client.get("/api/health").json()["worker"] == "running"
    reloaded = Database(path)
    assert len(reloaded.programs()) == 1
    assert reloaded.findings()
    assert reloaded.get_scan(second["id"])["status"] == "completed"
    assert any(event["action"] == "worker.recovered" for event in reloaded.audit())


def test_unknown_resources_and_api_routes_are_json_404(client):
    for url in ["/api/scans/missing", "/api/findings/missing/report", "/api/unknown"]:
        response = client.get(url)
        assert response.status_code == 404
        assert "detail" in response.json()
    assert client.patch("/api/findings/missing", headers=CLIENT_HEADERS, json={"status": "open"}).status_code == 404
