"""Synthetic-only rule semantics, evidence privacy, and transport budget tests."""

import json

import pytest

from scopeforge import scanner
from scopeforge.catalog import CHECK_DEFINITIONS
from scopeforge.security import parse_target


BASE = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Strict-Transport-Security", "max-age=31536000"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
]


def observe(headers=(), body=None, url="https://example.com/", remove=()):
    names = {name.lower() for name, _ in headers} | set(remove)
    snapshot = scanner.Snapshot(200, [row for row in BASE if row[0].lower() not in names] + list(headers),
                               body=body or "", body_analyzed=body is not None)
    return {item["check_id"]: item for item in scanner.analyze_headers(parse_target(url), snapshot)}


def test_snapshot_positional_synthetic_compatibility_and_independent_metadata():
    first = scanner.Snapshot(200, [], True)
    second = scanner.Snapshot(200, [])
    first.metadata["test"] = True
    assert first.synthetic and not first.body_analyzed and first.body == ""
    assert second.metadata == {}


@pytest.mark.parametrize("value,rule", [
    ("max-age=0", "hsts-disabled"), ("max-age=000", "hsts-disabled"),
    ('max-age="0"', "hsts-disabled"), ("includeSubDomains", "hsts-invalid"),
    ("max-age=-1", "hsts-invalid"), ("max-age=NaN", "hsts-invalid"),
    ("max-age=1; max-age=2", "hsts-invalid"), ("max-age=1; max-age", "hsts-invalid"),
])
def test_hsts_weak_observed_values(value, rule):
    result = observe([("Strict-Transport-Security", value)])
    assert rule in result


@pytest.mark.parametrize("value", ["max-age=31536000; includeSubDomains", 'max-age="31536000"', "max-age=" + "9" * 5000])
def test_hsts_accepts_positive_and_large_valid_ages_without_int_conversion(value):
    assert not observe([("Strict-Transport-Security", value)])


def test_hsts_checks_only_first_field_and_ignores_http_policy():
    assert not observe([("Strict-Transport-Security", "max-age=31536000"), ("Strict-Transport-Security", "max-age=0")])
    assert "hsts-disabled" not in observe([("Strict-Transport-Security", "max-age=0")], url="http://example.com/")


@pytest.mark.parametrize("policies,expected", [
    (["script-src 'unsafe-inline' 'unsafe-eval' *"], {"csp-unsafe-inline", "csp-unsafe-eval", "csp-broad-script-sources"}),
    (["script-src 'unsafe-inline' 'nonce-YWJj'"], set()),
    (["script-src 'unsafe-inline' 'sha256-YWJj'"], set()),
    (["script-src 'unsafe-inline' 'strict-dynamic' * https:"], set()),
    (["script-src 'unsafe-inline' 'unsafe-eval' *", "default-src 'self'"], set()),
    (["script-src 'unsafe-inline' 'unsafe-eval' *, default-src 'self'"], set()),
    (["script-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' *"], set()),
    (["script-src 'unsafe-inline'; script-src 'self'"], {"csp-unsafe-inline"}),
    (["script-src https:", "script-src data:"], set()),
    (["script-src *", "script-src https:"], {"csp-broad-script-sources"}),
    (["script-src 'unsafe-inline' 'unsafe-eval' *; sandbox"], set()),
    (["script-src 'unsafe-inline'; script-src-elem 'none'"], set()),
    (["script-src 'none'; script-src-elem 'unsafe-inline'"], {"csp-unsafe-inline"}),
    (["default-src 'unsafe-inline' 'unsafe-eval' *"], {"csp-unsafe-inline", "csp-unsafe-eval", "csp-broad-script-sources", "csp-broad-object-sources"}),
])
def test_csp_effective_script_rules(policies, expected):
    result = observe([("Content-Security-Policy", value) for value in policies])
    actual = {rule for rule in result if rule.startswith("csp-")}
    assert actual == expected


def test_report_only_csp_does_not_create_weak_policy_findings():
    result = observe([("Content-Security-Policy-Report-Only", "script-src 'unsafe-inline' 'unsafe-eval' *")])
    assert not result


def test_meta_csp_can_constrain_but_does_not_create_weak_response_policy():
    result = observe([("Content-Security-Policy", "script-src 'unsafe-inline' 'unsafe-eval' *")],
                     '<head><meta http-equiv="Content-Security-Policy" content="script-src \'none\'"></head>')
    assert not any(rule in result for rule in ("csp-unsafe-inline", "csp-unsafe-eval", "csp-broad-script-sources"))
    result = observe([("Content-Security-Policy", "report-uri https://example.com/reports")],
                     '<head><meta http-equiv="Content-Security-Policy" content="script-src * \'unsafe-inline\' \'unsafe-eval\'"></head>')
    assert not any(rule.startswith("csp-") for rule in result)


@pytest.mark.parametrize("values,expected", [
    (["DENY"], False), (["SAMEORIGIN"], False), (["DENY", "DENY"], False),
    (["ALLOWALL"], True), (["ALLOW-FROM https://SECRET.example"], True),
    (["DENY", "SAMEORIGIN"], True), (["DENY, SAMEORIGIN"], True),
])
def test_invalid_framing_values(values, expected):
    result = observe([("Content-Security-Policy", "default-src 'self'")] + [("X-Frame-Options", value) for value in values])
    assert ("framing-policy-invalid" in result) is expected
    assert "SECRET" not in str(result)


def test_csp_frame_ancestors_precedence_and_multiple_policies():
    assert "framing-policy-invalid" not in observe([("X-Frame-Options", "ALLOWALL")])
    assert "csp-framing-wildcard" in observe([("Content-Security-Policy", "frame-ancestors *")])
    assert "csp-framing-wildcard" not in observe([("Content-Security-Policy", "frame-ancestors *"), ("Content-Security-Policy", "frame-ancestors 'self'")])


@pytest.mark.parametrize("policy,expected", [
    ("unsafe-url", True), ("no-referrer-when-downgrade", True),
    ("unsafe-url, no-referrer", False), ("no-referrer, unsafe-url", True),
    ("unsafe-url, not-a-policy", True), ("not-a-policy", False),
    ("origin-when-cross-origin", False),
])
def test_referrer_policy_last_recognized_value(policy, expected):
    assert ("referrer-policy-unsafe" in observe([("Referrer-Policy", policy)])) is expected


@pytest.mark.parametrize("cookie,expected", [
    ("session=SECRET; SameSite=None", {"cookie-flags:session", "cookie-samesite-none:session"}),
    ("session=SECRET; SameSite=None; Secure; HttpOnly", set()),
    ("__Host-session=SECRET; Secure; HttpOnly; SameSite=Lax; Path=/", set()),
    ("__Host-session=SECRET; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=SECRET.example", {"cookie-host-prefix:__Host-session"}),
    ("__Host-session=SECRET; Secure; HttpOnly; SameSite=Lax; Path=/other", {"cookie-host-prefix:__Host-session"}),
    ("__Secure-session=SECRET; Secure; HttpOnly; SameSite=Lax", set()),
    ("__Secure-session=SECRET; HttpOnly; SameSite=Lax", {"cookie-flags:__Secure-session", "cookie-secure-prefix:__Secure-session"}),
    ("__host-session=SECRET; Secure; HttpOnly; SameSite=Lax", set()),
    ("bad/SECRET=SECRET; SameSite=None", set()),
])
def test_cookie_prefixes_samesite_and_redaction(cookie, expected):
    result = observe([("Set-Cookie", cookie)])
    assert set(result) == expected
    assert "SECRET" not in str(result)


def test_secure_cookie_prefix_over_http_is_invalid_even_with_secure_flag():
    result = observe([("Set-Cookie", "__Secure-session=SECRET; Secure; HttpOnly; SameSite=Lax")], url="http://example.com/")
    assert "cookie-secure-prefix:__Secure-session" in result


@pytest.mark.parametrize("origin,credentials,expected", [("null", "true", True), ("null", "false", False), ("*", "true", False), ("null", "TRUE", False)])
def test_credentialed_null_origin_observation_is_precise(origin, credentials, expected):
    result = observe([("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", credentials)])
    assert ("cors-null-origin" in result) is expected


@pytest.mark.parametrize("cache,expected", [
    ("public, max-age=60", True), ("s-maxage=60", True), ('s-maxage="60"', True),
    ("public, no-cache", True), ("public, private", False), ("public, no-store", False),
    ('public, private="Set-Cookie"', False), ('no-cache="public, s-maxage=60"', False),
    ("max-age=60", False), ("s-maxage=0", False), ("s-maxage=-1", False),
])
def test_cache_rule_requires_explicit_shared_storage_and_excludes_private(cache, expected):
    result = observe([("Cache-Control", cache), ("Set-Cookie", "session=SECRET; Secure; HttpOnly; SameSite=Lax")])
    assert ("public-cache-cookie" in result) is expected
    assert "SECRET" not in str(result)


def test_cache_rule_does_not_claim_all_public_responses_or_cookies_sensitive():
    assert "public-cache-cookie" not in observe([("Cache-Control", "public, max-age=60")])
    result = observe([("Cache-Control", "public"), ("Set-Cookie", "preference=SECRET; Secure; HttpOnly; SameSite=Lax")])
    assert result["public-cache-cookie"]["severity"] == "info"
    assert "may be intentional" in result["public-cache-cookie"]["impact"]


def test_html_requires_explicit_body_analysis_and_exact_mime():
    body = '<form><input type="password" name="secret"></form>'
    snapshot = scanner.Snapshot(200, BASE, body=body)
    assert scanner.analyze_headers(parse_target("https://example.com/"), snapshot) == []
    assert "password-form-get" not in observe([("Content-Type", "text/html-malicious")], body)


def test_html_passive_analysis_counts_without_retaining_any_page_data():
    body = '''<head><base href="https://SECRET-CDN.example/"></head><body>
    <script src="http://SECRET-CDN.example/script?token=SECRET_TOKEN"></script>
    <link rel="stylesheet" href="https://SECRET-CDN.example/style?token=SECRET_TOKEN">
    <img src="http://SECRET-CDN.example/picture">
    <form action="http://SECRET-AUTH.example/login?token=SECRET_TOKEN">
    <input type="password" name="SECRET_FIELD" value="SECRET_PASSWORD"></form></body>'''
    result = observe(body=body)
    assert {"external-base", "mixed-content-active", "mixed-content-passive", "script-integrity", "stylesheet-integrity", "password-form-get", "password-form-http", "password-form-external"} <= set(result)
    assert "SECRET" not in json.dumps(result)
    assert "No resource loaded or form submitted" in result["password-form-get"]["evidence"]


def test_mixed_content_excludes_navigation_and_respects_upgrading_csp():
    body = '<a href="http://elsewhere.example/">link</a><script src="http://elsewhere.example/script"></script><img src="http://elsewhere.example/image">'
    result = observe([("Content-Security-Policy", "upgrade-insecure-requests")], body)
    assert "mixed-content-active" not in result and "mixed-content-passive" not in result
    assert "script-integrity" in result
    result = observe(body='<a href="http://elsewhere.example/">link</a>')
    assert not result


def test_inline_scripts_styles_templates_comments_never_produce_active_markup_observations():
    result = observe(body='''<script>const a = '<form><input type="password" name="secret"></form>';</script>
    <template><form><input type="password" name="secret"></form></template>
    <noscript><form><input type="password" name="secret"></form></noscript>
    <!-- <script src="http://x.example/secret"></script> -->
    <script type="application/json" src="http://x.example/secret"></script>''')
    assert not result


def test_external_integrity_and_origin_normalization():
    result = observe(body='''<script src="https://EXAMPLE.com:443/local"></script>
    <script src="//cdn.example/script" integrity="sha384-SYNTHETIC"></script>
    <link rel="stylesheet" href="https://cdn.example/style" integrity="sha384-SYNTHETIC">
    <link rel="preconnect" href="http://cdn.example/">''')
    assert not result


def test_form_owner_outside_form_and_submit_button_overrides():
    body = '''<form id="signin" action="/login" method="post"></form>
    <input form="signin" type="password" name="SECRET">
    <button form="signin" formmethod="get" formaction="http://auth.example/login">Sign in</button>'''
    result = observe(body=body)
    assert {"password-form-get", "password-form-http", "password-form-external"} <= set(result)
    assert "SECRET" not in str(result)


def test_non_password_form_http_action_has_own_lower_severity():
    result = observe(body='<form action="http://example.com/search" method="post"><input name="query"></form>')
    assert set(result) == {"form-action-http"}
    assert result["form-action-http"]["severity"] == "low"


def test_password_field_on_http_is_observed_even_without_submission():
    result = observe(body='<input type="password">', url="http://example.com/")
    assert "password-over-http" in result and "password-form-get" not in result


@pytest.mark.parametrize("body", [
    '<form method="post"><input type="password" name="secret"></form>',
    '<form><input type="password" name="secret" disabled></form>',
    '<form><fieldset disabled><input type="password" name="secret"></fieldset></form>',
    '<form><input type="password"></form>',
    '<form method="dialog"><input type="password" name="secret"></form>',
    '<form><input form="missing" type="password" name="secret"></form>',
])
def test_form_rule_avoids_unsupported_get_claims(body):
    assert not any(rule.startswith("password-form-") for rule in observe(body=body))


def test_empty_form_action_ignores_external_base_and_nested_form_is_ignored():
    result = observe(body='''<base href="https://cdn.example/assets/">
    <form action="" method="post"><form action="http://other.example/" method="get"><input name="password" type="password"></form></form>''')
    assert set(result) == {"external-base"}


def test_markup_urls_are_resolved_safely_without_echoing_invalid_values():
    result = observe(body='''<form action="http://[SECRET_INVALID" method="post"><input type="password" name="pass"></form>
    <img src="http://host.example:SECRET_PORT/">
    <script src="h&#x09;ttp://cdn.example/SECRET_PATH"></script>''')
    assert "mixed-content-active" in result
    assert "SECRET" not in str(result)


@pytest.mark.parametrize("body,rule", [
    ('<h1>Index of /SECRET_FOLDER</h1><a href="../">Parent Directory</a>', "directory-listing"),
    ('<pre>Traceback (most recent call last):\n File "/SECRET_PATH/app.py", line 10\nException: SECRET</pre>', "debug-traceback"),
    ('<h1>Werkzeug Debugger</h1><p>SECRET_TRACE</p>', "debug-traceback"),
    ('<pre>-----BEGIN RSA PRIVATE KEY-----\nSECRET_KEY\n-----END RSA PRIVATE KEY-----</pre>', "private-key-marker"),
])
def test_signature_rules_only_retain_counts_and_are_explicitly_unconfirmed(body, rule):
    result = observe(body=body)
    assert rule in result
    assert result[rule]["confidence"] == "medium"
    assert "SECRET" not in str(result)


@pytest.mark.parametrize("body", [
    '<h1>Index of security concepts</h1>', '<p>Traceback documentation</p>',
    '<pre>-----BEGIN PRIVATE KEY-----\nSECRET_KEY</pre>',
    '<pre>-----BEGIN PUBLIC KEY-----\nSECRET_KEY\n-----END PUBLIC KEY-----</pre>',
    '<script>const a = "-----BEGIN PRIVATE KEY----- SECRET -----END PRIVATE KEY-----";</script>',
])
def test_signature_rules_require_specific_visible_signals(body):
    assert not observe(body=body)


def test_body_and_node_budgets_limit_analysis_without_retaining_truncated_content():
    body = " " * scanner.MAX_BODY_BYTES + '<form><input type="password" name="pass"></form>'
    assert not observe(body=body)
    body = "<br>" * 10001 + '<form><input type="password" name="pass"></form>'
    assert not observe(body=body)


def test_catalog_has_unique_rule_ids_and_actual_executable_profile_coverage():
    ids = [row["id"] for row in CHECK_DEFINITIONS]
    assert len(ids) == len(set(ids)) == 37
    keys = {"id", "title", "category", "profiles", "severity", "cwe", "description", "limitations", "reference_url"}
    assert all(set(row) == keys and row["limitations"] and row["reference_url"].startswith("https://") for row in CHECK_DEFINITIONS)
    headers = scanner.executed_checks("headers", scanner.demo_snapshot())
    web = scanner.executed_checks("web", scanner.demo_snapshot("web"))
    skipped = scanner.executed_checks("web", scanner.Snapshot(200, []))
    assert len(headers) == len(skipped) == 24
    assert len(web) == 37
    assert "password-form-get" not in headers and "password-form-get" in web


def test_extended_demo_is_offline_labeled_and_redacted():
    demo = scanner.demo_snapshot("web")
    result = scanner.analyze_headers(parse_target("https://demo.example/"), demo)
    assert len(result) > 12
    assert all("SYNTHETIC DEMO" in row["evidence"] for row in result)
    assert "DO_NOT_RETAIN" not in str(result)
    assert "SYNTHETIC_NOT_A_SECRET" not in str(result)


def fake_transport(monkeypatch, headers, payload, status=200):
    actions = []
    class Response:
        def getheaders(self):
            return headers
        def read(self, amount):
            actions.append(("read", amount))
            return payload[:amount]
        def close(self):
            actions.append(("response-close",))
    Response.status = status
    class Connection:
        def __init__(self, target, address, *, before_send=None):
            actions.append(("connect", address))
        def request(self, method, path, headers):
            actions.append(("request", method, path, headers))
        def getresponse(self):
            return Response()
        def close(self):
            actions.append(("connection-close",))
    monkeypatch.setattr(scanner, "resolve_public_addresses", lambda *args: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "PinnedHTTPConnection", Connection)
    return actions


def test_web_transport_reads_bounded_identity_html_once(monkeypatch):
    actions = fake_transport(monkeypatch, [("Content-Type", "text/html")], b"x" * (scanner.MAX_BODY_BYTES + 10))
    result = scanner.fetch_headers(parse_target("https://example.com/"), profile="web")
    assert result.body_analyzed and result.body_truncated
    assert result.metadata["body_bytes"] == scanner.MAX_BODY_BYTES
    assert len(result.body) == scanner.MAX_BODY_BYTES
    assert [entry for entry in actions if entry[0] == "read"] == [("read", scanner.MAX_BODY_BYTES)]
    assert len([entry for entry in actions if entry[0] == "request"]) == 1
    assert actions[-2:] == [("response-close",), ("connection-close",)]


@pytest.mark.parametrize("headers,status,reason", [
    ([("Content-Type", "application/json")], 200, "unsupported-content-type"),
    ([("Content-Type", "application/javascript")], 200, "unsupported-content-type"),
    ([("Content-Type", "text/html-malformed")], 200, "unsupported-content-type"),
    ([("Content-Type", "text/html"), ("Content-Encoding", "gzip")], 200, "compressed-content"),
    ([("Content-Type", "text/html"), ("Content-Encoding", "identity, gzip")], 200, "compressed-content"),
    ([("Content-Type", "text/html"), ("Content-Type", "application/json")], 200, "unsupported-content-type"),
    ([("Content-Type", "text/html"), ("Location", "http://127.0.0.1/private")], 302, "redirect-response"),
])
def test_web_transport_skips_unsupported_ambiguous_compressed_redirect_body(monkeypatch, headers, status, reason):
    actions = fake_transport(monkeypatch, headers, b"SECRET_BODY", status=status)
    result = scanner.fetch_headers(parse_target("https://example.com/"), profile="web")
    assert not result.body_analyzed and not result.body
    assert result.metadata["body_skip_reason"] == reason
    assert not any(entry[0] == "read" for entry in actions)


def test_default_headers_profile_does_not_read_and_web_small_xhtml_is_complete(monkeypatch):
    actions = fake_transport(monkeypatch, [("Content-Type", "application/xhtml+xml; charset=utf-8")], b"<html></html>")
    result = scanner.fetch_headers(parse_target("https://example.com/"))
    assert not result.body_analyzed and not any(entry[0] == "read" for entry in actions)
    result = scanner.fetch_headers(parse_target("https://example.com/"), profile="web")
    assert result.body_analyzed and not result.body_truncated and result.body == "<html></html>"


def test_unsupported_profile_rejected_before_dns(monkeypatch):
    monkeypatch.setattr(scanner, "resolve_public_addresses", lambda *args: pytest.fail("No DNS allowed"))
    with pytest.raises(ValueError, match="Unsupported scan profile"):
        scanner.fetch_headers(parse_target("https://example.com/"), profile="intrusive")


def test_cors_null_rule_avoids_ambiguous_repeated_headers():
    result = observe([("Access-Control-Allow-Origin", "null"), ("Access-Control-Allow-Origin", "https://other.example"), ("Access-Control-Allow-Credentials", "true")])
    assert "cors-null-origin" not in result


def test_unsupported_meta_sandbox_cannot_suppress_enforcing_header_observation():
    result = observe([("Content-Security-Policy", "script-src 'unsafe-inline' 'unsafe-eval' *")],
                     '<head><meta http-equiv="Content-Security-Policy" content="sandbox"></head>')
    assert {"csp-unsafe-inline", "csp-unsafe-eval", "csp-broad-script-sources"} <= set(result)


@pytest.mark.parametrize("action", ["javascript:void(0)", "mailto:help@example.com", "http://[invalid"])
def test_get_form_rule_requires_http_submission_destination(action):
    assert "password-form-get" not in observe(body=f'<form action="{action}"><input type="password" name="pass"></form>')


def test_web_response_combined_headers_and_body_still_has_global_budget(monkeypatch):
    wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            + (b"X-Noise: " + b"n" * 2900 + b"\r\n") * 80
            + b"Content-Length: 131072\r\n\r\n" + b"x" * scanner.MAX_BODY_BYTES)
    class MemorySocket:
        def __init__(self):
            self.offset = 0
        def settimeout(self, timeout):
            pass
        def recv_into(self, buffer, size):
            chunk = wire[self.offset:self.offset + size]
            buffer[:len(chunk)] = chunk
            self.offset += len(chunk)
            return len(chunk)
        def close(self):
            pass
    sock = MemorySocket()
    class Connection:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            wrapped = scanner._ResponseSocket(sock, scanner.time.monotonic() + 10)
            response = scanner.http.client.HTTPResponse(wrapped)
            response.begin()
            return response
        def close(self):
            pass
    monkeypatch.setattr(scanner, "resolve_public_addresses", lambda *args: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "PinnedHTTPConnection", Connection)
    with pytest.raises(scanner.ScanNetworkError, match="256 KiB"):
        scanner.fetch_headers(parse_target("https://example.com/"), profile="web")
    assert sock.offset == scanner.MAX_RESPONSE_BYTES


def test_web_body_timeout_does_not_return_partial_data_or_exception_details(monkeypatch):
    closed = []
    class Response:
        status = 200
        def getheaders(self):
            return [("Content-Type", "text/html")]
        def read(self, amount):
            raise TimeoutError("SECRET_RAW_TRANSPORT_DETAIL")
        def close(self):
            closed.append("response")
    class Connection:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return Response()
        def close(self):
            closed.append("connection")
    monkeypatch.setattr(scanner, "resolve_public_addresses", lambda *args: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "PinnedHTTPConnection", Connection)
    with pytest.raises(scanner.ScanNetworkError) as error:
        scanner.fetch_headers(parse_target("https://example.com/"), profile="web")
    assert "SECRET" not in str(error.value)
    assert "deadline" in str(error.value)
    assert closed == ["response", "connection"]


def test_repeated_cookie_names_emit_one_occurrence_per_rule_and_response():
    headers = BASE + [
        ("Set-Cookie", "__Host-session=SECRET_ONE; SameSite=None; Path=/one"),
        ("Set-Cookie", "__Host-session=SECRET_TWO; SameSite=None; Path=/two"),
        ("Set-Cookie", "__Secure-session=SECRET_ONE; SameSite=None; Path=/one"),
        ("Set-Cookie", "__Secure-session=SECRET_TWO; SameSite=None; Path=/two"),
    ]
    observations = scanner.analyze_headers(parse_target("https://example.com/"), scanner.Snapshot(200, headers))
    ids = [item["check_id"] for item in observations]
    assert len(ids) == len(set(ids)) == 6
    assert {"cookie-samesite-none:__Host-session", "cookie-host-prefix:__Host-session", "cookie-secure-prefix:__Secure-session"} <= set(ids)
    assert "SECRET" not in str(observations)
