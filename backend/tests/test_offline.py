import json
import socket

import pytest

from scopeforge.offline import MAX_IMPORT_BYTES, OPENAPI_CHECKS, analyze_import
from scopeforge.security import ScopeError, parse_target


TARGET = parse_target("https://lab.scopeforge.test/")


def spec():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Synthetic test", "version": "1"},
        "servers": [{"url": "https://lab.scopeforge.test"}],
        "security": [{"bearer": []}],
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
    }


def analyze(document, target=TARGET):
    return analyze_import("openapi", json.dumps(document), target, synthetic=True)


def identifiers(document):
    return {finding["check_id"] for finding in analyze(document)[0]}


def test_protected_spec_has_no_findings_and_no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Offline review attempted networking.")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    observations, checks, warnings, summary = analyze(spec())
    assert observations == []
    assert len(checks) == len(OPENAPI_CHECKS) == 15
    assert summary["network_requests"] == 0
    assert summary["operations_reviewed"] == 1
    assert summary["raw_content_retained"] is False
    assert warnings == []


@pytest.mark.parametrize("version", ["3.0.4", "3.1.1", "3.2.0"])
def test_supported_versions(version):
    document = spec()
    document["openapi"] = version
    assert analyze(document)[3]["specification_version"] == version


@pytest.mark.parametrize("version", ["2.0", "3.3.0", "3.1", "", True])
def test_unsupported_versions(version):
    document = spec()
    document["openapi"] = version
    with pytest.raises(ScopeError, match="supports JSON"):
        analyze(document)


def test_security_overrides_optional_and_undefined_names():
    document = spec()
    document["paths"] = {
        "/public": {"get": {"security": []}},
        "/write": {"post": {"security": []}},
        "/optional": {"get": {"security": [{}, {"bearer": []}]}},
        "/unknown": {"get": {"security": [{"undefined": []}]}},
    }
    assert identifiers(document) == {
        "openapi:missing-authentication", "openapi:unauthenticated-write",
        "openapi:optional-authentication", "openapi:undefined-security-scheme",
    }


def test_operation_authentication_restores_absent_root_security():
    document = spec()
    document.pop("security")
    document["paths"]["/items"]["get"]["security"] = [{"bearer": []}]
    assert identifiers(document) == set()


def test_and_security_requirements_do_not_become_optional():
    document = spec()
    document["components"]["securitySchemes"]["second"] = {"type": "http", "scheme": "bearer"}
    document["security"] = [{"bearer": [], "second": []}]
    assert identifiers(document) == set()


def test_effective_servers_inherit_and_override():
    document = spec()
    document["servers"] = [{"url": "http://lab.scopeforge.test"}]
    document["paths"] = {
        "/inherited": {"get": {}},
        "/override": {"get": {"servers": [{"url": "https://lab.scopeforge.test"}]}},
    }
    finding = analyze(document)[0][0]
    assert finding["check_id"] == "openapi:insecure-server"
    assert "GET /inherited" in finding["evidence"]
    assert "/override" not in finding["evidence"]


def test_api_key_and_basic_auth_rules():
    document = spec()
    document["servers"] = [{"url": "http://lab.scopeforge.test"}]
    document["components"]["securitySchemes"] = {
        "key": {"type": "apiKey", "in": "query", "name": "SECRET_PARAMETER_NAME"},
        "basic": {"type": "http", "scheme": "basic"},
    }
    document["security"] = [{"key": []}, {"basic": []}]
    observations = analyze(document)[0]
    assert {finding["check_id"] for finding in observations} == {
        "openapi:insecure-server", "openapi:query-api-key", "openapi:basic-auth-http",
    }
    assert "SECRET_PARAMETER_NAME" not in json.dumps(observations)


def test_modern_header_api_key_and_basic_over_https_not_flagged():
    document = spec()
    document["components"]["securitySchemes"] = {
        "key": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        "basic": {"type": "http", "scheme": "basic"},
    }
    document["security"] = [{"key": []}, {"basic": []}]
    assert identifiers(document) == set()


def test_legacy_oauth_and_unknown_scopes():
    document = spec()
    document["components"]["securitySchemes"]["oauth"] = {
        "type": "oauth2", "flows": {
            "implicit": {"authorizationUrl": "https://lab.scopeforge.test/auth", "scopes": {"read": "Read"}},
            "password": {"tokenUrl": "http://lab.scopeforge.test/token?secret=DO_NOT_RETAIN", "scopes": {}},
        },
    }
    document["security"] = [{"oauth": ["unlisted"]}]
    observations = analyze(document)[0]
    assert {finding["check_id"] for finding in observations} == {
        "openapi:oauth-implicit", "openapi:oauth-password",
        "openapi:oauth-insecure-endpoint", "openapi:undefined-oauth-scope",
    }
    assert "DO_NOT_RETAIN" not in json.dumps(observations)


def test_modern_oauth_known_scope():
    document = spec()
    document["components"]["securitySchemes"]["oauth"] = {
        "type": "oauth2", "flows": {"authorizationCode": {
            "authorizationUrl": "https://lab.scopeforge.test/auth",
            "tokenUrl": "https://lab.scopeforge.test/token", "scopes": {"read": "Read"},
        }},
    }
    document["security"] = [{"oauth": ["read"]}]
    assert identifiers(document) == set()


def test_parameter_override_and_url_credentials():
    document = spec()
    item = document["paths"]["/items"]
    item["parameters"] = [{"name": "limit", "in": "query", "schema": {"type": "integer"}}]
    item["get"]["parameters"] = [
        {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 100}},
        {"name": "password", "in": "query", "example": "SUPER_SECRET_VALUE"},
    ]
    observations = analyze(document)[0]
    assert {finding["check_id"] for finding in observations} == {"openapi:credential-url-parameter"}
    assert "SUPER_SECRET_VALUE" not in json.dumps(observations)
    item["get"]["parameters"].pop(0)
    assert "openapi:unbounded-pagination" in identifiers(document)


def test_request_schema_local_refs_readonly_and_size_limits():
    document = spec()
    document["components"]["schemas"] = {
        "Input": {"type": "object", "properties": {
            "isAdmin": {"type": "boolean"}, "items": {"type": "array", "items": {"type": "string"}},
            "immutable": {"readOnly": True, "type": "object", "properties": {"role": {"type": "string"}}},
        }},
    }
    document["paths"]["/items"] = {"post": {"requestBody": {
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Input"}}},
    }}}
    assert identifiers(document) == {"openapi:sensitive-writable-property", "openapi:unbounded-array-input"}
    schema = document["components"]["schemas"]["Input"]
    schema["properties"]["isAdmin"]["readOnly"] = True
    schema["properties"]["items"]["maxItems"] = 20
    assert identifiers(document) == set()


def test_composed_constraints_are_not_misreported_as_missing():
    document = spec()
    document["paths"]["/items"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"type": "array", "allOf": [{"maxItems": 10}]}}
    }}}}
    observations, _checks, warnings, _summary = analyze(document)
    assert observations == []
    assert any("Composed" in warning for warning in warnings)


def test_external_cyclic_and_missing_refs_are_bounded_and_not_fetched(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args: pytest.fail("Network called"))
    document = spec()
    document["paths"] = {
        "/external": {"$ref": "https://127.0.0.1/internal?token=HIDDEN"},
        "/cycle": {"$ref": "#/paths/~1cycle"},
        "/missing": {"$ref": "#/does-not-exist"},
    }
    observations, _checks, warnings, summary = analyze(document)
    assert observations == []
    assert summary["operations_reviewed"] == 0
    assert summary["external_references_skipped"] == 1
    assert summary["unresolved_local_references"] == 2
    assert "HIDDEN" not in json.dumps(warnings)


def test_opaque_or_noncanonical_route_templates_are_omitted():
    document = spec()
    document["security"] = []
    document["paths"] = {"/api?password=DO_NOT_RETAIN": {"get": {}},
                         "/" + "A" * 64: {"get": {}}}
    observations = analyze(document)[0]
    assert "DO_NOT_RETAIN" not in json.dumps(observations)
    assert "A" * 64 not in json.dumps(observations)
    assert "[route template omitted]" in observations[0]["evidence"]


@pytest.mark.parametrize("content", [
    '{"status":200,"status":201}', "[]", "null", '{"openapi": NaN}',
    '{"bad":1e9999}', '{"bad":"\\ud800"}', '{"\\ud800":1}',
    '{"broken":"PRIVATE_MALFORMED_SECRET"', "[" * 41 + "]" * 41,
])
def test_malformed_ambiguous_or_deep_json_rejected_without_echo(content):
    with pytest.raises(ScopeError) as caught:
        analyze_import("openapi", content, TARGET)
    assert "PRIVATE_MALFORMED_SECRET" not in str(caught.value)


def test_size_and_node_limits():
    with pytest.raises(ScopeError, match="256 KiB"):
        analyze_import("openapi", " " * (MAX_IMPORT_BYTES + 1), TARGET)
    with pytest.raises(ScopeError, match="complexity"):
        analyze_import("openapi", json.dumps({"a": [0] * 50001}), TARGET)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(security="none"),
    lambda d: d.update(security=[{"bearer": "wrong"}]),
    lambda d: d.update(paths=[]),
    lambda d: d.update(servers=[{"url": "https://["}]),
    lambda d: d["paths"]["/items"].update(get="not-an-operation"),
    lambda d: d["paths"]["/items"]["get"].update(parameters="not-a-list"),
])
def test_malformed_declarations_return_scope_error(mutation):
    document = spec()
    mutation(document)
    with pytest.raises(ScopeError):
        analyze(document)


def capture():
    return {"status": 200, "headers": [
        {"name": "Content-Type", "value": "text/html"},
        {"name": "Set-Cookie", "value": "session=CAPTURE_SECRET; Path=/"},
        {"name": "Authorization", "value": "Bearer PRIVATE_AUTH_SECRET"},
    ], "body": "<html><body>Training fixture</body></html>"}


def test_http_capture_reuses_sanitized_rules_without_network(monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: pytest.fail("Network called"))
    observations, checks, _warnings, summary = analyze_import("http", json.dumps(capture()), TARGET, True)
    assert observations and all(item["check_id"].startswith("import-http:") for item in observations)
    assert all("USER-PROVIDED HTTP CAPTURE" in item["evidence"] for item in observations)
    assert all(item.startswith("import-http:") for item in checks)
    serialized = json.dumps(observations)
    assert "CAPTURE_SECRET" not in serialized and "PRIVATE_AUTH_SECRET" not in serialized
    assert summary["body_analyzed"] and summary["network_requests"] == 0


def test_http_body_clipping_and_non_html_skip():
    document = capture()
    document["body"] = "<html>" + " " * (140 * 1024)
    _findings, _checks, warnings, summary = analyze_import("http", json.dumps(document), TARGET)
    assert summary["body_truncated"]
    assert summary["body_bytes_analyzed"] <= 128 * 1024
    assert warnings


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(status=302),
    lambda d: d["headers"].append({"name": "Content-Type", "value": "application/json"}),
    lambda d: d["headers"].append({"name": "Content-Encoding", "value": "gzip"}),
])
def test_http_body_ambiguity_and_redirects_skip_body_rules(mutation):
    document = capture()
    mutation(document)
    _findings, _checks, warnings, summary = analyze_import("http", json.dumps(document), TARGET)
    assert not summary["body_analyzed"]
    assert warnings
    document["headers"][0]["value"] = "application/json"
    _findings, checks, warnings, summary = analyze_import("http", json.dumps(document), TARGET)
    assert not summary["body_analyzed"] and summary["body_bytes_analyzed"] == 0
    assert warnings


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(status=True),
    lambda d: d.update(status=600),
    lambda d: d.update(headers={}),
    lambda d: d["headers"].append({"name": "X-Test", "value": "abc\r\nINJECTED"}),
    lambda d: d["headers"].append({"name": "Bad Name", "value": "x"}),
    lambda d: d.update(body={}),
    lambda d: d.update(url="https://untrusted.example"),
])
def test_http_capture_invalid_shapes_are_rejected(mutation):
    document = capture()
    mutation(document)
    with pytest.raises(ScopeError):
        analyze_import("http", json.dumps(document), TARGET)


@pytest.mark.parametrize("schema", [
    {"type": "integer", "allOf": [{"maximum": 100}]},
    {"$ref": "#/components/schemas/PageSize", "maximum": 100},
])
def test_pagination_constraints_are_not_inferred_absent_from_complex_schema(schema):
    document = spec()
    document["components"]["schemas"] = {"PageSize": {"type": "integer"}}
    document["paths"]["/items"]["get"]["parameters"] = [{"name": "limit", "in": "query", "schema": schema}]
    observations, _checks, warnings, _summary = analyze(document)
    assert observations == []
    assert any("schema" in warning.lower() and "skipped" in warning for warning in warnings)


@pytest.mark.parametrize("property_schema", [
    {"$ref": "#/components/schemas/Role", "readOnly": True},
    {"allOf": [{"type": "boolean", "readOnly": True}]},
    {"oneOf": [{"type": "boolean", "readOnly": True}, {"type": "null"}]},
])
def test_readonly_property_complexity_does_not_emit_writable_claim(property_schema):
    document = spec()
    document["components"]["schemas"] = {"Role": {"type": "boolean"}}
    document["paths"]["/items"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"type": "object", "properties": {"isAdmin": property_schema}}},
    }}}}
    observations, _checks, warnings, _summary = analyze(document)
    assert observations == []
    assert any("schema" in warning.lower() and "skipped" in warning for warning in warnings)


def test_schema_scope_changes_are_not_resolved_against_wrong_document():
    document = spec()
    document["components"]["schemas"] = {"Role": {"type": "boolean"}}
    document["paths"]["/items"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"$id": "https://elsewhere.example/schema", "type": "object", "properties": {
            "role": {"$ref": "#/components/schemas/Role"},
        }}},
    }}}}
    observations, _checks, warnings, _summary = analyze(document)
    assert observations == []
    assert any("identifiers" in warning and "skipped" in warning for warning in warnings)
    assert "elsewhere.example" not in json.dumps(warnings)


def test_oas30_reference_siblings_are_ignored_under_30_semantics():
    document = spec()
    document["openapi"] = "3.0.4"
    document["components"]["schemas"] = {"Role": {"type": "boolean"}}
    document["paths"]["/items"] = {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"type": "object", "properties": {
            "isAdmin": {"$ref": "#/components/schemas/Role", "readOnly": True},
        }}},
    }}}}
    assert identifiers(document) == {"openapi:sensitive-writable-property"}


@pytest.mark.parametrize("target,default", [(TARGET, "http"), (parse_target("http://lab.scopeforge.test/"), "https")])
def test_templated_server_scheme_is_explicitly_unknown(target, default):
    document = spec()
    document["servers"] = [{"url": "{scheme}://api.example.test", "variables": {"scheme": {"default": default}}}]
    observations, _checks, warnings, _summary = analyze(document, target)
    assert observations == []
    assert any("Templated server" in warning for warning in warnings)


def test_explicit_insecure_server_still_detected_alongside_unresolved_template():
    document = spec()
    document["servers"] = [{"url": "{scheme}://api.example.test", "variables": {"scheme": {"default": "https"}}}, {"url": "http://lab.scopeforge.test"}]
    observations, _checks, warnings, _summary = analyze(document)
    assert {finding["check_id"] for finding in observations} == {"openapi:insecure-server"}
    assert any("Templated server" in warning for warning in warnings)


def test_oas32_local_security_scheme_uri_is_resolved_without_false_undefined():
    document = spec()
    document["openapi"] = "3.2.0"
    document["security"] = [{"#/components/securitySchemes/bearer": []}]
    assert identifiers(document) == set()
    document["components"]["securitySchemes"]["bearer"] = {"type": "apiKey", "in": "query", "name": "api_key"}
    assert identifiers(document) == {"openapi:query-api-key"}


def test_oas32_security_scheme_component_name_has_precedence_over_uri():
    document = spec()
    document["openapi"] = "3.2.0"
    name = "#/components/securitySchemes/bearer"
    document["components"]["securitySchemes"][name] = {"type": "apiKey", "in": "query", "name": "api_key"}
    document["security"] = [{name: []}]
    assert identifiers(document) == {"openapi:query-api-key"}


@pytest.mark.parametrize("name,summary_key", [
    ("https://secrets.example/scheme?token=URI_SECRET", "external_references_skipped"),
    ("relative-scheme.json", "external_references_skipped"),
    ("#/components/securitySchemes/missing", "unresolved_local_references"),
])
def test_oas32_unresolved_security_scheme_uris_warn_without_claim_or_network(name, summary_key, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: pytest.fail("Network called"))
    document = spec()
    document["openapi"] = "3.2.0"
    document["security"] = [{name: []}]
    observations, _checks, warnings, summary = analyze(document)
    assert observations == [] and warnings
    assert summary[summary_key] == 1
    assert "URI_SECRET" not in json.dumps(warnings)


def test_oas31_security_requirement_still_requires_defined_component_name():
    document = spec()
    document["security"] = [{"#/components/securitySchemes/bearer": []}]
    assert identifiers(document) == {"openapi:undefined-security-scheme"}


def test_redacted_paths_preserve_distinct_operation_counts_without_retaining_paths():
    document = spec()
    document["security"] = []
    document["paths"] = {"/" + "A" * 64: {"get": {}}, "/" + "B" * 64: {"get": {}}}
    observations, _checks, _warnings, summary = analyze(document)
    assert summary["operations_reviewed"] == 2
    assert "Affected operation declarations: 2" in observations[0]["evidence"]
    assert "A" * 64 not in json.dumps(observations) and "B" * 64 not in json.dumps(observations)


def test_oas32_additional_operations_are_reported_as_unreviewed():
    document = spec()
    document["openapi"] = "3.2.0"
    document["paths"] = {"/items": {"query": {}, "additionalOperations": {"COPY": {}}}}
    observations, _checks, warnings, summary = analyze(document)
    assert observations == [] and summary["operations_reviewed"] == 0
    assert any("QUERY and additionalOperations" in warning for warning in warnings)
