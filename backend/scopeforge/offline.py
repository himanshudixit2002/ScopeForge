"""Bounded, network-free review of user-supplied HTTP captures and OpenAPI JSON.

Raw documents, example values, auth headers, and cookie values are never returned
to persistence. OpenAPI findings describe declarations, not server behavior.
"""

import json
import math
import re
from urllib.parse import urlsplit

from .security import ScopeError, Target

MAX_IMPORT_BYTES = 256 * 1024
MAX_DEPTH = 40
MAX_NODES = 50000
SPEC_REFERENCE = "https://spec.openapis.org/oas/latest.html"
REST_REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
OAUTH_REFERENCE = "https://www.rfc-editor.org/rfc/rfc9700.html"
LIMITATION = (
    "This is a declaration in a user-provided OpenAPI document. No endpoint was "
    "contacted. Runtime middleware, gateway controls, and intended public access "
    "may change the security impact; manual validation is required."
)


def definition(identifier, title, severity, cwe, description, reference=REST_REFERENCE):
    return {
        "id": "openapi:" + identifier, "title": title, "category": "API design",
        "profiles": ["openapi"], "severity": severity, "cwe": cwe,
        "description": description, "limitations": LIMITATION,
        "reference_url": reference,
    }


OPENAPI_CHECKS = [
    definition("insecure-server", "Unencrypted API server declared", "low", "CWE-319",
               "Detects effective server declarations using HTTP."),
    definition("missing-authentication", "Read operations lack declared authentication", "info", "CWE-306",
               "Detects read operations with no effective OpenAPI security requirement.", SPEC_REFERENCE),
    definition("optional-authentication", "Optional authentication declared", "low", "CWE-306",
               "Detects an empty security requirement object that permits anonymous access.", SPEC_REFERENCE),
    definition("unauthenticated-write", "Write operations lack required authentication", "medium", "CWE-306",
               "Detects write operations with absent or explicitly optional declared security.", SPEC_REFERENCE),
    definition("undefined-security-scheme", "Security requirement references an undefined scheme", "low", "CWE-287",
               "Detects security requirement names missing from components.securitySchemes.", SPEC_REFERENCE),
    definition("query-api-key", "API key declared in a query parameter", "medium", "CWE-598",
               "Detects used API-key schemes carried in URLs."),
    definition("basic-auth-http", "HTTP Basic authentication declared over HTTP", "medium", "CWE-319",
               "Detects effective HTTP server declarations used with HTTP Basic authentication."),
    definition("oauth-implicit", "OAuth implicit flow declared", "low", "CWE-287",
               "Detects used OAuth implicit flows requiring review against current OAuth guidance.", OAUTH_REFERENCE),
    definition("oauth-password", "OAuth password grant declared", "medium", "CWE-522",
               "Detects the resource-owner password grant, prohibited by the OAuth security BCP.", OAUTH_REFERENCE),
    definition("oauth-insecure-endpoint", "Unencrypted OAuth endpoint declared", "medium", "CWE-319",
               "Detects HTTP authorization, token, or refresh URLs in used OAuth flows.", OAUTH_REFERENCE),
    definition("undefined-oauth-scope", "Required OAuth scope is not declared by its scheme", "low", "CWE-285",
               "Detects required OAuth scopes absent from all declared flows.", SPEC_REFERENCE),
    definition("credential-url-parameter", "Credential-like parameter declared in a URL", "medium", "CWE-598",
               "Detects password, token, or secret parameter names in query/path declarations."),
    definition("unbounded-pagination", "Pagination size has no declared upper bound", "info", "CWE-770",
               "Detects integer page-size/limit parameters lacking maximum or exclusiveMaximum."),
    definition("sensitive-writable-property", "Sensitive fields declared writable", "low", "CWE-915",
               "Highlights write request schemas exposing ownership, privilege, or balance fields without readOnly.",
               "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"),
    definition("unbounded-array-input", "Input array has no declared item limit", "info", "CWE-770",
               "Detects arrays in write request bodies lacking maxItems; runtime limits may exist.",
               "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"),
]
_DEFINITIONS = {item["id"]: item for item in OPENAPI_CHECKS}
_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
_WRITE_METHODS = {"put", "post", "patch", "delete"}
_CREDENTIAL_NAMES = {"password", "passwd", "secret", "clientsecret", "accesstoken",
                     "refreshtoken", "token", "apikey", "authorization"}
_SENSITIVE_FIELDS = {"isadmin", "admin", "role", "roles", "permissions", "ownerid",
                     "userid", "accountbalance", "balance"}
_PAGINATION = {"limit", "pagesize", "perpage", "maxresults"}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
            raise ScopeError("Import JSON contains invalid Unicode.")
        if key in result:
            raise ScopeError("Duplicate JSON keys are not accepted.")
        result[key] = value
    return result


def _document(content):
    if not isinstance(content, str):
        raise ScopeError("Import content must be JSON text.")
    try:
        size = len(content.encode("utf-8"))
    except UnicodeError:
        raise ScopeError("Import text must contain valid Unicode.") from None
    if size > MAX_IMPORT_BYTES:
        raise ScopeError("Import content is limited to 256 KiB of UTF-8 text.")
    # Bound nesting before Python's decoder enters its recursive parser.
    depth, quoted, escaped = 0, False, False
    for character in content:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ScopeError("Import JSON exceeds the 40-level nesting limit.")
        elif character in "]}":
            depth -= 1
    try:
        result = json.loads(content, object_pairs_hook=_pairs,
                            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except ScopeError:
        raise
    except (ValueError, RecursionError):
        raise ScopeError("Import is not valid JSON. Document contents are omitted from this error.") from None
    if not isinstance(result, dict):
        raise ScopeError("Import JSON must be an object.")
    stack, nodes = [result], 0
    while stack:
        value = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ScopeError("Import JSON exceeds the 50,000-node complexity limit.")
        if isinstance(value, dict):
            nodes += len(value)
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ScopeError("Non-finite numbers are not accepted in imported JSON.")
        elif isinstance(value, str) and any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ScopeError("Import JSON contains invalid Unicode.")
    return result


def _http(document, target, synthetic):
    from .scanner import Snapshot, analyze_headers, executed_checks
    if set(document) - {"status", "headers", "body"}:
        raise ScopeError("HTTP capture accepts only status, headers, and optional body.")
    status, headers = document.get("status"), document.get("headers")
    if type(status) is not int or not 100 <= status <= 599:
        raise ScopeError("HTTP capture status must be an integer between 100 and 599.")
    if not isinstance(headers, list) or len(headers) > 100:
        raise ScopeError("HTTP capture headers must be an array of at most 100 name/value objects.")
    pairs = []
    for header in headers:
        if not isinstance(header, dict) or set(header) != {"name", "value"}:
            raise ScopeError("Each captured header needs exactly name and value.")
        name, value = header["name"], header["value"]
        if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]{1,128}", name):
            raise ScopeError("Captured header name is invalid.")
        if (not isinstance(value, str) or len(value) > 8192
                or any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value)):
            raise ScopeError("Captured header values must be bounded single-line strings.")
        pairs.append((name, value))
    body = document.get("body", "")
    if not isinstance(body, str):
        raise ScopeError("Captured body must be text.")
    body_bytes = body.encode("utf-8")
    truncated = len(body_bytes) > 128 * 1024
    body = body_bytes[:128 * 1024].decode("utf-8", errors="ignore")
    content_types = [v.split(";", 1)[0].strip().lower() for k, v in pairs if k.lower() == "content-type"]
    encodings = [v.strip().lower() for k, v in pairs if k.lower() == "content-encoding"]
    analyze_body = ("body" in document and len(content_types) == 1
                    and content_types[0] in {"text/html", "application/xhtml+xml"}
                    and all(value in {"", "identity"} for value in encodings)
                    and not 300 <= status < 400)
    warnings = []
    if not analyze_body:
        warnings.append("HTML body checks skipped: require a non-redirect response with one HTML/XHTML Content-Type and identity encoding.")
    if truncated:
        warnings.append("Body analysis limited to the first 128 KiB; coverage is partial.")
    snapshot = Snapshot(status, pairs, synthetic=synthetic, body=body if analyze_body else "",
                        body_truncated=truncated, body_analyzed=analyze_body)
    findings = analyze_headers(target, snapshot)
    for finding in findings:
        finding["check_id"] = "import-http:" + finding["check_id"]
        finding["evidence"] = "USER-PROVIDED HTTP CAPTURE — no target request was made.\n" + finding["evidence"]
    checks = ["import-http:" + item for item in executed_checks("web", snapshot)]
    return findings, checks, warnings, {
        "format": "http", "network_requests": 0, "http_status": status,
        "body_analyzed": analyze_body, "body_truncated": truncated,
        "body_bytes_analyzed": len(body.encode("utf-8")) if analyze_body else 0,
        "rules_evaluated": len(checks), "raw_content_retained": False,
    }


def _name(value):
    return re.sub(r"[^a-z0-9]", "", value.lower()) if isinstance(value, str) else ""


def _route(path, method):
    # Preserve ordinary route templates, omit queries, emails, encoded strings,
    # long opaque identifiers, and other non-canonical contents from evidence.
    if (len(path) > 160 or not re.fullmatch(r"/[A-Za-z0-9_./{}:~\-]*", path)
            or any(len(part) > 32 and not (part.startswith("{") and part.endswith("}"))
                   for part in path.split("/"))):
        return method.upper() + " [route template omitted]"
    return method.upper() + " " + path


def _security(value):
    if not isinstance(value, list) or len(value) > 100:
        raise ScopeError("OpenAPI security must be an array of requirement objects.")
    for requirement in value:
        if not isinstance(requirement, dict):
            raise ScopeError("OpenAPI security entries must be objects.")
        for scopes in requirement.values():
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                raise ScopeError("OpenAPI security scope lists must contain strings.")
    return value


def _openapi(document, target, synthetic):
    version = document.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.[012]\.\d+", version):
        raise ScopeError("OpenAPI import supports JSON specifications 3.0.x, 3.1.x, and 3.2.x.")
    minor_version = int(version.split(".")[1])
    paths = document.get("paths")
    if not isinstance(paths, dict) or len(paths) > 1000:
        raise ScopeError("OpenAPI paths must be an object containing at most 1,000 paths.")
    warnings, issues = set(), {}
    external_refs, unresolved_refs = set(), set()
    global_security = _security(document.get("security", []))
    components = document.get("components", {})
    if not isinstance(components, dict):
        raise ScopeError("OpenAPI components must be an object.")
    schemes = components.get("securitySchemes", {})
    if not isinstance(schemes, dict):
        raise ScopeError("OpenAPI securitySchemes must be an object.")

    def resolve(value, *, schema=False):
        seen = set()
        while isinstance(value, dict):
            if schema:
                if any(key in value for key in ("allOf", "oneOf", "anyOf", "not")):
                    warnings.add("Composed/negated request schemas require manual constraint review; those schema branches were skipped.")
                    return None
                if any(key in value for key in ("$id", "$dynamicRef", "$dynamicAnchor")):
                    warnings.add("Schema identifiers and dynamic references require manual resolution; those schema branches were skipped.")
                    return None
                if minor_version >= 1 and "$ref" in value and len(value) > 1:
                    # JSON Schema siblings apply alongside $ref in OAS 3.1+.
                    # Following only the target would invent absent readOnly
                    # or size constraints, even if a warning were also emitted.
                    warnings.add("Schema reference siblings require combined constraint review; those schema branches were skipped.")
                    return None
            if "$ref" not in value:
                break
            reference = value["$ref"]
            if not isinstance(reference, str):
                raise ScopeError("OpenAPI references must be strings.")
            if not reference.startswith("#/"):
                external_refs.add(reference)
                return None
            if reference in seen or len(seen) >= 20:
                unresolved_refs.add(reference)
                return None
            seen.add(reference)
            result = document
            for part in reference[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(result, dict) or part not in result:
                    result = None
                    break
                result = result[part]
            if result is None:
                unresolved_refs.add(reference)
                return None
            # Conservative: do not infer overrides from reference siblings.
            if len(value) > 1:
                warnings.add("Reference siblings were not merged; review those declarations manually.")
            value = result
        return value

    def issue(identifier, context):
        bucket = issues.setdefault("openapi:" + identifier, set())
        bucket.add(context)

    def servers(value):
        if not isinstance(value, list):
            raise ScopeError("OpenAPI servers must be an array.")
        for server in value:
            if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                raise ScopeError("Each OpenAPI server must contain a URL string.")
        insecure = False
        for server in value:
            url = server["url"]
            if "{" in url or "}" in url:
                warnings.add("Templated server URLs were not evaluated; review variable defaults and allowed values manually.")
                continue
            # Relative server URLs inherit the imported target scheme. Do not
            # mistake an unresolved {scheme} variable for a relative URL.
            scheme = urlsplit(url).scheme.lower()
            insecure |= scheme == "http" or not scheme and target.scheme == "http"
        return insecure if value else target.scheme == "http"

    root_servers = document.get("servers", [])
    servers(root_servers)
    operations = 0
    for path, raw_item in paths.items():
        if not path.startswith("/"):
            raise ScopeError("OpenAPI path entries must start with /.")
        item = resolve(raw_item)
        if item is None:
            continue
        if not isinstance(item, dict):
            raise ScopeError("OpenAPI path entries must be objects.")
        if "query" in item or "additionalOperations" in item:
            warnings.add("QUERY and additionalOperations declarations were not evaluated; review those operation declarations manually.")
        for method, raw_operation in item.items():
            if method not in _METHODS:
                continue
            operation = resolve(raw_operation)
            if operation is None:
                continue
            if not isinstance(operation, dict):
                raise ScopeError("OpenAPI operations must be objects.")
            operations += 1
            if operations > 1000:
                raise ScopeError("OpenAPI review is limited to 1,000 operations.")
            # The private ordinal keeps separate declarations distinct even
            # when their displayed route templates are identically redacted.
            context = (operations, _route(path, method))
            effective_servers = operation.get("servers", item.get("servers", root_servers))
            insecure_server = servers(effective_servers)
            if insecure_server:
                issue("insecure-server", context)
            security = _security(operation.get("security", global_security))
            optional = any(not requirement for requirement in security)
            if not security and method not in _WRITE_METHODS:
                issue("missing-authentication", context)
            if optional:
                issue("optional-authentication", context)
            if (not security or optional) and method in _WRITE_METHODS:
                issue("unauthenticated-write", context)
            for requirement in security:
                for scheme_name, required_scopes in requirement.items():
                    if scheme_name in schemes:
                        scheme = resolve(schemes[scheme_name])
                    elif minor_version >= 2:
                        # OAS 3.2 permits a Security Scheme URI when component
                        # name lookup fails. Resolve local fragments only;
                        # all other URIs remain unverified, without fetching.
                        scheme = resolve({"$ref": scheme_name})
                    else:
                        issue("undefined-security-scheme", context)
                        continue
                    if not isinstance(scheme, dict):
                        continue
                    if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
                        issue("query-api-key", context)
                    if (scheme.get("type") == "http" and str(scheme.get("scheme", "")).lower() == "basic"
                            and insecure_server):
                        issue("basic-auth-http", context)
                    if scheme.get("type") != "oauth2":
                        continue
                    flows = scheme.get("flows", {})
                    if not isinstance(flows, dict):
                        raise ScopeError("OpenAPI OAuth flows must be an object.")
                    known_scopes = set()
                    for flow_name, flow in flows.items():
                        if not isinstance(flow, dict):
                            raise ScopeError("OpenAPI OAuth flow entries must be objects.")
                        if flow_name == "implicit":
                            issue("oauth-implicit", context)
                        if flow_name == "password":
                            issue("oauth-password", context)
                        for key in ("authorizationUrl", "tokenUrl", "refreshUrl"):
                            endpoint = flow.get(key)
                            if isinstance(endpoint, str) and endpoint.lower().startswith("http://"):
                                issue("oauth-insecure-endpoint", context)
                        declared_scopes = flow.get("scopes", {})
                        if not isinstance(declared_scopes, dict):
                            raise ScopeError("OpenAPI OAuth scopes must be an object.")
                        known_scopes.update(declared_scopes)
                    if set(required_scopes) - known_scopes:
                        issue("undefined-oauth-scope", context)
            parameters = []
            for owner in (item, operation):
                declared = owner.get("parameters", [])
                if not isinstance(declared, list):
                    raise ScopeError("OpenAPI parameters must be an array.")
                for raw_parameter in declared:
                    parameter = resolve(raw_parameter)
                    if isinstance(parameter, dict):
                        parameters.append(parameter)
            # Operation parameter definitions override path definitions by name/in.
            effective_parameters = {(p.get("name"), p.get("in")): p for p in parameters
                                    if isinstance(p.get("name"), str) and isinstance(p.get("in"), str)}
            for parameter in effective_parameters.values():
                if parameter.get("in") not in {"query", "path"}:
                    continue
                parameter_name = _name(parameter.get("name"))
                if parameter_name in _CREDENTIAL_NAMES:
                    issue("credential-url-parameter", context)
                schema = resolve(parameter.get("schema", {}), schema=True)
                if (parameter_name in _PAGINATION and isinstance(schema, dict)
                        and schema.get("type") == "integer"
                        and "maximum" not in schema and "exclusiveMaximum" not in schema):
                    issue("unbounded-pagination", context)
            if method not in _WRITE_METHODS:
                continue
            request = resolve(operation.get("requestBody", {}))
            if not isinstance(request, dict):
                continue
            media = request.get("content", {})
            if not isinstance(media, dict):
                raise ScopeError("OpenAPI requestBody content must be an object.")
            schema_stack = [(entry.get("schema", {}), 0) for entry in media.values() if isinstance(entry, dict)]
            visited, traversed = set(), 0
            while schema_stack:
                raw_schema, depth = schema_stack.pop()
                schema = resolve(raw_schema, schema=True)
                if not isinstance(schema, dict) or id(schema) in visited:
                    continue
                visited.add(id(schema))
                traversed += 1
                if depth > 20 or traversed > 300:
                    warnings.add("Request-schema traversal was bounded; some nested constraints were not evaluated.")
                    break
                if schema.get("readOnly") is True:
                    continue
                if schema.get("type") == "array" and "maxItems" not in schema:
                    issue("unbounded-array-input", context)
                properties = schema.get("properties", {})
                if isinstance(properties, dict):
                    for name, raw_property in properties.items():
                        prop = resolve(raw_property, schema=True)
                        if not isinstance(prop, dict):
                            continue
                        if _name(name) in _SENSITIVE_FIELDS and prop.get("readOnly") is not True:
                            issue("sensitive-writable-property", context)
                        schema_stack.append((prop, depth + 1))
                for key in ("items", "additionalProperties"):
                    schema_stack.append((schema.get(key), depth + 1))
    if external_refs:
        warnings.add(f"{len(external_refs)} external/non-local reference(s) were not resolved or fetched.")
    if unresolved_refs:
        warnings.add(f"{len(unresolved_refs)} unresolved or cyclic local reference(s) limited analysis.")
    findings = []
    for identifier, contexts in issues.items():
        rule = _DEFINITIONS[identifier]
        samples = [label for _ordinal, label in sorted(contexts)[:12]]
        evidence = ("SYNTHETIC DEMO — user-provided fixture.\n" if synthetic else "")
        evidence += "OPENAPI DOCUMENT REVIEW — no endpoint contacted.\n"
        evidence += f"Affected operation declarations: {len(contexts)}\n"
        evidence += "\n".join(samples)
        if len(contexts) > len(samples):
            evidence += f"\n{len(contexts) - len(samples)} additional operation declarations omitted."
        findings.append({
            "check_id": identifier, "title": rule["title"], "severity": rule["severity"],
            "confidence": "high", "cwe": rule["cwe"],
            "description": rule["description"] + " " + LIMITATION,
            "impact": "The declared design may weaken confidentiality, access control, or resource boundaries. " + LIMITATION,
            "remediation": _remediation(identifier) + " Recheck the deployed control and document demonstrated impact before reporting.",
            "evidence": evidence,
        })
    return findings, list(_DEFINITIONS), sorted(warnings), {
        "format": "openapi", "specification_version": version,
        "operations_reviewed": operations, "paths_in_document": len(paths),
        "external_references_skipped": len(external_refs),
        "unresolved_local_references": len(unresolved_refs),
        "rules_evaluated": len(OPENAPI_CHECKS), "network_requests": 0,
        "raw_content_retained": False,
    }


def _remediation(identifier):
    suffix = identifier.split(":", 1)[-1]
    if suffix in {"insecure-server", "basic-auth-http", "oauth-insecure-endpoint"}:
        return "Use verified HTTPS for API and OAuth endpoints and remove insecure server declarations."
    if suffix in {"missing-authentication", "optional-authentication", "unauthenticated-write"}:
        return "Confirm intended public access; declare required security on sensitive operations and enforce it at runtime."
    if suffix == "undefined-security-scheme":
        return "Correct security requirement names and define the intended security schemes."
    if suffix in {"query-api-key", "credential-url-parameter"}:
        return "Carry credentials in appropriate authorization headers or a protected request body, not URL components."
    if suffix in {"oauth-implicit", "oauth-password"}:
        return "Review migration to authorization code with PKCE or another suitable modern OAuth flow."
    if suffix == "undefined-oauth-scope":
        return "Align required OAuth scopes with the scheme and the authorization server's actual scope policy."
    if suffix == "sensitive-writable-property":
        return "Use request DTOs and allowlisted fields; mark server-controlled properties readOnly and enforce ownership/role authorization."
    return "Declare suitable maximum sizes and enforce request, pagination, and resource limits in the service or gateway."


def analyze_import(format: str, content: str, target: Target, synthetic: bool = False):
    document = _document(content)
    if format == "http":
        return _http(document, target, synthetic)
    if format == "openapi":
        try:
            return _openapi(document, target, synthetic)
        except ScopeError:
            raise
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ScopeError("OpenAPI contains unsupported or malformed declarations. Contents are omitted from this error.") from None
    raise ScopeError("Choose an HTTP capture or OpenAPI JSON import.")
