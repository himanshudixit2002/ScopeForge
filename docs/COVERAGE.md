# ScopeForge 0.2 coverage

ScopeForge implements 52 rule families: 24 response-header rules, 13 static-HTML rules, and 15 OpenAPI design rules. The dashboard’s **Check catalog** loads definitions from the running engine, including rule IDs, profiles, severity, CWE mapping, reference, and limitations. A family may emit no observation or several cookie-specific observations. Counts measure implemented checks and recorded observations, not proven vulnerabilities or bounty eligibility.

## Response headers — 24 families

Transport over HTTP; HSTS missing, malformed, or disabled; CSP missing, unsafe inline/eval, broad script/object sources, and wildcard framing; framing policy missing or invalid; MIME sniffing protection; missing or unsafe referrer policy; cookie Secure/HttpOnly/SameSite protections; SameSite=None without Secure; invalid `__Host-` and `__Secure-` cookie attributes; technology disclosure; wildcard/null CORS signals; public caching with cookies; redirect context.

The analyzer considers enforcing CSP headers together, including nonce/hash and `strict-dynamic` effects. Multiple policies can constrain each other. CORS observations do not establish that a browser exposes authenticated sensitive data: ScopeForge sends no injected Origin or credentials. Cookie flags may be irrelevant for a non-sensitive cookie. A disclosed technology name is not evidence of a vulnerable version or CVE. Missing security best practices often require demonstrated impact to qualify for a bounty. [OWASP HTTP header guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

## Static HTML — 13 families

Mixed active content; mixed passive content; password input over HTTP; password form using GET; password form posting to HTTP; other form actions using HTTP; password form submitting to an external origin; external script without integrity metadata; external stylesheet without integrity metadata; external base URL; directory-listing signature; debug-traceback signature; private-key marker.

Live HTML requires the program’s `web` permission profile. One GET reads at most 128 KiB of uncompressed HTML/XHTML in memory within the overall 256 KiB response cap and 10-second HTTP deadline. Non-HTML, compressed/ambiguous content types, and redirects skip body analysis. Responses are never rendered as HTML or JavaScript. Parser observations cannot account for every browser behavior, dynamic DOM change, application control, or false-positive marker. CSP upgrade/block settings and form ownership/submit overrides are considered conservatively. Missing integrity attributes are context-dependent observations. A private-key marker reports only the marker count; no key material is retained and key validity is not tested.

HTML evidence stores bounded counts and static explanations. Resource URLs, form fields/values, source snippets and raw body content are omitted. Truncation and skipped body analysis appear in the scan summary. An HTML rule absent from `checks` did not execute; an empty result is not proof the page is secure.

## Offline HTTP capture

Paste or open a JSON document in **Research lab**:

```json
{
  "status": 200,
  "headers": [
    {"name": "Content-Type", "value": "text/html; charset=utf-8"},
    {"name": "Set-Cookie", "value": "example=REDACTED; Path=/"}
  ],
  "body": "<html><body>A permitted captured page</body></html>"
}
```

This reuses the 37 header/HTML families on supplied evidence and sends **zero target requests or DNS lookups**. Imports receive separate `import-http:` rule identities and `http-import` provenance. The target URL associates evidence with the recorded scope; it does not authenticate the capture, establish freshness, or verify deployed behavior. No remote subresources are fetched. Inputs are at most 256 KiB UTF-8 JSON; at most 100 single-line headers, 8,192 characters per value, and bounded HTML are analyzed. Duplicate content-type ambiguity and encoded/redirect bodies skip HTML. Raw HTTP transcripts, HAR and YAML are not supported.

## OpenAPI design — 15 families

HTTP servers; missing authentication declarations; optional authentication alternatives; write operations without required declared authentication; undefined security schemes; API keys in query parameters; Basic authentication over HTTP; OAuth implicit grant; OAuth password grant; insecure OAuth endpoints; undefined OAuth scopes; credential-like URL parameters; unbounded pagination; sensitive writable properties; unbounded input arrays.

These are **document reviews**, not vulnerability confirmation. A gateway may enforce authentication outside the document, a route may intentionally be public, and a schema field may be protected in application code. URL credentials and outdated OAuth grants warrant review against current guidance. [OWASP REST security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), [OAuth security best current practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).

Supported inputs are JSON OpenAPI 3.0, 3.1 and 3.2. The parser reviews bounded `paths` operations and security inheritance, including operation overrides and optional alternatives. It is not a complete OpenAPI validator. Only bounded local references can be followed. External references are never fetched. Complex/ambiguous schema semantics, templated servers and unsupported operation shapes are skipped with warnings rather than inventing effective constraints. Composed schemas and reference siblings can carry constraints this analyzer does not merge. API routes do not become live scan targets or expand program scope. [OpenAPI specification](https://spec.openapis.org/oas/latest.html).

Processing limits: 256 KiB UTF-8 input, 40 nesting levels, 50,000 JSON nodes, 1,000 path entries, 1,000 reviewed operations, 20 local-reference hops, and 300 schema traversal nodes/20 schema levels per operation. Duplicate JSON keys, invalid constants and malformed shapes are rejected. Stored evidence contains rule context, counts and a bounded selection of ordinary route templates; opaque or potentially sensitive route labels are omitted. Examples, credentials, server URLs and raw specifications are not retained. The operator must keep an authorized original separately when reproduction needs it.

## Research workflow and boundaries

Record permitted header/web profiles when creating a program. Existing real 0.1 programs remain headers-only after upgrade. Use offline imports to review authorized evidence regardless of live profile selection; permission, scope, expiry and revocation still apply. Batches admit 1–20 distinct explicit URLs atomically, with a shared program interval and one request budget per URL. No wildcard discovery is performed.

Each repeated observation adds a sanitized occurrence and preserves analyst status/notes. HTTP, imported HTTP, OpenAPI and manual records retain separate provenance. A later scan without the observation does not automatically resolve an earlier finding. Manual evidence is saved as supplied, with no independent validation; redact it before saving. Exports are local drafts and are never submitted automatically.

This release does not test runtime access control/IDOR, authentication bypass, SQL injection, command execution, SSRF exploitability, stored/reflected/DOM XSS exploitability, business logic, race conditions, file upload exploitation, or authenticated multi-step workflows. It does not crawl, fuzz, brute-force, launch third-party scanner templates or contact described API endpoints. No finite automated check set can establish that an application is vulnerability-free. ScopeForge helps organize permitted investigation and evidence; eligibility and demonstrated impact require researcher review.
