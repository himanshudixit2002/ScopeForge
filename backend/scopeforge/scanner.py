"""One-URL, one-request observations. Bounded HTML analysis; no response retention."""

from dataclasses import dataclass, field
from html.parser import HTMLParser
import http.client
import io
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

from .security import Target, resolve_public_addresses
from .catalog import CHECK_DEFINITIONS

MAX_RESPONSE_BYTES = 256 * 1024
MAX_BODY_BYTES = 128 * 1024
REQUEST_TIMEOUT_SECONDS = 10.0
CHECKS = [item["id"] for item in CHECK_DEFINITIONS]


class ScanNetworkError(ValueError):
    pass


@dataclass(frozen=True)
class Snapshot:
    status: int
    headers: list[tuple[str, str]]
    synthetic: bool = False
    body: str = ""
    body_truncated: bool = False
    body_analyzed: bool = False
    metadata: dict = field(default_factory=dict)


class _BoundedReader(io.RawIOBase):
    """Bound all response reads, including headers, by bytes and elapsed time."""

    def __init__(self, sock, deadline: float):
        super().__init__()
        self.sock = sock
        self.deadline = deadline
        self.remaining = MAX_RESPONSE_BYTES

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining_time = self.deadline - time.monotonic()
        if remaining_time <= 0:
            raise TimeoutError("Response deadline exceeded.")
        if self.remaining <= 0:
            raise ScanNetworkError("Response exceeded the 256 KiB total response limit.")
        self.sock.settimeout(remaining_time)
        count = self.sock.recv_into(buffer, min(len(buffer), self.remaining))
        self.remaining -= count
        return count


class _ResponseSocket:
    def __init__(self, sock, deadline, before_send=None):
        self.sock = sock
        self.deadline = deadline
        self.before_send = before_send

    def makefile(self, mode, *args, **kwargs):
        if mode != "rb":
            raise ValueError("Only binary response reads are supported.")
        return io.BufferedReader(_BoundedReader(self.sock, self.deadline))

    def sendall(self, data, *args, **kwargs):
        if self.before_send is not None:
            callback, self.before_send = self.before_send, None
            callback()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Request deadline exceeded.")
        self.sock.settimeout(remaining)
        return self.sock.sendall(data, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.sock, name)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect directly to a vetted numeric IP; keep the original Host and SNI."""

    def __init__(self, target: Target, address: str, *, timeout=REQUEST_TIMEOUT_SECONDS, before_send=None):
        super().__init__(target.hostname, target.port, timeout=timeout)
        self.target = target
        self.address = address
        self.deadline = time.monotonic() + timeout
        self.before_send = before_send

    def connect(self):
        family = socket.AF_INET6 if ipaddress.ip_address(self.address).version == 6 else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(max(0.001, self.deadline - time.monotonic()))
            raw.connect((self.address, self.port))
            if self.target.scheme == "https":
                context = ssl.create_default_context()
                raw.settimeout(max(0.001, self.deadline - time.monotonic()))
                raw = context.wrap_socket(raw, server_hostname=self.target.hostname)
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Connection deadline exceeded.")
            raw.settimeout(remaining)
            self.sock = _ResponseSocket(raw, self.deadline, before_send=self.before_send)
        except BaseException:
            raw.close()
            raise


def fetch_headers(target: Target, *, before_request=None, before_send=None, profile="headers") -> Snapshot:
    if profile not in {"headers", "web"}:
        raise ValueError("Unsupported scan profile.")
    addresses = resolve_public_addresses(target.hostname, target.port)
    # Do not retry other addresses: a scan is at most one request attempt.
    if before_request is not None:
        before_request()
    connection = PinnedHTTPConnection(target, addresses[0], before_send=before_send)
    try:
        connection.request(
            "GET", target.path,
            headers={
                "Host": target.hostname,
                "User-Agent": "ScopeForge/0.2 (+authorized-one-url-review)",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.5",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        try:
            headers = response.getheaders()
            values = {}
            for name, value in headers:
                values.setdefault(name.lower(), []).append(value)
            content_types = values.get("content-type", [])
            html = len(content_types) == 1 and _is_html(content_types[0])
            encodings = values.get("content-encoding", [])
            identity = not encodings or all(value.strip().lower() == "identity" for value in encodings)
            skip = "headers-profile" if profile == "headers" else (
                "redirect-response" if 300 <= response.status < 400 else (
                    "unsupported-content-type" if not html else (
                        "compressed-content" if not identity else "")))
            if skip:
                return Snapshot(response.status, headers, metadata={"body_skip_reason": skip, "body_bytes": 0})
            # Read no more than the body budget, even for chunked responses.
            # Exact-budget bodies are conservatively marked possibly truncated;
            # no extra byte is read to distinguish EOF from a larger response.
            raw = response.read(MAX_BODY_BYTES)
            remaining_length = getattr(response, "length", None)
            truncated = len(raw) >= MAX_BODY_BYTES or (isinstance(remaining_length, int) and remaining_length > 0)
            encoding = "utf-8"
            charset = re.search(r"(?:^|;)\s*charset\s*=\s*[\"']?([A-Za-z0-9_-]+)", content_types[0], re.I)
            if charset and charset.group(1).lower() in {"iso-8859-1", "latin1", "windows-1252"}:
                encoding = "cp1252"
            body = raw.decode(encoding, errors="replace")
            return Snapshot(response.status, headers, body=body, body_truncated=truncated,
                            body_analyzed=True, metadata={"body_bytes": len(raw), "body_skip_reason": None})
        finally:
            response.close()
    except ssl.SSLCertVerificationError:
        raise ScanNetworkError("TLS certificate verification failed; insecure fallback is disabled.") from None
    except (socket.timeout, TimeoutError):
        raise ScanNetworkError("The target exceeded the ten-second request deadline.") from None
    except ScanNetworkError:
        raise
    except (OSError, http.client.HTTPException):
        raise ScanNetworkError("The target could not be reached or returned an invalid HTTP response.") from None
    finally:
        connection.close()


def demo_snapshot(profile="headers") -> Snapshot:
    snapshot = Snapshot(
        status=200,
        headers=[
            ("Content-Type", "text/html; charset=utf-8"),
            ("Server", "SyntheticTrainingServer/1.0"),
            ("X-Powered-By", "SyntheticFramework"),
            ("Set-Cookie", "training_session=SYNTHETIC_NOT_A_SECRET; Path=/"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
        synthetic=True,
    )
    if profile != "web":
        return snapshot
    body = """<!doctype html><html><head><title>ScopeForge SYNTHETIC training page</title>
    <base href="https://synthetic-assets.example/">
    <script src="http://synthetic-assets.example/training.js?sample=DO_NOT_RETAIN"></script>
    <link rel="stylesheet" href="https://synthetic-assets.example/training.css">
    </head><body><h1>SYNTHETIC offline demonstration</h1>
    <img src="http://synthetic-assets.example/training.png">
    <form action="http://synthetic-training.example/login" method="get">
    <input type="password" name="training_password" value="SYNTHETIC_DO_NOT_RETAIN">
    <button>Training form — never submitted</button></form>
    </body></html>"""
    return Snapshot(snapshot.status, snapshot.headers + [
        ("Strict-Transport-Security", "max-age=0"),
        ("Content-Security-Policy", "script-src * 'unsafe-inline' 'unsafe-eval'; object-src *"),
        ("Referrer-Policy", "unsafe-url"),
        ("Set-Cookie", "__Host-training=DO_NOT_RETAIN; Domain=synthetic-training.example; SameSite=None"),
        ("Cache-Control", "public, max-age=60"),
    ], True, body=body, body_analyzed=True, metadata={"body_bytes": len(body.encode()), "body_skip_reason": None})


def _is_html(content_type: str) -> bool:
    return content_type.partition(";")[0].strip().lower() in {"text/html", "application/xhtml+xml"}


def executed_checks(profile: str, snapshot: Snapshot) -> list[str]:
    """Report rules evaluated, including applicability checks, without claiming coverage."""
    return [item["id"] for item in CHECK_DEFINITIONS if profile in item["profiles"]
            and ("headers" in item["profiles"] or snapshot.body_analyzed)]


def analyze_headers(target: Target, snapshot: Snapshot) -> list[dict]:
    """Produce observations, never claims of exploitation or bounty eligibility."""
    values: dict[str, list[str]] = {}
    for name, value in snapshot.headers:
        values.setdefault(name.lower(), []).append(value)
    first = lambda name: values.get(name, [""])[0]
    observations = []
    observed_ids = set()
    prefix = "SYNTHETIC DEMO — offline fixture; no target was contacted.\n" if snapshot.synthetic else ""

    def add(check_id, title, severity, description, impact, remediation, evidence, confidence="high"):
        # A response may set one cookie name for several paths. Those paths are
        # deliberately not retained; record each family/name once per response
        # so a scan appends exactly one immutable occurrence for that finding.
        if check_id in observed_ids:
            return
        observed_ids.add(check_id)
        definition = next((item for item in CHECK_DEFINITIONS if item["id"] == check_id.split(":", 1)[0]), {})
        observations.append({
            "check_id": check_id, "title": title, "severity": severity, "confidence": confidence,
            "description": description, "impact": impact, "remediation": remediation,
            "evidence": prefix + f"HTTP status: {snapshot.status}\n" + evidence,
            "cwe": definition.get("cwe"), "category": definition.get("category", "Observation"),
        })

    if target.scheme == "http":
        add("transport-security", "Response served over unencrypted HTTP", "low",
            "The selected URL uses HTTP. Redirects are not followed, so the destination's protections have not been assessed.",
            "Traffic may be observable or modifiable in transit. Confirm whether this endpoint handles sensitive data before assigning impact.",
            "Serve the application over HTTPS and redirect HTTP traffic to its HTTPS origin.", "Transport: HTTP; no TLS connection was used.")

    if target.scheme == "https" and not first("strict-transport-security"):
        add("strict-transport-security", "HSTS header not observed", "low",
            "This HTTPS response did not include Strict-Transport-Security. A parent policy or browser preload may already cover the host.",
            "A missing header alone does not establish a downgrade attack. Check parent policy, preload coverage, and sensitive workflows manually.",
            "If appropriate for the domain, enable HSTS after testing HTTPS coverage and a safe rollout.", "Strict-Transport-Security: absent on this response.")

    html = _is_html(first("content-type"))
    policies = values.get("content-security-policy", [])
    csp = ",".join(policies)
    # Every enforcing CSP applies. Match directive names, not substrings in
    # source expressions or report URLs. Commas separate combined policies.
    csp_directives = {
        directive.strip().split()[0].lower()
        for policy in policies for part in policy.split(",")
        for directive in part.split(";") if directive.strip()
    }
    if html and not csp:
        add("content-security-policy", "CSP response header not observed", "low",
            "An HTML response did not include an enforcing Content-Security-Policy header. This header-specific observation does not establish whether a document-level meta policy provides protection.",
            "This is a defense-in-depth observation; it does not prove cross-site scripting or exploitable content injection.",
            "Review existing policies and introduce a tested nonce- or hash-based CSP where appropriate.", "Content-Type: HTML\nContent-Security-Policy response header: absent.")

    if html and not first("x-frame-options") and "frame-ancestors" not in csp_directives:
        add("framing-policy", "Framing restriction not observed", "low",
            "Neither X-Frame-Options nor an enforcing CSP frame-ancestors directive was observed on this HTML response.",
            "Clickjacking requires a sensitive, frameable UI and a reproducible user action. This response alone does not demonstrate either.",
            "Set CSP frame-ancestors to the intended embedding origins, and consider X-Frame-Options for older clients.", "X-Frame-Options: absent\nCSP frame-ancestors: not observed.")

    if first("x-content-type-options").strip().lower() != "nosniff":
        add("content-type-options", "MIME sniffing protection not observed", "low",
            "X-Content-Type-Options: nosniff was not observed on this response.",
            "Impact depends on content types and whether untrusted content can be served. No injection or browser exploitation was tested.",
            "Send correct Content-Type values and X-Content-Type-Options: nosniff.", "X-Content-Type-Options: nosniff not observed.")

    if html and not first("referrer-policy"):
        add("referrer-policy", "Explicit referrer policy not observed", "info",
            "No Referrer-Policy response header was found. Browser defaults or document-level policies may provide protection.",
            "Sensitive URL data leakage would require separate evidence. Query strings and document-level policy effects are not evaluated.",
            "Choose a Referrer-Policy appropriate for the application, such as strict-origin-when-cross-origin.", "Referrer-Policy response header: absent.")

    cookie_flags: dict[str, set[str]] = {}
    for cookie in values.get("set-cookie", []):
        # Values never leave this function. Only syntactically safe names and
        # attribute presence become evidence; malformed cookies are omitted.
        parts = cookie.split(";")
        name, separator, _value = parts[0].partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", name):
            continue
        attributes = {part.partition("=")[0].strip().lower() for part in parts[1:]}
        missing = set()
        if target.scheme == "https" and "secure" not in attributes:
            missing.add("Secure")
        if "httponly" not in attributes:
            missing.add("HttpOnly")
        if "samesite" not in attributes:
            missing.add("SameSite")
        if missing:
            cookie_flags.setdefault(name, set()).update(missing)
    for name, missing in cookie_flags.items():
        missing_text = ", ".join(sorted(missing))
        add(f"cookie-flags:{name}", f"Cookie attributes need review: {name}", "low" if missing - {"SameSite"} else "info",
            f"The {name} cookie was observed without: {missing_text}. Its purpose and sensitivity were not assessed.",
            "Some cookies intentionally permit client-side access. Browser SameSite defaults also vary. Confirm session or sensitive use before treating this as a vulnerability.",
            "For sensitive cookies, set Secure, HttpOnly, and an appropriate explicit SameSite policy after checking application behavior.",
            f"Set-Cookie: {name}=[REDACTED]\nAttributes not observed: {missing_text}.")

    disclosed = [name for name in ("server", "x-powered-by", "x-aspnet-version") if name in values]
    if disclosed:
        add("technology-disclosure", "Technology disclosure headers observed", "info",
            "Response headers identify server or framework technology. Their values are intentionally omitted from stored evidence.",
            "Technology identification is generally informational and is rarely bounty-eligible on its own. No version vulnerability was inferred.",
            "Remove unnecessary identification headers where practical; keep dependencies patched regardless of disclosure.", "Headers present: " + ", ".join(disclosed) + ". Values omitted.")

    if first("access-control-allow-origin") == "*":
        credentials = first("access-control-allow-credentials").strip().lower() == "true"
        add("cors-policy", "Wildcard CORS policy observed", "info",
            "Access-Control-Allow-Origin allows any origin for non-credentialed browser access." + (" Allow-Credentials is also true, but browsers reject credentialed access with a wildcard origin." if credentials else ""),
            "Wildcard CORS is valid for public resources. No malicious Origin, credentials, or sensitive response data was tested; data exposure is not established.",
            "Confirm that this resource is intentionally public. Restrict origins only when required by the resource's access model.",
            "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: " + ("true" if credentials else "not true") + ".")

    if 300 <= snapshot.status < 400:
        add("redirect-observation", "Redirect response received; destination not scanned", "info",
            "The target responded with a redirect. No redirect was followed and the destination was not evaluated.",
            "This is execution context, not an open redirect finding. No destination manipulation was attempted.",
            "If further review is needed, confirm that the destination is explicitly authorized before creating another scan.", "Redirect following: disabled\nLocation value: omitted.")
    document = None
    if html and snapshot.body_analyzed:
        document = _HTMLObservations(target)
        bounded_body = snapshot.body.encode("utf-8", errors="replace")[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
        document.feed(bounded_body)
        document.close()
    enforcing = _parse_policies(policies)
    # Meta CSP is considered only as an extra constraint. It cannot create a
    # weak-header finding and frame-ancestors in meta never protects embedding.
    meta_policies = _parse_policies(document.meta_policies) if document else []
    for policy in meta_policies:
        # These directives do not apply when delivered in a meta element.
        for name in ("sandbox", "frame-ancestors", "report-uri", "report-to"):
            policy.pop(name, None)
    effective_script_policies = enforcing + meta_policies
    _analyze_extended_headers(target, values, html, enforcing, effective_script_policies, add)
    if document is not None:
        _analyze_document(target, document, effective_script_policies, snapshot.body_truncated, add)
    return observations


def _parse_policies(fields: list[str]) -> list[dict[str, list[str]]]:
    result = []
    for field_value in fields:
        for serialized in field_value.split(","):
            policy = {}
            for directive in serialized.split(";"):
                tokens = directive.split()
                if tokens:
                    # CSP ignores repeated instances after the first directive.
                    policy.setdefault(tokens[0].lower(), [token.lower() for token in tokens[1:]])
            if policy:
                result.append(policy)
    return result


def _sources(policy, kind):
    fallbacks = {"script-src-elem": ("script-src-elem", "script-src", "default-src"),
                 "script-src": ("script-src", "default-src"),
                 "object-src": ("object-src", "default-src")}
    return next((policy[name] for name in fallbacks.get(kind, (kind,)) if name in policy), None)


def _inline_allowed(sources):
    return sources is None or ("'unsafe-inline'" in sources and "'strict-dynamic'" not in sources
        and not any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[a-z0-9+/_=-]+'", token) for token in sources))


def _broad_source_intersection(policies, kind):
    allowed = {"http:", "https:", "data:"}
    observed = False
    for policy in policies:
        sources = _sources(policy, kind)
        if sources is None:
            continue
        if kind.startswith("script") and "'strict-dynamic'" in sources:
            return False
        broad = set(sources) & {"http:", "https:", "data:"}
        if "*" in sources:
            broad |= {"http:", "https:"}
        observed |= bool(broad)
        allowed &= broad
    return observed and bool(allowed)


def _analyze_extended_headers(target, values, html, enforcing, scripts, add):
    first = lambda name: values.get(name, [""])[0]
    if target.scheme == "https" and "strict-transport-security" in values:
        directives = [item.strip().partition("=") for item in first("strict-transport-security").split(";")]
        age_directives = [(separator, value.strip()) for name, separator, value in directives if name.strip().lower() == "max-age"]
        ages = [value for separator, value in age_directives if separator]
        valid = len(age_directives) == len(ages) == 1 and re.fullmatch(r'(?:[0-9]+|"[0-9]+")', ages[0])
        if not valid:
            add("hsts-invalid", "HSTS max-age is malformed", "low",
                "The first HSTS response field does not contain one valid nonnegative integer max-age directive.",
                "Browsers may ignore this field. Existing HSTS state, parent coverage, or preload may still protect the host.",
                "Send one valid HSTS policy after verifying HTTPS deployment and rollback requirements.",
                "HSTS field present; max-age missing, duplicated, or nonnumeric. Raw policy omitted.")
        elif not ages[0].strip('"').strip("0"):
            add("hsts-disabled", "HSTS policy sets max-age to zero", "low",
                "The HTTPS response asks browsers to expire this host's dynamic HSTS policy.",
                "This may be a deliberate rollback. Parent policies and preload can still apply; no downgrade was tested.",
                "Confirm the rollback is intended, or restore a tested positive max-age policy.", "Strict-Transport-Security max-age: 0.")

    if html and enforcing:
        scripts_blocked = any("sandbox" in policy and "allow-scripts" not in policy["sandbox"] for policy in scripts)
        inline = [_sources(policy, "script-src-elem") for policy in scripts]
        inline_observed = any(source is not None and "'unsafe-inline'" in source for source in [_sources(policy, "script-src-elem") for policy in enforcing])
        if not scripts_blocked and inline_observed and all(_inline_allowed(source) for source in inline):
            add("csp-unsafe-inline", "Enforcing CSP allows unrestricted inline scripts", "low",
                "Unsafe-inline remains effective for script elements across the observed enforcing policies; no nonce, hash, or strict-dynamic restriction suppressed it.",
                "This weakens a defense against injected scripts but does not establish an injection vulnerability.",
                "Use a tested nonce- or hash-based script policy and remove unrestricted inline execution where possible.",
                "Effective script policy observation: unsafe-inline. Policy text and nonces omitted.")
        eval_sources = [_sources(policy, "script-src") for policy in scripts]
        eval_observed = any(source is not None and "'unsafe-eval'" in source for source in [_sources(policy, "script-src") for policy in enforcing])
        if not scripts_blocked and eval_observed and all(source is None or "'unsafe-eval'" in source for source in eval_sources):
            add("csp-unsafe-eval", "Enforcing CSP permits string evaluation", "low",
                "All observed script policies allow unsafe-eval or do not constrain it.",
                "A script must still evaluate attacker-controlled strings for exploitation; no script is executed or inspected for that behavior.",
                "Remove unsafe-eval after replacing dependencies or code paths that require string compilation.",
                "Effective script policy observation: unsafe-eval. Raw policy omitted.")
        if not scripts_blocked and _broad_source_intersection(enforcing, "script-src-elem") and _broad_source_intersection(scripts, "script-src-elem"):
            add("csp-broad-script-sources", "CSP has broadly allowed script sources", "low",
                "A wildcard, scheme-wide, or data script source remains broadly allowed across the observed policy constraints.",
                "This can weaken CSP's value after content injection. It does not demonstrate that injected scripts can run.",
                "Restrict script sources and consider a tested nonce/hash policy with strict-dynamic.",
                "Broad script source class observed; hosts, nonces, URLs, and policy values omitted.")
        if _broad_source_intersection(enforcing, "object-src") and _broad_source_intersection(scripts, "object-src"):
            add("csp-broad-object-sources", "CSP has broadly allowed object sources", "low",
                "An explicit object-src or fallback default-src policy permits broad object resource origins.",
                "Browser and plugin support vary; no object content was requested or executed.",
                "Use object-src 'none' when embedded object resources are unnecessary.",
                "Broad object source class observed. Policy values omitted.")
        ancestors = [policy["frame-ancestors"] for policy in enforcing if "frame-ancestors" in policy]
        if ancestors and all("*" in source for source in ancestors):
            add("csp-framing-wildcard", "CSP frame-ancestors allows wildcard embedding", "low",
                "Every observed frame-ancestors policy includes a wildcard source.",
                "Sensitive, frameable actions are required to establish clickjacking; no embedding or interaction was attempted.",
                "Restrict frame-ancestors to the application's intended embedding origins.", "CSP frame-ancestors: wildcard in all applicable policies.")

    if html and "x-frame-options" in values and not any("frame-ancestors" in policy for policy in enforcing):
        frames = [value.strip().upper() for field in values["x-frame-options"] for value in field.split(",")]
        if len(set(frames)) != 1 or frames[0] not in {"DENY", "SAMEORIGIN"}:
            add("framing-policy-invalid", "X-Frame-Options value needs correction", "low",
                "The response includes unsupported or conflicting X-Frame-Options tokens and no enforcing frame-ancestors directive.",
                "Browser handling varies; unsupported ALLOW-FROM is not a reliable framing defense. No clickjacking workflow was tested.",
                "Set one valid DENY or SAMEORIGIN value, or configure CSP frame-ancestors for intended origins.",
                "X-Frame-Options: unsupported or conflicting values. Raw values omitted.")

    valid_referrers = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
    referrers = [item.strip().lower() for field in values.get("referrer-policy", []) for item in field.split(",") if item.strip().lower() in valid_referrers]
    if html and referrers and referrers[-1] in {"unsafe-url", "no-referrer-when-downgrade"}:
        add("referrer-policy-unsafe", "Response declares a permissive referrer policy", "info",
            "The last recognized response policy can include path and query information in some cross-origin referrers.",
            "Actual disclosure requires sensitive URL data and a navigation or request; document/element policies may override this default.",
            "Consider strict-origin-when-cross-origin or a stricter policy after checking application requirements.",
            "Last recognized Referrer-Policy token: " + referrers[-1] + ".")

    cookie_count = 0
    for cookie in values.get("set-cookie", []):
        parts = cookie.split(";")
        name, separator, _ = parts[0].partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", name):
            continue
        cookie_count += 1
        attributes = {}
        for part in parts[1:]:
            attr, _, value = part.partition("=")
            attributes[attr.strip().lower()] = value.strip()
        flags = set(attributes)
        evidence = f"Set-Cookie: {name}=[REDACTED]\n"
        if attributes.get("samesite", "").lower() == "none" and "secure" not in flags:
            add("cookie-samesite-none:" + name, "SameSite=None cookie lacks Secure: " + name, "low",
                "A cookie declares SameSite=None without the Secure attribute.",
                "Modern browsers typically reject this cookie. This is a configuration observation, not proof of CSRF or session compromise.",
                "Use Secure with SameSite=None over HTTPS, or choose an appropriate Lax/Strict policy.", evidence + "SameSite: None; Secure: absent.")
        if name.startswith("__Host-") and (target.scheme != "https" or "secure" not in flags or "domain" in flags or attributes.get("path") != "/"):
            add("cookie-host-prefix:" + name, "__Host- cookie requirements not met: " + name, "low",
                "This prefixed cookie does not satisfy all of HTTPS origin, Secure, Path=/, and absence of Domain.",
                "Supporting browsers reject invalid prefixed cookies; legacy behavior and application impact need manual review.",
                "Set __Host- cookies over HTTPS with Secure and Path=/, without a Domain attribute.", evidence + "Required __Host- constraints are not all present. Attribute values omitted.")
        if name.startswith("__Secure-") and (target.scheme != "https" or "secure" not in flags):
            add("cookie-secure-prefix:" + name, "__Secure- cookie requirements not met: " + name, "low",
                "A __Secure- cookie lacks Secure or was observed on an HTTP response.",
                "Supporting browsers reject invalid prefixed cookies. No cookie was replayed and session impact is unknown.",
                "Set __Secure- cookies only over HTTPS with the Secure attribute.", evidence + "Secure prefix requirements are not satisfied.")

    if (len(values.get("access-control-allow-origin", [])) == len(values.get("access-control-allow-credentials", [])) == 1
            and first("access-control-allow-origin").strip() == "null" and first("access-control-allow-credentials").strip() == "true"):
        add("cors-null-origin", "CORS allows credentialed access from the null origin", "low",
            "This response declares Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true.",
            "Several opaque-origin contexts serialize to null. Sensitive credentialed access is unproven because no Origin or credentials were sent.",
            "Avoid trusting null as an origin when serving private data; use an explicit validated origin allowlist.",
            "Access-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true. No Origin test performed.")
    # No-cache allows storage. Private/no-store are conservative suppressors,
    # including field-qualified private, whose field semantics require review.
    cache = []
    for value in values.get("cache-control", []):
        cache.extend(part.strip().lower() for part in re.findall(r'(?:[^,\"]|\"[^\"]*\")+', value))
    cache_names = {part.partition("=")[0].strip() for part in cache}
    shared = "public" in cache_names or any(re.fullmatch(r's-maxage\s*=\s*"?0*[1-9][0-9]*"?', part) for part in cache)
    if cookie_count and shared and not cache_names & {"private", "no-store"}:
        add("public-cache-cookie", "Cookie-setting response explicitly permits shared caching", "info",
            "This response sets cookies and declares public or a positive s-maxage without private/no-store.",
            "Public cookies and shared resources may be intentional. Cookie sensitivity, actual cache storage, and cross-user disclosure were not tested.",
            "For personalized or sensitive responses, verify cache keys and use suitable private/no-store controls.",
            f"Cookie fields with safe names: {cookie_count}\nExplicit shared caching: observed\nPrivate/no-store: absent. Cookie values omitted.")


class _HTMLObservations(HTMLParser):
    """A bounded markup inventory, not a browser. Everything here is ephemeral."""

    def __init__(self, target):
        super().__init__(convert_charrefs=True)
        self.target = target
        self.base_href = None
        self.resources = []
        self.forms = []
        self.controls = []
        self.current_form = None
        self.meta_policies = []
        self.visible_text = []
        self.headings = []
        self.in_heading = 0
        self.ignored = []
        self.in_head = True
        self.disabled_fieldsets = []
        self.nodes = 0
        self.limited = False

    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        if self.nodes > 10000:
            self.limited = True
            return
        # HTML keeps the first duplicate attribute. Never persist arbitrary
        # attribute text, names, IDs, URLs, field values, or inline script text.
        attributes = {}
        for name, value in attrs:
            attributes.setdefault(name, value or "")
        if self.ignored:
            if tag in {"template", "noscript"}:
                self.ignored.append(tag)
            return
        if tag in {"script", "style", "template", "noscript"}:
            if tag == "script" and attributes.get("src") and attributes.get("type", "").strip().lower() in {
                "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript",
            }:
                self.resources.append(("script", attributes["src"], bool(attributes.get("integrity", "").strip())))
            self.ignored.append(tag)
            return
        if tag == "body":
            self.in_head = False
        if tag == "base" and self.base_href is None and "href" in attributes:
            self.base_href = attributes["href"]
        if tag == "meta" and self.in_head and attributes.get("http-equiv", "").lower() == "content-security-policy":
            self.meta_policies.append(attributes.get("content", ""))
        if tag in {"h1", "title"}:
            self.in_heading += 1
        if tag == "fieldset":
            self.disabled_fieldsets.append("disabled" in attributes)
        if tag == "form" and self.current_form is None:
            self.current_form = len(self.forms)
            self.forms.append(attributes)
        if tag in {"input", "button"} and "disabled" not in attributes and not any(self.disabled_fieldsets):
            self.controls.append((tag, attributes, self.current_form))
        if tag == "link" and "stylesheet" in attributes.get("rel", "").lower().split() and attributes.get("href"):
            self.resources.append(("stylesheet", attributes["href"], bool(attributes.get("integrity", "").strip())))
        resource = {"iframe": "src", "frame": "src", "object": "data", "embed": "src", "img": "src", "audio": "src", "video": "src", "source": "src"}.get(tag)
        if resource and attributes.get(resource):
            self.resources.append((tag, attributes[resource], False))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.limited:
            return
        if self.ignored:
            if tag == self.ignored[-1]:
                self.ignored.pop()
            return
        if tag == "head":
            self.in_head = False
        if tag in {"h1", "title"} and self.in_heading:
            self.in_heading -= 1
        if tag == "form":
            self.current_form = None
        if tag == "fieldset" and self.disabled_fieldsets:
            self.disabled_fieldsets.pop()

    def handle_data(self, text):
        if not self.ignored and not self.limited:
            self.visible_text.append(text)
            if self.in_heading:
                self.headings.append(text)


def _resolve_markup_url(base, value):
    # Match browser treatment of ASCII tab/newline characters in URL attributes;
    # invalid port/netloc syntax is skipped, never echoed in an exception.
    value = value.replace("\t", "").replace("\r", "").replace("\n", "").strip()
    try:
        url = urljoin(base, value)
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return url, (parsed.scheme, parsed.hostname.lower(), port)
    except (ValueError, UnicodeError):
        return None


def _analyze_document(target, document, policies, body_truncated, add):
    origin = (target.scheme, target.hostname, target.port)
    base = _resolve_markup_url(target.url, document.base_href) if document.base_href is not None else None
    base_url = base[0] if base else target.url
    counters = {}

    def count(name):
        counters[name] = counters.get(name, 0) + 1

    def record(check_id, title, severity, description, impact, remediation):
        if counters.get(check_id):
            limited = body_truncated or document.limited
            add(check_id, title, severity, description, impact, remediation,
                f"Matching markup observations: {counters[check_id]}\n"
                + ("Only a bounded document prefix was inspected.\n" if limited else "")
                + "URLs, paths, query strings, field names/values, and raw HTML omitted. No resource loaded or form submitted.",
                confidence="medium" if check_id in {"directory-listing", "debug-traceback", "private-key-marker"} else "high")

    if base and base[1] != origin:
        count("external-base")
    upgrades = any("upgrade-insecure-requests" in policy for policy in policies)
    for kind, source, integrity in document.resources:
        resolved = _resolve_markup_url(base_url, source)
        if not resolved:
            continue
        _, resource_origin = resolved
        if target.scheme == "https" and resource_origin[0] == "http" and not upgrades:
            count("mixed-content-passive" if kind in {"img", "audio", "video", "source"} else "mixed-content-active")
        if kind in {"script", "stylesheet"} and resource_origin != origin and not integrity:
            count(kind + "-integrity")

    forms_by_id = {}
    for index, form in enumerate(document.forms):
        if form.get("id"):
            forms_by_id.setdefault(form["id"], index)
    password_forms = set()
    overrides = {}
    for tag, attrs, owner in document.controls:
        if "form" in attrs:
            owner = forms_by_id.get(attrs["form"])
        kind = attrs.get("type", "submit" if tag == "button" else "text").strip().lower()
        if tag == "input" and kind == "password":
            if target.scheme == "http":
                count("password-over-http")
            # Unnamed controls are not successful form controls in native
            # submissions; do not claim GET/HTTP submission on those alone.
            if owner is not None and attrs.get("name"):
                password_forms.add(owner)
        if owner is not None and ((tag == "button" and kind not in {"reset", "button"}) or (tag == "input" and kind in {"submit", "image"})):
            if "formaction" in attrs or "formmethod" in attrs:
                overrides.setdefault(owner, []).append(attrs)

    for index, form in enumerate(document.forms):
        methods = set()
        origins = set()
        for override in [{}] + overrides.get(index, []):
            method = override.get("formmethod", form.get("method", "get")).strip().lower()
            if method == "dialog":
                continue
            action = override.get("formaction", form.get("action", ""))
            # Empty/missing action targets the document URL, not the base URL.
            resolved = _resolve_markup_url(base_url, action) if action.strip() else _resolve_markup_url(target.url, target.url)
            if resolved:
                methods.add("post" if method == "post" else "get")
                origins.add(resolved[1])
        is_password = index in password_forms
        if is_password and "get" in methods:
            count("password-form-get")
        if any(item[0] == "http" for item in origins):
            if is_password:
                count("password-form-http")
            elif target.scheme == "https":
                count("form-action-http")
        if is_password and any(item != origin for item in origins):
            count("password-form-external")

    visible = " ".join(document.visible_text)
    headings = " ".join(document.headings)
    if re.search(r"\bindex\s+of\s+/", headings, re.I) and re.search(r"\bparent\s+directory\b", visible, re.I):
        count("directory-listing")
    signatures = [
        (r"Traceback\s*\(most recent call last\)", r'File\s+["\'][^"\']{1,300}["\'],\s*line\s+\d+'),
        (r"Werkzeug\s+Debugger", r"(?:traceback|debugger)",),
        (r"Django Version\s*:", r"Exception (?:Type|Value)\s*:"),
        (r"(?:Fatal error|Uncaught (?:Error|Exception))", r"\bon\s+line\s+\d+"),
    ]
    if any(all(re.search(pattern, visible, re.I) for pattern in pair) for pair in signatures):
        count("debug-traceback")
    # Only armor marker pairs are counted. No key content is interpreted,
    # fingerprinted, returned, or written to disk.
    key_ends = {kind: visible.rfind("-----END " + kind + "PRIVATE KEY-----") for kind in ("", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED ")}
    for marker in re.finditer(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?)PRIVATE KEY-----", visible):
        if key_ends[marker.group(1)] >= marker.end():
            count("private-key-marker")

    record("mixed-content-active", "HTTPS HTML references HTTP active resources", "low",
           "The inspected markup references HTTP scripts, stylesheets, frames, or embedded objects from an HTTPS document.",
           "Modern browsers usually block active mixed content. Runtime behavior, HSTS coverage, and content exploitability were not tested.",
           "Use HTTPS or same-origin secure references and verify the page's browser console after deployment.")
    record("mixed-content-passive", "HTTPS HTML references HTTP media", "info",
           "The inspected markup contains HTTP media references in an HTTPS page.",
           "Modern browsers generally upgrade these resources or block them; successful insecure transfer was not observed.",
           "Use HTTPS media URLs and review browser mixed-content diagnostics.")
    record("password-over-http", "Password controls appear on an HTTP page", "medium",
           "An enabled password input was observed in markup received over unencrypted HTTP.",
           "An active network attacker could modify an HTTP page. No password value was collected or submitted and no attack was attempted.",
           "Serve the entire login experience over HTTPS, including the form page, and deploy appropriate transport policies.")
    record("password-form-get", "Password form declares GET submission", "medium",
           "A form with an enabled named password control uses GET by default, explicitly, or through a submit-button override.",
           "Native submission may place password data in a URL. Runtime handlers may change behavior; the form was never submitted.",
           "Use POST over HTTPS for password forms, verify submit-button overrides, and avoid credentials in URLs.")
    record("password-form-http", "Password form targets an HTTP destination", "medium",
           "A form with a named password input declares an HTTP submission destination, including observed submit-button overrides.",
           "Native submission could expose credentials in transit, but browser upgrades, CSP, HSTS, and runtime handlers were not evaluated.",
           "Use an HTTPS action for all password submissions and verify the flow in an authorized test environment.")
    record("form-action-http", "HTTPS form targets an HTTP destination", "low",
           "A non-password form in HTTPS markup declares an HTTP action or submit-button override.",
           "Form data may be sensitive, but its contents, runtime handlers, and browser transmission behavior are unknown.",
           "Use HTTPS form destinations and verify all submit-button action overrides.")
    record("password-form-external", "Password form submits across origins", "info",
           "A password form's declared HTTP(S) submission origin differs from the document origin.",
           "This may be an intentional identity-provider integration. No leakage, malicious destination, or credential transfer is established.",
           "Confirm that the destination is controlled and expected for the authentication flow.")
    record("script-integrity", "Cross-origin scripts lack integrity metadata", "info",
           "Cross-origin script elements were found without a nonempty integrity attribute.",
           "This is a supply-chain hardening observation. Trusted hosting, CSP, or dynamic-resource requirements may justify the design.",
           "For stable third-party scripts, consider Subresource Integrity with suitable CORS settings, version pinning, or self-hosting.")
    record("stylesheet-integrity", "Cross-origin stylesheets lack integrity metadata", "info",
           "Cross-origin stylesheet links were found without integrity metadata.",
           "No stylesheet was fetched or found compromised; controlled hosting or dynamic stylesheets may justify this configuration.",
           "Consider integrity metadata for stable external stylesheets and keep third-party resources under review.")
    record("external-base", "Document base URL changes the origin", "info",
           "The first base href resolves to an HTTP(S) origin different from the selected page.",
           "Relative resources and nonempty form actions may resolve against that base. Intentional CDN use is common; injection was not tested.",
           "Confirm the base origin is intentional and consider an appropriate CSP base-uri directive.")
    record("directory-listing", "Directory-index markup signature observed", "low",
           "An Index of heading and Parent Directory text were observed together in the inspected document prefix.",
           "A generated listing may disclose files, but documentation can match this signature. No listed file was opened or retained.",
           "Verify whether the response is a directory index and disable unintended auto-indexing or restrict access.")
    record("debug-traceback", "Debug diagnostic markup signature observed", "low",
           "The inspected document contains characteristic traceback or framework diagnostic text.",
           "Detailed errors can reveal internals, but documentation may contain examples. Stack frames, paths, and error contents were omitted.",
           "Use generic production error pages and keep detailed diagnostic data in access-controlled logs.")
    record("private-key-marker", "Private-key armor markers observed in HTML text", "medium",
           "Matching private-key begin/end markers were found in the inspected HTML text; key material was not parsed or retained.",
           "This could be documentation, an example, or a real key. Validity, ownership, and usage are unverified.",
           "Review the response privately. If an actual secret was exposed, remove it and follow the owner's key-rotation process.")
