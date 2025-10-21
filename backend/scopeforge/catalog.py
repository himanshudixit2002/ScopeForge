"""Auditable catalog: every entry corresponds to an implemented observation rule."""

from copy import deepcopy

MDN = "https://developer.mozilla.org/en-US/docs/"
OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/"
CSP = MDN + "Web/HTTP/Reference/Headers/Content-Security-Policy"
COOKIE = MDN + "Web/HTTP/Reference/Headers/Set-Cookie"
HSTS = MDN + "Web/HTTP/Reference/Headers/Strict-Transport-Security"
MIXED = MDN + "Web/Security/Defenses/Mixed_content"
FORM = MDN + "Web/HTML/Reference/Elements/form"
HEADERS = OWASP + "HTTP_Headers_Cheat_Sheet.html"


def _check(id, title, category, severity, cwe, description, limitations, reference_url, *, body=False):
    return dict(id=id, title=title, category=category, profiles=["web"] if body else ["headers", "web"],
                severity=severity, cwe=cwe, description=description, limitations=limitations,
                reference_url=reference_url)


CHECK_DEFINITIONS = [
    _check("transport-security", "Unencrypted response transport", "Transport", "low", "CWE-319", "Records a selected HTTP URL.", "No HTTPS endpoint or sensitive transaction is tested.", HEADERS),
    _check("strict-transport-security", "Missing HSTS header", "Transport", "low", "CWE-319", "Checks HTTPS responses for an HSTS header.", "Parent policy and preload protection are not checked.", HSTS),
    _check("content-security-policy", "Missing CSP response header", "Browser policy", "low", "CWE-693", "Checks HTML for an enforcing CSP response header.", "Missing defense in depth does not establish injection; a meta policy may apply.", CSP),
    _check("framing-policy", "Missing framing restriction", "Browser policy", "low", "CWE-1021", "Looks for X-Frame-Options or enforcing frame-ancestors.", "No frame is rendered and no sensitive action is identified.", CSP + "/frame-ancestors"),
    _check("content-type-options", "Missing nosniff protection", "Browser policy", "low", "CWE-693", "Checks for X-Content-Type-Options: nosniff.", "Does not establish browser exploitation or attacker-controlled content.", HEADERS),
    _check("referrer-policy", "Missing referrer policy header", "Privacy", "info", "CWE-200", "Checks HTML for a Referrer-Policy response header.", "Browser defaults, document policy, and element overrides may apply.", MDN + "Web/HTTP/Reference/Headers/Referrer-Policy"),
    _check("cookie-flags", "Cookie attribute review", "Cookies", "low", "CWE-614", "Reports missing Secure, HttpOnly, and SameSite attributes by redacted cookie name.", "Cookie sensitivity is unknown; client-readable cookies can be intentional. SameSite-only observations are informational.", COOKIE),
    _check("technology-disclosure", "Technology headers", "Exposure", "info", "CWE-200", "Detects technology identification header names; omits their values.", "No software version, CVE, or exploitability is inferred.", HEADERS),
    _check("cors-policy", "Wildcard CORS observation", "Cross-origin", "info", "CWE-942", "Records a wildcard allowed origin.", "Public resources may intentionally use wildcard CORS; browsers reject wildcard credentialed access.", MDN + "Web/HTTP/Guides/CORS"),
    _check("redirect-observation", "Unfollowed redirect", "Execution context", "info", None, "Records a redirect without retaining its destination.", "This is execution context, not an open redirect vulnerability.", MDN + "Web/HTTP/Guides/Redirections"),
    _check("hsts-invalid", "Malformed HSTS max-age", "Transport", "low", "CWE-693", "Detects missing, duplicate, or nonnumeric max-age in the first HSTS field.", "Existing browser HSTS state, parent policies, and preload may protect the host.", HSTS),
    _check("hsts-disabled", "HSTS max-age zero", "Transport", "low", "CWE-319", "Detects an HTTPS response that sets max-age=0.", "This can be an intentional rollback; parent HSTS and preload are not evaluated.", HSTS),
    _check("csp-unsafe-inline", "CSP permits unrestricted inline scripts", "Browser policy", "low", "CWE-693", "Finds effective unsafe-inline after examining all enforcing script policies.", "Nonce/hash policies, restrictive additional policies, and strict-dynamic suppress the rule; no injection is attempted.", CSP + "/script-src"),
    _check("csp-unsafe-eval", "CSP permits string evaluation", "Browser policy", "low", "CWE-693", "Finds unsafe-eval when no enforcing script policy blocks it.", "No eval call or attacker-controlled input is established.", CSP + "/script-src"),
    _check("csp-broad-script-sources", "Broad CSP script sources", "Browser policy", "low", "CWE-693", "Detects wildcard, HTTP(S) scheme-wide, or data script source lists across enforcing policies.", "Host-specific intersections and strict-dynamic are treated conservatively; no script is loaded.", CSP + "/script-src"),
    _check("csp-broad-object-sources", "Broad CSP object sources", "Browser policy", "low", "CWE-693", "Detects explicit broad object-src or fallback default-src lists.", "Plugin and browser support vary; no object is loaded.", CSP + "/object-src"),
    _check("csp-framing-wildcard", "Wildcard CSP frame ancestors", "Browser policy", "low", "CWE-1021", "Detects a wildcard in every applicable frame-ancestors policy.", "No UI is embedded; multiple restrictive policies suppress the observation.", CSP + "/frame-ancestors"),
    _check("framing-policy-invalid", "Invalid X-Frame-Options", "Browser policy", "low", "CWE-1021", "Detects unsupported or conflicting X-Frame-Options values.", "An enforcing frame-ancestors policy takes precedence and suppresses this rule; browser handling can vary.", MDN + "Web/HTTP/Reference/Headers/X-Frame-Options"),
    _check("referrer-policy-unsafe", "Permissive referrer policy", "Privacy", "info", "CWE-200", "Evaluates the last recognized response policy for unsafe-url or no-referrer-when-downgrade.", "Sensitive URLs and document/element overrides are not tested.", MDN + "Web/HTTP/Reference/Headers/Referrer-Policy"),
    _check("cookie-samesite-none", "SameSite=None without Secure", "Cookies", "low", "CWE-1275", "Detects cookies declaring SameSite=None without Secure.", "Modern browsers usually reject these cookies; this does not prove CSRF.", COOKIE),
    _check("cookie-host-prefix", "Invalid __Host- cookie attributes", "Cookies", "low", "CWE-614", "Checks secure origin, Secure, Path=/, and absence of Domain for __Host- cookies.", "Supporting browsers reject invalid prefixed cookies. Values are never retained.", COOKIE),
    _check("cookie-secure-prefix", "Invalid __Secure- cookie attributes", "Cookies", "low", "CWE-614", "Checks secure origin and Secure on __Secure- cookies.", "Supporting browsers reject invalid prefixed cookies; no cookie is replayed.", COOKIE),
    _check("cors-null-origin", "Credentialed null-origin CORS", "Cross-origin", "low", "CWE-942", "Records allowed origin null with Allow-Credentials: true.", "No Origin header, cookie, credential, or sandbox document is sent; sensitive access is unproven.", MDN + "Web/HTTP/Reference/Headers/Access-Control-Allow-Origin"),
    _check("public-cache-cookie", "Shared-cache directives with cookies", "Caching", "info", "CWE-525", "Detects explicit public or positive s-maxage on responses setting cookies without private/no-store.", "Cookie purpose and cache behavior are unknown; Set-Cookie alone does not prohibit shared caching.", MDN + "Web/HTTP/Reference/Headers/Cache-Control"),
    _check("mixed-content-active", "HTTP active resource references", "HTML resources", "low", "CWE-319", "Counts HTTP script, stylesheet, frame, or object references in HTTPS HTML.", "Modern browsers may block these references. CSP upgrade-insecure-requests suppresses this rule. No resource is fetched.", MIXED, body=True),
    _check("mixed-content-passive", "HTTP media references", "HTML resources", "info", "CWE-319", "Counts HTTP image, audio, and video references in HTTPS HTML.", "Browsers usually upgrade or block mixed media. CSS and responsive srcset are outside this parser.", MIXED, body=True),
    _check("password-over-http", "Password field on HTTP page", "Forms", "medium", "CWE-319", "Counts enabled password inputs served over HTTP.", "No credentials are collected or submitted; field purpose and browser behavior require review.", OWASP + "Transport_Layer_Security_Cheat_Sheet.html", body=True),
    _check("password-form-get", "Password form uses GET", "Forms", "medium", "CWE-598", "Detects named password controls in forms using GET, including default methods and submit overrides.", "Static markup only; script-based submission and disabled fieldset inheritance are not simulated.", FORM, body=True),
    _check("password-form-http", "Password form submits to HTTP", "Forms", "medium", "CWE-319", "Detects password forms with HTTP submission destinations.", "No submission occurs; CSP, HSTS, browser upgrades, and runtime handlers may prevent transmission.", FORM, body=True),
    _check("form-action-http", "HTTPS form targets HTTP", "Forms", "low", "CWE-319", "Counts non-password forms with HTTP submission destinations from HTTPS pages.", "Form data sensitivity and actual runtime submission are unknown.", FORM, body=True),
    _check("password-form-external", "Password form crosses origins", "Forms", "info", "CWE-200", "Counts password forms with HTTP(S) submission origins different from the page.", "Legitimate identity providers may use this design; no credential leakage is asserted.", FORM, body=True),
    _check("script-integrity", "External script lacks integrity metadata", "HTML resources", "info", "CWE-353", "Counts cross-origin scripts without a nonempty integrity attribute.", "Integrity presence is not validated; CSP and controlled third-party hosting may mitigate risk.", MDN + "Web/Security/Defenses/Subresource_Integrity", body=True),
    _check("stylesheet-integrity", "External stylesheet lacks integrity metadata", "HTML resources", "info", "CWE-353", "Counts cross-origin stylesheets without integrity metadata.", "Stylesheet content is never fetched and supply-chain compromise is not established.", MDN + "Web/Security/Defenses/Subresource_Integrity", body=True),
    _check("external-base", "External document base URL", "HTML resources", "info", "CWE-200", "Records when the first base href changes the HTTP(S) document origin.", "External asset origins may be intentional; no URL or link is followed.", MDN + "Web/HTML/Reference/Elements/base", body=True),
    _check("directory-listing", "Directory listing signature", "Exposure", "low", "CWE-548", "Matches an Index of heading and parent-directory text in rendered text candidates.", "Templates or documentation can mimic listings; no listed path is retained or requested.", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration", body=True),
    _check("debug-traceback", "Debug traceback signature", "Exposure", "low", "CWE-209", "Matches characteristic Python, Werkzeug, Django, or PHP diagnostic text patterns.", "Documentation may contain examples. No stack frames, filenames, or paths are retained.", OWASP + "Error_Handling_Cheat_Sheet.html", body=True),
    _check("private-key-marker", "Private-key block marker", "Exposure", "medium", "CWE-321", "Counts matching private-key begin/end armor markers in the inspected HTML prefix.", "Key material is never retained or parsed; examples and test keys can match and validity is unverified.", OWASP + "Secrets_Management_Cheat_Sheet.html", body=True),
]


def get_checks() -> list[dict]:
    # Import lazily: offline HTTP parsing reuses scanner.Snapshot and would
    # otherwise create an import cycle. No content or network work happens here.
    from .offline import OPENAPI_CHECKS
    return deepcopy(CHECK_DEFINITIONS + OPENAPI_CHECKS)
