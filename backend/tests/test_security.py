from datetime import datetime, timedelta, timezone
import socket
import time

import pytest

from scopeforge.security import (
    ScopeError, normalize_path, parse_target, public_address,
    resolve_public_addresses, validate_program,
)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com/", "https://example.com:8443/",
    "https://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data",
    "http://127.1/", "http://2130706433/", "http://0x7f000001/", "http://localhost/",
    "https://user:password@example.com/", "https://example.com@evil.com/",
    "https://example.com./", "https://*.example.com/", "https://exa_mple.com/",
    "https://example.com:/", "https://example.com:443:443/",
    "https://example.com/a?token=secret", "https://example.com/a?", "https://example.com/a#",
    "https://example.com/a\\b", "https://example.com/a\nb", "https://example.com/a\x00b",
    " https://example.com/", "https://example.com/a\x7fb", "https://exämple.com/",
    "https://example.com/%2e%2e/admin", "https://example.com/%2Fadmin", "https://example.com/%252e%252e/admin",
    "https://example.com/a/../admin", "https://example.com/a/./admin", "https://example.com//admin",
    "https://example.com/a/..;/admin", "https://example.com/%61dmin", "https://example.com/ａｄｍｉｎ",
])
def test_rejects_ambiguous_or_unsupported_targets(url):
    with pytest.raises(ScopeError):
        parse_target(url)


def test_origin_normalization_and_exact_matching():
    target = parse_target("https://EXAMPLE.COM:443/reports/a-b_1.html")
    assert target.origin == "https://example.com"
    assert target.url == "https://example.com/reports/a-b_1.html"
    assert parse_target("https://example.com/", origin_only=True).origin == "https://example.com"
    with pytest.raises(ScopeError):
        parse_target("https://example.com/path", origin_only=True)


def program(**changes):
    return {"authorized": True, "is_demo": False, "scope_origins": ["https://example.com"],
            "excluded_paths": ["/admin"], "authorization_expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(), **changes}


@pytest.mark.parametrize("target", ["https://sub.example.com/", "https://example.com.evil.com/", "http://example.com/", "https://example.com/admin", "https://example.com/administrator"])
def test_no_scope_inference_or_exclusion_escape(target):
    with pytest.raises(ScopeError):
        validate_program(program(), target, "passive")


def test_authorization_modes_and_expiry():
    assert validate_program(program(), "https://example.com/public", "passive").path == "/public"
    for changes, mode in [({"authorized": False}, "passive"), ({"authorization_expires_at": "2020-01-01T00:00:00Z"}, "passive"), ({"is_demo": True}, "passive"), ({}, "demo")]:
        with pytest.raises(ScopeError):
            validate_program(program(**changes), "https://example.com/", mode)
    with pytest.raises(ScopeError):
        normalize_path("admin")


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "0.0.0.0", "100.100.100.200", "100.64.0.1", "192.0.0.1", "192.0.2.1",
    "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
    "::1", "::", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1",
    "::ffff:127.0.0.1", "::ffff:8.8.8.8", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
])
def test_private_metadata_reserved_and_tunnel_addresses_blocked(address):
    assert not public_address(address)


def test_dns_all_answers_must_be_public_and_results_are_pinned():
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    seen = []
    def resolver(*args):
        seen.append(args)
        return answers
    assert resolve_public_addresses("example.com", 443, resolver=resolver) == ["93.184.216.34"]
    assert seen == [("example.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM)]
    answers.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)))
    with pytest.raises(ScopeError, match="every resolved address"):
        resolve_public_addresses("example.com", 443, resolver=resolver)


def test_dns_timeout_does_not_use_late_results():
    def slow(*args):
        time.sleep(0.025)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    with pytest.raises(ScopeError, match="timeout"):
        resolve_public_addresses("example.com", 443, resolver=slow, timeout=0.001)


def test_dns_failure_is_sanitized():
    def error(*args):
        raise socket.gaierror("resolver internal secret")
    with pytest.raises(ScopeError, match="DNS lookup failed") as captured:
        resolve_public_addresses("example.com", 443, resolver=error)
    assert "secret" not in str(captured.value)
