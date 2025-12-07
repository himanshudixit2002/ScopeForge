import io
import socket

import pytest

from scopeforge import scanner
from scopeforge.security import parse_target


def checks(snapshot):
    return {item["check_id"]: item for item in scanner.analyze_headers(parse_target("https://example.com/"), snapshot)}


def test_synthetic_fixture_is_honest_and_redacts_values():
    result = checks(scanner.demo_snapshot())
    assert "cookie-flags:training_session" in result
    assert all(item["severity"] in {"low", "info"} for item in result.values())
    assert all("SYNTHETIC DEMO" in item["evidence"] for item in result.values())
    serialized = str(result)
    assert "SYNTHETIC_NOT_A_SECRET" not in serialized
    assert "[REDACTED]" in serialized
    assert "browsers reject credentialed access" in result["cors-policy"]["description"]


def test_protected_html_does_not_generate_missing_header_findings():
    result = checks(scanner.Snapshot(200, [
        ("Content-Type", "text/html"), ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
        ("Set-Cookie", "session=KEEP_SECRET; Secure; HttpOnly; SameSite=Lax"),
    ]))
    assert result == {}


@pytest.mark.parametrize("policies", [
    ["default-src 'self'", "frame-ancestors 'none'"],
    ["default-src 'self', frame-ancestors 'none'"],
])
def test_all_enforcing_csp_policies_are_considered(policies):
    result = checks(scanner.Snapshot(200, [("Content-Type", "text/html")] + [("Content-Security-Policy", value) for value in policies]))
    assert "framing-policy" not in result


def test_csp_report_url_substring_is_not_a_framing_directive():
    result = checks(scanner.Snapshot(200, [("Content-Type", "text/html"), ("Content-Security-Policy", "report-uri https://reports.example/frame-ancestors")]))
    assert "framing-policy" in result


def test_non_html_skips_html_specific_checks_and_does_not_store_cookie_values():
    result = checks(scanner.Snapshot(302, [
        ("Content-Type", "application/json"), ("Location", "http://169.254.169.254/?token=SECRET"),
        ("Set-Cookie", "session=SECRET_COOKIE; SameSite=Lax"), ("Server", "SECRET_BANNER"),
    ]))
    assert "content-security-policy" not in result
    assert "framing-policy" not in result
    assert "referrer-policy" not in result
    assert "redirect-observation" in result
    assert "SECRET" not in str(result)
    assert "169.254.169.254" not in str(result)


class FakeSocket:
    def __init__(self):
        self.connected = None
        self.timeouts = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.connected = address

    def close(self):
        self.closed = True

    def sendall(self, data):
        self.sent = data


def test_pinned_tls_connection_retains_sni_and_uses_default_verification(monkeypatch):
    raw = FakeSocket()
    tls_calls = []
    context_calls = []
    class Context:
        def wrap_socket(self, sock, *, server_hostname):
            tls_calls.append((sock, server_hostname))
            return sock
    monkeypatch.setattr(scanner.socket, "socket", lambda family, kind: raw)
    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda: context_calls.append("verified") or Context())
    connection = scanner.PinnedHTTPConnection(parse_target("https://example.com/public"), "93.184.216.34")
    connection.connect()
    assert raw.connected == ("93.184.216.34", 443)
    assert tls_calls == [(raw, "example.com")]
    assert context_calls == ["verified"]
    assert connection.host == "example.com"
    connection.close()
    assert raw.closed


def test_sendall_budget_is_remaining_deadline(monkeypatch):
    raw = FakeSocket()
    monkeypatch.setattr(scanner.time, "monotonic", lambda: 9.0)
    wrapped = scanner._ResponseSocket(raw, deadline=10.0)
    wrapped.sendall(b"GET / HTTP/1.1\r\n")
    assert raw.timeouts[-1] == 1.0
    monkeypatch.setattr(scanner.time, "monotonic", lambda: 10.1)
    with pytest.raises(TimeoutError):
        wrapped.sendall(b"anything")


def test_entire_response_reader_has_byte_and_time_caps(monkeypatch):
    class Incoming(FakeSocket):
        def recv_into(self, target, size):
            target[:size] = b"x" * size
            return size
    monkeypatch.setattr(scanner.time, "monotonic", lambda: 1.0)
    reader = scanner._BoundedReader(Incoming(), deadline=2.0)
    target = bytearray(scanner.MAX_RESPONSE_BYTES + 1)
    assert reader.readinto(target) == scanner.MAX_RESPONSE_BYTES
    with pytest.raises(scanner.ScanNetworkError, match="256 KiB"):
        reader.readinto(target)
    reader = scanner._BoundedReader(Incoming(), deadline=0.0)
    with pytest.raises(TimeoutError):
        reader.readinto(target)


def test_fetch_is_one_get_without_proxy_redirect_retry_or_body_reads(monkeypatch):
    requests = []
    gate = []
    class Response:
        status = 302
        def getheaders(self):
            return [("Location", "http://127.0.0.1/admin")]
        def close(self):
            pass
        def read(self, *args):
            raise AssertionError("Body should not be deliberately read")
    class Connection:
        def __init__(self, target, address, *, before_send=None):
            assert address == "93.184.216.34"
        def request(self, method, path, headers):
            requests.append((method, path, headers))
        def getresponse(self):
            return Response()
        def close(self):
            pass
    monkeypatch.setattr(scanner, "resolve_public_addresses", lambda *args: ["93.184.216.34", "93.184.216.35"])
    monkeypatch.setattr(scanner, "PinnedHTTPConnection", Connection)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
    result = scanner.fetch_headers(parse_target("https://example.com/safe"), before_request=lambda: gate.append(True))
    assert result.status == 302
    assert gate == [True]
    assert len(requests) == 1
    method, path, headers = requests[0]
    assert (method, path, headers["Host"]) == ("GET", "/safe", "example.com")
    assert "Cookie" not in headers
    assert "Authorization" not in headers


def test_write_boundary_callback_runs_once_after_connection_and_before_bytes():
    raw = FakeSocket()
    calls = []
    def boundary():
        assert not hasattr(raw, "sent")
        calls.append("authorized")
    wrapped = scanner._ResponseSocket(raw, deadline=scanner.time.monotonic() + 10, before_send=boundary)
    wrapped.sendall(b"first")
    wrapped.sendall(b"second")
    assert calls == ["authorized"]


def test_write_boundary_cancellation_prevents_any_bytes():
    raw = FakeSocket()
    def revoked():
        raise ValueError("revoked during handshake")
    wrapped = scanner._ResponseSocket(raw, deadline=scanner.time.monotonic() + 10, before_send=revoked)
    with pytest.raises(ValueError, match="revoked"):
        wrapped.sendall(b"GET / HTTP/1.1\r\n")
    assert not hasattr(raw, "sent")
