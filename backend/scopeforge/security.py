"""Conservative URL, scope, and network-boundary validation.

These checks constrain the software. The operator must still have permission
from the target owner; a saved policy URL is never treated as authorization.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
import socket
from urllib.parse import urlsplit


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    url: str
    origin: str
    hostname: str
    scheme: str
    port: int
    path: str


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,=:@/\-]*$")
_DNS_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scopeforge-dns")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_expiry(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ScopeError("Authorization expiry must be an ISO 8601 timestamp.") from None
    if result.tzinfo is None:
        raise ScopeError("Authorization expiry must include a timezone (for example Z).")
    return result.astimezone(timezone.utc)


def normalize_path(path: str) -> str:
    path = path or "/"
    if not _PATH.fullmatch(path):
        raise ScopeError("Use a literal ASCII path; encoded paths, backslashes, parameters, and control characters are unsupported.")
    if "//" in path or any(part in {".", ".."} for part in path.split("/")):
        raise ScopeError("Ambiguous paths with duplicate slashes or dot segments are not allowed.")
    return path


def parse_target(value: str, *, origin_only: bool = False) -> Target:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ScopeError("Provide a URL no longer than 2048 characters.")
    if any(ord(char) <= 32 or ord(char) >= 127 for char in value) or "\\" in value:
        raise ScopeError("URLs must be ASCII and cannot contain whitespace, control characters, or backslashes.")
    if "?" in value or "#" in value:
        raise ScopeError("Query strings and fragments are not allowed in scan URLs or origins.")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise ScopeError("The URL is malformed.") from None
    if parts.scheme not in {"http", "https"} or not hostname:
        raise ScopeError("Only absolute http:// or https:// URLs are supported.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ScopeError("Credentials are not allowed in URLs.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ScopeError("IP address targets are not supported. Use an explicitly authorized domain origin.")
    labels = hostname.split(".")
    if len(hostname) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
        raise ScopeError("Use a fully qualified ASCII domain without wildcards or a trailing dot.")
    # Numeric and alternate numeric host syntax must not be interpreted as a domain.
    if labels[-1].isdigit() or hostname.startswith("0x"):
        raise ScopeError("Numeric address syntax is not supported.")
    default_port = 443 if parts.scheme == "https" else 80
    if port not in {None, default_port} or parts.netloc.endswith(":"):
        raise ScopeError("Only default HTTP (80) and HTTPS (443) ports are supported.")
    path = normalize_path(parts.path)
    if origin_only and path != "/":
        raise ScopeError("Scope entries must be exact origins without a path.")
    origin = f"{parts.scheme}://{hostname}"
    return Target(f"{origin}{path}", origin, hostname, parts.scheme, default_port, path)


def validate_program(program: dict, target_url: str, mode: str) -> Target:
    if not program["authorized"]:
        raise ScopeError("Authorization has been revoked for this program.")
    if parse_expiry(program["authorization_expires_at"]) <= datetime.now(timezone.utc):
        raise ScopeError("Authorization has expired. Create a program with renewed permission before scanning.")
    if mode == "demo" and not program["is_demo"]:
        raise ScopeError("Demo scans can only use the built-in training program.")
    if mode == "passive" and program["is_demo"]:
        raise ScopeError("The training program is offline only and cannot make network requests.")
    target = parse_target(target_url)
    if target.origin not in program["scope_origins"]:
        raise ScopeError("Target origin is outside the explicitly authorized scope.")
    if any(target.path.startswith(prefix) for prefix in program["excluded_paths"]):
        raise ScopeError("Target path matches a program exclusion.")
    return target


def public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
        return False
    if isinstance(address, ipaddress.IPv6Address) and (
        address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None
    ):
        return False
    return True


def resolve_public_addresses(hostname: str, port: int, *, resolver=None, timeout: float = 5.0) -> list[str]:
    """Resolve once, reject the entire answer set if any result is non-public.

    A bounded shared pool limits outstanding OS resolver calls. A timed-out call
    is never used later. The HTTP transport connects to one returned numeric IP.
    """
    resolver = resolver or socket.getaddrinfo
    future = _DNS_POOL.submit(resolver, hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    try:
        records = future.result(timeout=timeout)
    except FutureTimeout:
        future.cancel()
        raise ScopeError("DNS lookup exceeded the five-second timeout.") from None
    except OSError:
        raise ScopeError("DNS lookup failed for the target domain.") from None
    addresses = []
    for family, socktype, _protocol, _name, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6} or socktype != socket.SOCK_STREAM:
            raise ScopeError("DNS returned an unsupported address type.")
        value = sockaddr[0]
        if not public_address(value):
            raise ScopeError("Network boundary blocked this target: every resolved address must be public. Private, local, reserved, and metadata addresses are forbidden.")
        if value not in addresses:
            addresses.append(value)
    if not addresses:
        raise ScopeError("DNS did not return a usable public address.")
    return addresses
