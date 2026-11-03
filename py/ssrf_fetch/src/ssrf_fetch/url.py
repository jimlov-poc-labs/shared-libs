"""URL-validering och namnupplösning. Allt som är oväntat ger Failed, aldrig tillåtet."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from ssrf_fetch.address import (
    is_blocked_ip,
    is_canonical_ipv4,
    is_numeric_label,
    parse_legacy_ipv4,
)
from ssrf_fetch.models import ErrorCode, Failed, Resolver

MAX_URL_LENGTH = 8192
_HOST_CHARS = re.compile(r"[a-z0-9_.-]+")


@dataclass(frozen=True)
class Target:
    """En validerad URL med de adresser som får kontaktas (DNS-pinning)."""

    scheme: str
    host: str
    port: int
    path_query: str
    addresses: tuple[str, ...]
    is_ip_literal: bool

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host_header}"


def default_resolver(host: str, port: int) -> list[str]:
    """getaddrinfo, TCP, i systemets ordning (RFC 6724). Blockerande; ingen egen timeout."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _fail(url: str, code: ErrorCode, detail: str) -> Failed:
    return Failed(url=url, code=code, detail=detail)


def _classify_host(url: str, netloc: str, hostname: str) -> tuple[str, bool] | Failed:
    """(normaliserat värdnamn eller IP, är_ip_literal) eller Failed."""
    if "[" in netloc or ":" in hostname:
        # IPv6-literal; måste vara hakparentesad och en riktig IPv6-adress.
        if not (netloc.rpartition("@")[2].startswith("[") and "]" in netloc):
            return _fail(url, ErrorCode.INVALID_HOST, "ogiltig IPv6-literal")
        try:
            addr6 = ipaddress.IPv6Address(hostname)
        except ValueError:
            return _fail(url, ErrorCode.INVALID_HOST, "ogiltig IPv6-literal")
        if is_blocked_ip(str(addr6)):
            return _fail(url, ErrorCode.BLOCKED_IP, "adressen är inte publikt routbar")
        return str(addr6), True

    name = hostname[:-1] if hostname.endswith(".") else hostname
    if not name:
        return _fail(url, ErrorCode.NO_HOST, "tomt värdnamn")
    try:
        name = name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return _fail(url, ErrorCode.INVALID_HOST, "värdnamnet är inte giltig IDNA")
    if len(name) > 253 or not _HOST_CHARS.fullmatch(name):
        return _fail(url, ErrorCode.INVALID_HOST, "ogiltiga tecken i värdnamnet")

    if is_numeric_label(name.rsplit(".", 1)[-1]):
        # Numeriskt slut = IPv4-form (inet_aton-kompatibla klienter tolkar den så).
        legacy = parse_legacy_ipv4(name)
        if legacy is None:
            return _fail(url, ErrorCode.INVALID_HOST, "ogiltig numerisk värd")
        if is_blocked_ip(legacy):
            return _fail(url, ErrorCode.BLOCKED_IP, "adressen är inte publikt routbar")
        if not is_canonical_ipv4(name):
            return _fail(url, ErrorCode.INVALID_HOST, "icke-kanonisk IPv4-form nekas")
        return name, True

    labels = name.split(".")
    if name == "localhost" or labels[-1] == "localhost":
        return _fail(url, ErrorCode.BLOCKED_HOST, "localhost nekas")
    return name, False


def check_url_syntax(url: str, allowed_ports: frozenset[int] | None = None) -> Target | Failed:
    """Allt som kan avgöras utan DNS. Returnerar Target utan adresser, eller Failed."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        return _fail(str(url)[:200], ErrorCode.INVALID_URL, "tom, för lång eller ingen sträng")
    if "\\" in url or any(c <= " " or c == "\x7f" or c.isspace() for c in url):
        return _fail(url, ErrorCode.INVALID_URL, "blanksteg, styrtecken eller backslash")
    try:
        parts = urlsplit(url)
        port = parts.port
        hostname = parts.hostname
    except ValueError:
        return _fail(url, ErrorCode.INVALID_URL, "kunde inte tolkas")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return _fail(url, ErrorCode.SCHEME_NOT_ALLOWED, "bara http och https")
    if "@" in parts.netloc:
        return _fail(url, ErrorCode.CREDENTIALS_IN_URL, "användaruppgifter i URL")
    if not hostname:
        return _fail(url, ErrorCode.NO_HOST, "värdnamn saknas")
    if "%" in parts.netloc:
        return _fail(url, ErrorCode.INVALID_HOST, "procentkodad värd")
    if port == 0:
        return _fail(url, ErrorCode.INVALID_URL, "port 0")
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if allowed_ports is not None and effective_port not in allowed_ports:
        return _fail(url, ErrorCode.PORT_NOT_ALLOWED, f"porten {effective_port} är inte tillåten")
    host = _classify_host(url, parts.netloc, hostname)
    if isinstance(host, Failed):
        return host
    path_query = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if not path_query.startswith("/"):
        return _fail(url, ErrorCode.INVALID_URL, "ogiltig sökväg")
    return Target(scheme, host[0], effective_port, path_query, (), host[1])


def validate_url(
    url: str,
    resolver: Resolver = default_resolver,
    allowed_ports: frozenset[int] | None = None,
) -> Target | Failed:
    """Validera URL och lös upp namnet *en* gång. Varje adress måste vara publik.

    Anroparen ska ansluta till `Target.addresses` och aldrig lösa upp namnet igen.
    """
    target = check_url_syntax(url, allowed_ports)
    if isinstance(target, Failed):
        return target
    if target.is_ip_literal:
        return Target(
            target.scheme, target.host, target.port, target.path_query, (target.host,), True
        )
    try:
        resolved = list(resolver(target.host, target.port))
    except Exception as error:  # fail closed på allt
        return _fail(url, ErrorCode.DNS_ERROR, f"{type(error).__name__} vid namnupplösning")
    addresses = tuple(dict.fromkeys(str(a) for a in resolved))
    if not addresses:
        return _fail(url, ErrorCode.DNS_EMPTY, "namnet gav inga adresser")
    if any(is_blocked_ip(a) for a in addresses):
        # Neka om *någon* adress är intern; vi filtrerar inte bort de interna.
        return _fail(url, ErrorCode.BLOCKED_IP, "namnet pekar på en icke-publik adress")
    return Target(target.scheme, target.host, target.port, target.path_query, addresses, False)
