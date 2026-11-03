"""Gemensamma typer: felkoder, resultat, konfiguration. Se spec/ssrf_fetch/README.md."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

# En resolver tar (värdnamn, port) och returnerar adresser som text. Fel ska ge exception;
# biblioteket tolkar varje exception, tom lista eller icke-adress som nekat.
Resolver = Callable[[str, int], Sequence[str]]


class ErrorCode(StrEnum):
    """Stabil orsakskod. Värdena är en del av kontraktet och delas med TS-porten."""

    INVALID_URL = "invalid_url"
    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    CREDENTIALS_IN_URL = "credentials_in_url"
    NO_HOST = "no_host"
    INVALID_HOST = "invalid_host"
    PORT_NOT_ALLOWED = "port_not_allowed"
    BLOCKED_HOST = "blocked_host"
    BLOCKED_IP = "blocked_ip"
    DNS_ERROR = "dns_error"
    DNS_EMPTY = "dns_empty"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    REDIRECT_DOWNGRADE = "redirect_downgrade"
    BAD_REDIRECT = "bad_redirect"
    HTTP_STATUS = "http_status"
    TIMEOUT = "timeout"
    CONNECT_FAILED = "connect_failed"
    NETWORK_ERROR = "network_error"
    TOO_LARGE = "too_large"
    CONTENT_TYPE_NOT_ALLOWED = "content_type_not_allowed"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    ROBOTS_DISALLOWED = "robots_disallowed"
    ROBOTS_UNAVAILABLE = "robots_unavailable"
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class Fetched:
    """Ett hämtat dokument (status 2xx)."""

    url: str
    final_url: str
    status: int
    content_type: str
    body: bytes
    truncated: bool
    redirects: int


@dataclass(frozen=True)
class Failed:
    """Hämtningen nekades eller misslyckades. `url` är maskerad (inga användaruppgifter, query eller
    fragment; trasig URL ger en fast platshållare) och `detail` innehåller aldrig URL:en."""

    url: str
    code: ErrorCode
    detail: str
    http_status: int | None = None


@dataclass(frozen=True)
class FetchConfig:
    """Gränser och beteende. Alla värden har säkra standardvärden."""

    user_agent: str = "shared-libs-ssrf-fetch/0.1"
    accept: str = "*/*"
    max_bytes: int = 4 * 1024 * 1024
    truncate_oversize: bool = False
    max_redirects: int = 5
    total_timeout: float = 15.0
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    max_addresses: int = 4
    allowed_ports: frozenset[int] | None = None
    allowed_content_types: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if self.max_bytes < 1 or self.max_redirects < 0 or self.max_addresses < 1:
            raise ValueError("max_bytes/max_addresses måste vara >= 1 och max_redirects >= 0")
        if min(self.total_timeout, self.connect_timeout, self.read_timeout) <= 0:
            raise ValueError("timeout måste vara > 0")


@dataclass(frozen=True)
class RobotsConfig:
    """robots.txt-stöd. `agent` är produkttoken som matchas mot User-agent-rader."""

    agent: str
    ttl: float = 3600.0
    max_bytes: int = 512 * 1024
    max_entries: int = 1024
    max_rules: int = 10_000
    strict_client_errors: bool = False

    def __post_init__(self) -> None:
        name = self.agent
        if not name or any(c.isspace() or c in ":#*" for c in name):
            raise ValueError("ogiltig robots-agent")
        if self.ttl <= 0 or self.max_bytes < 1 or self.max_entries < 1 or self.max_rules < 1:
            raise ValueError("ogiltig robots-konfiguration")
