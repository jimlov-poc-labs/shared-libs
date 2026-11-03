"""SafeFetcher: SSRF-säker hämtning med DNS-pinning, validerade omdirigeringar och tak.

Varje URL (även varje omdirigeringshopp och robots.txt) går genom samma väg:
validate_url -> (robots) -> (hastighetsgräns) -> anslutning till validerad IP.
Transporten används direkt (ingen httpx.Client): inga cookies, ingen proxy från miljön,
ingen automatisk omdirigering, ingen avkodning av innehåll.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Self
from urllib.parse import urljoin, urlsplit

import httpx

from ssrf_fetch.deadline import DeadlineBackend, build_transport
from ssrf_fetch.models import (
    ErrorCode,
    Failed,
    FetchConfig,
    Fetched,
    Resolver,
    RobotsConfig,
)
from ssrf_fetch.ratelimit import HostLimiter
from ssrf_fetch.robots import ALLOW_ALL, RobotsCache, RobotsRules, parse_robots
from ssrf_fetch.url import Target, default_resolver, redact_url, validate_url

_ASCII_DIGITS = re.compile(r"[0-9]+")
_MAX_LENGTH_DIGITS = 18  # längre tal är över varje tak; int() på tusentals siffror är dyrt
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class _Redirect:
    location: str


@dataclass(frozen=True)
class _ConnectFailure:
    detail: str


class SafeFetcher:
    """Hämtar otrodda URL:er. All konfiguration och allt tillstånd ägs av instansen."""

    def __init__(
        self,
        config: FetchConfig | None = None,
        *,
        resolver: Resolver = default_resolver,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        robots: RobotsConfig | None = None,
        robots_cache: RobotsCache | None = None,
        limiter: HostLimiter | None = None,
    ) -> None:
        self._config = config or FetchConfig()
        self._resolver = resolver
        self._owns_transport = transport is None
        self._clock = clock
        self._backend = DeadlineBackend(clock)
        # Inga keep-alive-anslutningar: en TLS-session verifierad för ett namn får
        # inte återanvändas för ett annat namn på samma IP.
        self._transport: httpx.BaseTransport = transport or build_transport(self._backend)
        self._sleep = sleep
        self._robots = robots
        self._robots_cache: RobotsCache | None = None
        if robots is not None:
            # `is not None`, inte `or`: en tom RobotsCache är falsy (har __len__).
            self._robots_cache = (
                robots_cache
                if robots_cache is not None
                else RobotsCache(robots.ttl, robots.max_entries, clock)
            )
        self._limiter = limiter

    def close(self) -> None:
        if self._owns_transport:
            self._transport.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def fetch(self, url: str) -> Fetched | Failed:
        """Hämta `url`. Kastar aldrig för hotfulla eller onåbara URL:er; ger Failed med kod."""
        cfg = self._config
        try:
            return self._run(
                url,
                self._clock() + cfg.total_timeout,
                max_bytes=cfg.max_bytes,
                truncate=cfg.truncate_oversize,
                content_types=cfg.allowed_content_types,
                use_robots=self._robots is not None,
            )
        except Exception as error:  # fail closed: oväntat fel är nekat, inte "klart"
            return Failed(redact_url(url), ErrorCode.INTERNAL_ERROR, type(error).__name__)

    # --- kärnan -----------------------------------------------------------------

    def _run(
        self,
        url: str,
        deadline: float,
        *,
        max_bytes: int,
        truncate: bool,
        content_types: frozenset[str] | None,
        use_robots: bool,
    ) -> Fetched | Failed:
        cfg = self._config
        current = url
        shown = redact_url(url)  # allt som lämnar biblioteket visar bara den maskerade URL:en
        for hop in range(cfg.max_redirects + 1):
            target = validate_url(
                current,
                self._resolver,
                cfg.allowed_ports,
                dns_timeout=deadline - self._clock(),
            )
            if isinstance(target, Failed):
                return _shown(target, shown)
            denial = self._robots_check(target, deadline, use_robots)
            if denial is not None:
                return _shown(denial, shown)
            outcome = self._hop(target, deadline, max_bytes, truncate, content_types)
            if not isinstance(outcome, _Redirect):
                return _finish(outcome, shown, url, current, hop)
            if hop >= cfg.max_redirects:
                return Failed(shown, ErrorCode.TOO_MANY_REDIRECTS, f"fler än {cfg.max_redirects}")
            following = _follow(current, outcome.location, target.scheme, shown)
            if isinstance(following, Failed):
                return following
            current = following
        return Failed(shown, ErrorCode.TOO_MANY_REDIRECTS, f"fler än {cfg.max_redirects}")

    def _robots_check(self, target: Target, deadline: float, use_robots: bool) -> Failed | None:
        if not use_robots:
            return None
        return self._robots_denial(target, deadline)

    def _hop(
        self,
        target: Target,
        deadline: float,
        max_bytes: int,
        truncate: bool,
        content_types: frozenset[str] | None,
    ) -> Fetched | Failed | _Redirect:
        remaining = deadline - self._clock()
        if remaining <= 0:
            return Failed("", ErrorCode.TIMEOUT, "totaltiden är slut")
        if self._limiter is not None:
            wait = self._limiter.reserve(target.host, remaining)
            if wait is None:
                return Failed("", ErrorCode.RATE_LIMITED, "väntetiden överstiger tillgänglig tid")
            if wait > 0:
                self._sleep(wait)
        last = "inga adresser"
        for ip in target.addresses[: self._config.max_addresses]:
            result = self._attempt(target, ip, deadline, max_bytes, truncate, content_types)
            if not isinstance(result, _ConnectFailure):
                return result
            last = result.detail
        return Failed("", ErrorCode.CONNECT_FAILED, last)

    def _attempt(
        self,
        target: Target,
        ip: str,
        deadline: float,
        max_bytes: int,
        truncate: bool,
        content_types: frozenset[str] | None,
    ) -> Fetched | Failed | _Redirect | _ConnectFailure:
        cfg = self._config
        remaining = deadline - self._clock()
        if remaining <= 0:
            return Failed("", ErrorCode.TIMEOUT, "totaltiden är slut")
        netloc = f"[{ip}]" if ":" in ip else ip
        try:
            # URL:en byggs av validerade delar, aldrig av originalsträngen: ingen
            # parserskillnad mellan vår validering och klienten kan peka om anslutningen.
            request = httpx.Request(
                "GET",
                f"{target.scheme}://{netloc}:{target.port}{target.path_query}",
                headers={
                    "Host": target.host_header,
                    "User-Agent": cfg.user_agent,
                    "Accept": cfg.accept,
                    "Accept-Encoding": "identity",
                },
                extensions={
                    "timeout": {
                        "connect": min(cfg.connect_timeout, remaining),
                        "read": min(cfg.read_timeout, remaining),
                        "write": min(cfg.read_timeout, remaining),
                        "pool": min(cfg.read_timeout, remaining),
                    },
                    # Certifikatet kontrolleras mot namnet, inte mot IP:n vi ansluter till.
                    **(
                        {"sni_hostname": target.host}
                        if target.scheme == "https" and not target.is_ip_literal
                        else {}
                    ),
                },
            )
        except httpx.InvalidURL:
            return Failed("", ErrorCode.INVALID_URL, "kunde inte byggas")

        response: httpx.Response | None = None
        try:
            with self._backend.scope(deadline):  # absolut deadline även för svarshuvudet
                response = self._transport.handle_request(request)
                return self._read(response, deadline, max_bytes, truncate, content_types)
        except (httpx.ConnectTimeout, httpx.ConnectError) as error:
            return _ConnectFailure(type(error).__name__)
        except httpx.TimeoutException as error:
            return Failed("", ErrorCode.TIMEOUT, type(error).__name__)
        except httpx.HTTPError as error:
            return Failed("", ErrorCode.NETWORK_ERROR, type(error).__name__)
        finally:
            if response is not None:
                response.close()

    def _read(
        self,
        response: httpx.Response,
        deadline: float,
        max_bytes: int,
        truncate: bool,
        content_types: frozenset[str] | None,
    ) -> Fetched | Failed | _Redirect:
        status = response.status_code
        if status in _REDIRECT_STATUSES:
            location = response.headers.get("location")
            if not location:
                return Failed("", ErrorCode.BAD_REDIRECT, f"{status} utan Location", status)
            return _Redirect(location)
        if not 200 <= status < 300:
            return Failed("", ErrorCode.HTTP_STATUS, f"HTTP {status}", status)
        rejection = _header_rejection(response.headers, status, content_types, max_bytes, truncate)
        if rejection is not None:
            return rejection
        content_type = response.headers.get("content-type", "")
        return self._read_body(response, status, content_type, deadline, max_bytes, truncate)

    def _read_body(
        self,
        response: httpx.Response,
        status: int,
        content_type: str,
        deadline: float,
        max_bytes: int,
        truncate: bool,
    ) -> Fetched | Failed:
        body = bytearray()
        truncated = False
        stream = response.stream
        if not isinstance(stream, httpx.SyncByteStream):
            return Failed("", ErrorCode.INTERNAL_ERROR, "transporten gav ingen synkron ström")
        for chunk in stream:  # strömmande; läser aldrig mer än taket + en bit
            if self._clock() >= deadline:
                return Failed("", ErrorCode.TIMEOUT, "totaltiden slut under läsning", status)
            body.extend(chunk)
            if len(body) > max_bytes:
                if not truncate:
                    return Failed("", ErrorCode.TOO_LARGE, "svaret över taket", status)
                del body[max_bytes:]
                truncated = True
                break
        return Fetched("", "", status, content_type, bytes(body), truncated, 0)

    # --- robots -------------------------------------------------------------------

    def _robots_denial(self, target: Target, deadline: float) -> Failed | None:
        robots = self._robots
        cache = self._robots_cache
        if robots is None or cache is None:
            return Failed("", ErrorCode.INTERNAL_ERROR, "robots saknar konfiguration")
        cached = cache.get(target.origin)
        rules = cached if cached is not None else self._load_robots(target, robots, cache, deadline)
        if isinstance(rules, Failed):
            return rules
        if rules.allows(target.path_query):
            return None
        return Failed("", ErrorCode.ROBOTS_DISALLOWED, "robots.txt förbjuder sökvägen")

    def _load_robots(
        self, target: Target, robots: RobotsConfig, cache: RobotsCache, deadline: float
    ) -> RobotsRules | Failed:
        result = self._run(
            f"{target.origin}/robots.txt",
            deadline,
            max_bytes=robots.max_bytes,
            truncate=True,
            content_types=None,
            use_robots=False,
        )
        if isinstance(result, Fetched):
            rules = parse_robots(
                result.body.decode("utf-8", "replace"), robots.agent, robots.max_rules
            )
            cache.put(target.origin, rules)
            return rules
        status = result.http_status
        if result.code is ErrorCode.HTTP_STATUS and status is not None and 400 <= status < 500:
            lenient = status != 429  # 429 = "försök senare", inte "inga regler"
            if status in (404, 410) or (lenient and not robots.strict_client_errors):
                cache.put(target.origin, ALLOW_ALL)
                return ALLOW_ALL
        # 5xx, 429, nätverksfel, timeout, spärrad omdirigering: ingen tillåtelse (RFC 9309).
        # Cachas inte; ett tillfälligt fel ska inte låsa ute en sajt i en timme.
        return Failed(
            "", ErrorCode.ROBOTS_UNAVAILABLE, f"robots.txt kunde inte läsas ({result.code})"
        )


def _header_rejection(
    headers: httpx.Headers,
    status: int,
    content_types: frozenset[str] | None,
    max_bytes: int,
    truncate: bool,
) -> Failed | None:
    """Nekar på svarshuvudet (kodning, innehållstyp, längd) innan någon kropp läses."""
    encoding = headers.get("content-encoding", "").strip().lower()
    if encoding not in ("", "identity"):
        return Failed("", ErrorCode.UNSUPPORTED_ENCODING, "komprimerat svar nekas", status)
    content_type = headers.get("content-type", "")
    if content_types is not None and not _type_allowed(content_type, content_types):
        return Failed("", ErrorCode.CONTENT_TYPE_NOT_ALLOWED, "innehållstypen nekas", status)
    return _length_rejection(headers.get("content-length", "").strip(), status, max_bytes, truncate)


def _length_rejection(declared: str, status: int, max_bytes: int, truncate: bool) -> Failed | None:
    if not declared:
        return None
    # Strikt ASCII: str.isdigit() godtar t.ex. "²" och int() kastar då.
    if not _ASCII_DIGITS.fullmatch(declared):
        return Failed("", ErrorCode.NETWORK_ERROR, "ogiltig Content-Length", status)
    too_big = len(declared) > _MAX_LENGTH_DIGITS or int(declared) > max_bytes
    if too_big and not truncate:
        return Failed("", ErrorCode.TOO_LARGE, "Content-Length över taket", status)
    return None


def _shown(failed: Failed, shown: str) -> Failed:
    """Samma fel men med den maskerade URL:en."""
    return Failed(shown, failed.code, failed.detail, failed.http_status)


def _finish(
    outcome: Fetched | Failed, shown: str, url: str, current: str, hop: int
) -> Fetched | Failed:
    """Slutresultat för ett hopp: Failed får den maskerade URL:en, Fetched får hoppräkningen."""
    if isinstance(outcome, Failed):
        return _shown(outcome, shown)
    return Fetched(
        url,
        current,
        outcome.status,
        outcome.content_type,
        outcome.body,
        outcome.truncated,
        hop,
    )


def _follow(current: str, location: str, scheme: str, shown: str) -> str | Failed:
    """Nästa URL efter en omdirigering, eller Failed (oläsbar Location, https till http)."""
    try:
        following = urljoin(current, location)
        next_scheme = urlsplit(following).scheme.lower()
    except ValueError:
        return Failed(shown, ErrorCode.BAD_REDIRECT, "Location kunde inte tolkas")
    if scheme == "https" and next_scheme == "http":
        return Failed(shown, ErrorCode.REDIRECT_DOWNGRADE, "https till http nekas")
    return following


def _type_allowed(header: str, allowed: frozenset[str]) -> bool:
    media = header.split(";", 1)[0].strip().lower()
    if not media:
        return False  # saknad typ + allowlist = nekat
    return media in allowed or f"{media.split('/', 1)[0]}/*" in allowed
