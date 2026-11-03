"""SSRF-säker HTTP-hämtning. Kontrakt och testvektorer: spec/ssrf_fetch/."""

from ssrf_fetch.address import is_blocked_ip
from ssrf_fetch.fetcher import SafeFetcher
from ssrf_fetch.models import (
    ErrorCode,
    Failed,
    FetchConfig,
    Fetched,
    Resolver,
    RobotsConfig,
)
from ssrf_fetch.ratelimit import HostLimiter
from ssrf_fetch.robots import RobotsCache, RobotsRules, parse_robots
from ssrf_fetch.url import Target, default_resolver, validate_url

__all__ = [
    "ErrorCode",
    "Failed",
    "FetchConfig",
    "Fetched",
    "HostLimiter",
    "Resolver",
    "RobotsCache",
    "RobotsConfig",
    "RobotsRules",
    "SafeFetcher",
    "Target",
    "default_resolver",
    "is_blocked_ip",
    "parse_robots",
    "validate_url",
]
