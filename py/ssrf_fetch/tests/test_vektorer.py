"""Kör de delade testvektorerna i spec/ssrf_fetch/vektorer.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fakes import FakeClock, FakeDns, FakeTransport
from ssrf_fetch import (
    Failed,
    FetchConfig,
    Fetched,
    HostLimiter,
    RobotsConfig,
    SafeFetcher,
    Target,
    is_blocked_ip,
    parse_robots,
    validate_url,
)

_FIL = Path(__file__).resolve().parents[3] / "spec" / "ssrf_fetch" / "vektorer.json"
_V: dict[str, Any] = json.loads(_FIL.read_text(encoding="utf-8"))


def _ids(key: str) -> list[str]:
    return [f["namn"] for f in _V[key]]


def test_vektorfilen_är_inte_tom() -> None:
    # Fail closed: en tom eller saknad avdelning får inte ge ett grönt test.
    assert len(_V["ip_spar"]) >= 60
    assert len(_V["url_validering"]) >= 100
    assert len(_V["robots_tolkning"]) >= 30
    assert len(_V["hamtning"]) >= 70
    assert len(_V["hastighetsgrans"]) >= 5


@pytest.mark.parametrize("fall", _V["ip_spar"], ids=_ids("ip_spar"))
def test_ip_spar(fall: dict[str, Any]) -> None:
    assert is_blocked_ip(fall["ip"]) is fall["blockerad"]


@pytest.mark.parametrize("fall", _V["url_validering"], ids=_ids("url_validering"))
def test_url_validering(fall: dict[str, Any]) -> None:
    ports = frozenset(fall["allowed_ports"]) if "allowed_ports" in fall else None
    result = validate_url(fall["url"], FakeDns(fall["dns"]), ports)
    ut = fall["ut"]
    if ut["ok"]:
        assert isinstance(result, Target), result
        assert result.host == ut["host"]
        assert result.port == ut["port"]
        assert list(result.addresses) == ut["adresser"]
        assert result.path_query == ut["path_query"]
    else:
        assert isinstance(result, Failed), result
        assert result.code.value == ut["kod"]


@pytest.mark.parametrize("fall", _V["robots_tolkning"], ids=_ids("robots_tolkning"))
def test_robots_tolkning(fall: dict[str, Any]) -> None:
    rules = parse_robots(fall["text"], fall["agent"])
    for kontroll in fall["kontroller"]:
        assert rules.allows(kontroll["path"]) is kontroll["tillaten"], kontroll["path"]


@pytest.mark.parametrize("fall", _V["hastighetsgrans"], ids=_ids("hastighetsgrans"))
def test_hastighetsgrans(fall: dict[str, Any]) -> None:
    clock = FakeClock()
    limiter = HostLimiter(fall["min_interval"], clock)
    for anrop in fall["anrop"]:
        clock.now = anrop["t"]
        wait = limiter.reserve(anrop["host"], fall["max_wait"])
        if anrop["vantan"] is None:
            assert wait is None
        else:
            assert wait == pytest.approx(anrop["vantan"])


def _config(raw: dict[str, Any]) -> FetchConfig:
    kwargs = dict(raw)
    for key in ("allowed_ports", "allowed_content_types"):
        if key in kwargs:
            kwargs[key] = frozenset(kwargs[key])
    return FetchConfig(**kwargs)


def _check(
    ut: dict[str, Any],
    result: Fetched | Failed,
    transport: FakeTransport,
    dns: FakeDns,
    start_index: int,
) -> None:
    assert isinstance(result, Fetched) is ut["ok"], result
    if not ut["ok"]:
        assert isinstance(result, Failed)
        assert result.code.value == ut["kod"], result
        if "status" in ut:
            assert result.http_status == ut["status"]
    if isinstance(result, Fetched):
        for key, attr in (
            ("status", "status"),
            ("final_url", "final_url"),
            ("body_len", None),
            ("truncated", "truncated"),
            ("omdirigeringar", "redirects"),
            ("content_type", "content_type"),
        ):
            if key in ut:
                actual = len(result.body) if key == "body_len" else getattr(result, str(attr))
                assert actual == ut[key], key
    seen = transport.seen[start_index:]
    if "anslutna_ip" in ut:
        assert [s.ip for s in seen] == ut["anslutna_ip"]
    if "forfragningar" in ut:
        assert [s.url for s in seen] == ut["forfragningar"]
    if "antal_forfragningar" in ut:
        assert len(seen) == ut["antal_forfragningar"]
    if "host_header" in ut:
        assert seen[-1].headers["host"] == ut["host_header"]
    if "sni" in ut:
        assert seen[-1].sni == ut["sni"]
    if "metod" in ut:
        assert all(s.method == ut["metod"] for s in seen)
    if "user_agent" in ut:
        assert all(s.headers["user-agent"] == ut["user_agent"] for s in seen)
    for name in ut.get("saknade_huvuden", []):
        assert all(name not in s.headers for s in seen)
    if "accept_encoding" in ut:
        assert all(s.headers["accept-encoding"] == ut["accept_encoding"] for s in seen)
    if "last_bytes" in ut:
        assert transport.bytes_read == ut["last_bytes"]
    for host, n in ut.get("dns_anrop", {}).items():
        assert dns.calls.get(host, 0) == n, host


@pytest.mark.parametrize("fall", _V["hamtning"], ids=_ids("hamtning"))
def test_hamtning(fall: dict[str, Any]) -> None:
    clock = FakeClock()
    transport = FakeTransport(
        fall["rutter"],
        clock=clock,
        step=fall.get("tid_per_forfragan", 0.0),
        ip_errors=fall.get("ip_fel", {}),
    )
    dns = FakeDns(fall["dns"], fall.get("dns_sekvens"))
    robots = RobotsConfig(**fall["robots"]) if "robots" in fall else None
    fetcher = SafeFetcher(
        _config(fall.get("config", {})),
        resolver=dns,
        transport=transport,
        clock=clock,
        sleep=clock.sleep,
        robots=robots,
    )
    calls = fall.get("anrop") or [{"url": fall["start"], "t": 0, "ut": fall["ut"]}]
    for call in calls:
        clock.now = call["t"]
        before = len(transport.seen)
        result = fetcher.fetch(call["url"])
        _check(call["ut"], result, transport, dns, before)
    for url, n in fall.get("forvantat_antal", {}).items():
        assert transport.counts.get(url, 0) == n, url
