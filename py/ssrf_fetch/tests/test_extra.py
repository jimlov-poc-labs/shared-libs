"""Tester utöver vektorerna: Python-specifikt, tillstånd, äkta socket mot lokal server."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import httpx
import pytest

from fakes import FakeClock, FakeDns, FakeTransport
from ssrf_fetch import (
    ErrorCode,
    Failed,
    FetchConfig,
    Fetched,
    HostLimiter,
    RobotsCache,
    RobotsConfig,
    SafeFetcher,
    default_resolver,
    parse_robots,
    validate_url,
)
from ssrf_fetch import url as url_module
from ssrf_fetch.url import URL_PLACEHOLDER, redact_url, resolve_with_timeout

PUB = "93.184.216.34"
DNS = {"example.com": [PUB]}


def _fetcher(routes: dict[str, Any], **kw: Any) -> tuple[SafeFetcher, FakeTransport]:
    clock = kw.pop("clock", FakeClock())
    transport = FakeTransport(routes, clock=clock)
    fetcher = SafeFetcher(
        kw.pop("config", None),
        resolver=kw.pop("resolver", FakeDns(DNS)),
        transport=transport,
        clock=clock,
        sleep=clock.sleep,
        **kw,
    )
    return fetcher, transport


def _ok(text: str = "x") -> dict[str, Any]:
    return {"status": 200, "body_text": text}


def _failed(result: Fetched | Failed) -> Failed:
    assert isinstance(result, Failed), result
    return result


# --- fail closed ------------------------------------------------------------------


@pytest.mark.parametrize("error", [RuntimeError("x"), OSError("x"), KeyError("x"), TimeoutError()])
def test_varje_resolverfel_nekas(error: Exception) -> None:
    def broken(host: str, port: int) -> list[str]:
        raise error

    result = validate_url("http://example.com/", broken)
    assert isinstance(result, Failed) and result.code is ErrorCode.DNS_ERROR


def test_resolver_som_ger_fel_typ_nekas() -> None:
    result = validate_url("http://example.com/", lambda h, p: None)  # type: ignore[arg-type,return-value]
    assert isinstance(result, Failed)


def test_ovantat_fel_i_transporten_ger_internal_error_inte_exception() -> None:
    class Boom(FakeTransport):
        def handle_request(self, request: Any) -> Any:
            raise RuntimeError("boom")

    clock = FakeClock()
    fetcher = SafeFetcher(resolver=FakeDns(DNS), transport=Boom({}), clock=clock)
    result = _failed(fetcher.fetch("http://example.com/"))
    assert result.code is ErrorCode.INTERNAL_ERROR


def test_icke_strang_nekas() -> None:
    fetcher, transport = _fetcher({})
    assert _failed(fetcher.fetch(None)).code is ErrorCode.INVALID_URL  # type: ignore[arg-type]
    assert _failed(fetcher.fetch(b"http://example.com/")).code is ErrorCode.INVALID_URL  # type: ignore[arg-type]
    assert not transport.seen


def test_for_lang_url_nekas() -> None:
    fetcher, transport = _fetcher({})
    result = _failed(fetcher.fetch("http://example.com/" + "a" * 9000))
    assert result.code is ErrorCode.INVALID_URL and not transport.seen


def test_felmeddelanden_innehaller_aldrig_url_med_hemlig_token() -> None:
    secret = "tok_SUPERSECRET"
    fetcher, _ = _fetcher({"http://example.com/h?t=" + secret: {"status": 500}})
    for url in (
        "http://example.com/h?t=" + secret,
        "http://127.0.0.1/h?t=" + secret,
        "http://nope.example/h?t=" + secret,
        "ftp://example.com/h?t=" + secret,
    ):
        result = _failed(fetcher.fetch(url))
        assert secret not in result.detail
        assert secret not in repr(result.code)


def test_scheme_relativ_omdirigering_till_intern_ip_nekas() -> None:
    fetcher, transport = _fetcher(
        {"http://example.com/": {"status": 302, "headers": {"location": "//127.0.0.1/x"}}}
    )
    assert _failed(fetcher.fetch("http://example.com/")).code is ErrorCode.BLOCKED_IP
    assert len(transport.seen) == 1


def test_3xx_utan_omdirigeringsstatus_ar_http_status() -> None:
    fetcher, _ = _fetcher({"http://example.com/": {"status": 300, "headers": {"location": "/x"}}})
    result = _failed(fetcher.fetch("http://example.com/"))
    assert result.code is ErrorCode.HTTP_STATUS and result.http_status == 300


def test_ipv6_host_header_och_anslutning() -> None:
    addr = "2606:2800:220:1:248:1893:25c8:1946"
    fetcher, transport = _fetcher({f"https://[{addr}]:8443/": _ok()}, resolver=FakeDns({}))
    assert isinstance(fetcher.fetch(f"https://[{addr}]:8443/"), Fetched)
    assert transport.seen[0].ip == addr
    assert transport.seen[0].headers["host"] == f"[{addr}]:8443"


# --- config -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_bytes": 0},
        {"max_redirects": -1},
        {"max_addresses": 0},
        {"total_timeout": 0},
        {"connect_timeout": -1},
        {"read_timeout": 0},
    ],
)
def test_ogiltig_konfiguration_avvisas(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        FetchConfig(**kwargs)


@pytest.mark.parametrize("agent", ["", "*", "a b", "a:b", "a#b"])
def test_ogiltig_robotsagent_avvisas(agent: str) -> None:
    with pytest.raises(ValueError):
        RobotsConfig(agent=agent)


def test_ogiltig_robotskonfiguration() -> None:
    bad: list[dict[str, Any]] = [{"ttl": 0}, {"max_bytes": 0}, {"max_entries": 0}, {"max_rules": 0}]
    for kwargs in bad:
        with pytest.raises(ValueError):
            RobotsConfig(agent="bot", **kwargs)


# --- robots: tillstånd och hårdhet -------------------------------------------------


def test_robotsmatchning_tal_katastrofmonster() -> None:
    rules = parse_robots("User-agent: *\nDisallow: /" + "*a" * 200 + "*b", "bot")
    start = time.perf_counter()
    assert rules.allows("/" + "a" * 100_000) is True
    assert time.perf_counter() - start < 2.0


def test_robots_ar_per_instans_inget_globalt_tillstand() -> None:
    routes = {
        "http://example.com/robots.txt": {"status": 404},
        "http://example.com/": _ok(),
    }
    a, ta = _fetcher(routes, robots=RobotsConfig("bot"))
    b, tb = _fetcher(routes, robots=RobotsConfig("bot"))
    a.fetch("http://example.com/")
    b.fetch("http://example.com/")
    assert ta.counts["http://example.com/robots.txt"] == 1
    assert tb.counts["http://example.com/robots.txt"] == 1


def test_injicerad_robotscache_delas_av_vald_instans() -> None:
    clock = FakeClock()
    cache = RobotsCache(100, 10, clock)
    routes = {"http://example.com/robots.txt": {"status": 404}, "http://example.com/": _ok()}
    a, ta = _fetcher(routes, robots=RobotsConfig("bot"), robots_cache=cache, clock=clock)
    b, tb = _fetcher(routes, robots=RobotsConfig("bot"), robots_cache=cache, clock=clock)
    a.fetch("http://example.com/")
    b.fetch("http://example.com/")
    assert ta.counts["http://example.com/robots.txt"] == 1
    assert "http://example.com/robots.txt" not in tb.counts


def test_robotscache_har_tak_och_rensar_utgangna() -> None:
    clock = FakeClock()
    cache = RobotsCache(10, 2, clock)
    rules = parse_robots("", "bot")
    cache.put("a", rules)
    clock.now = 5
    cache.put("b", rules)
    clock.now = 11  # a har gått ut
    cache.put("c", rules)
    assert len(cache) == 2 and cache.get("a") is None and cache.get("c") is not None
    cache.put("d", rules)  # inget utgånget: äldsta ut
    assert len(cache) == 2


def test_robots_hamtas_med_samma_spar_ssrf_och_hastighetsgrans() -> None:
    clock = FakeClock()
    limiter = HostLimiter(1.0, clock)
    routes = {"http://example.com/robots.txt": {"status": 404}, "http://example.com/a": _ok()}
    fetcher, transport = _fetcher(routes, robots=RobotsConfig("bot"), limiter=limiter, clock=clock)
    assert isinstance(fetcher.fetch("http://example.com/a"), Fetched)
    assert [s.url for s in transport.seen] == [
        "http://example.com/robots.txt",
        "http://example.com/a",
    ]
    assert clock.now == pytest.approx(1.0)  # andra anropet (sidan) väntade på sin lucka


def test_hastighetsgrans_nekar_om_vantan_overstiger_totaltiden() -> None:
    clock = FakeClock()
    limiter = HostLimiter(60.0, clock)
    fetcher, _ = _fetcher(
        {"http://example.com/": _ok()},
        limiter=limiter,
        clock=clock,
        config=FetchConfig(total_timeout=5),
    )
    assert isinstance(fetcher.fetch("http://example.com/"), Fetched)
    assert _failed(fetcher.fetch("http://example.com/")).code is ErrorCode.RATE_LIMITED


def test_hostlimiter_har_tak_pa_antal_varden() -> None:
    clock = FakeClock()
    limiter = HostLimiter(10.0, clock, max_hosts=2)
    assert limiter.reserve("a", 1) == 0
    assert limiter.reserve("b", 1) == 0
    assert limiter.reserve("c", 1) is None  # fail closed, inte obegränsat tillstånd
    clock.now = 100  # a och b har löpt ut
    assert limiter.reserve("c", 1) == 0


def test_hostlimiter_avvisar_ogiltig_konfiguration() -> None:
    with pytest.raises(ValueError):
        HostLimiter(0, FakeClock())
    with pytest.raises(ValueError):
        HostLimiter(1, FakeClock(), max_hosts=0)


def test_default_resolver_ger_unika_adresser_i_ordning(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(host: str, port: int, **kw: Any) -> list[tuple[Any, ...]]:
        assert kw["type"] == socket.SOCK_STREAM
        return [
            (socket.AF_INET6, 1, 6, "", ("2606:2800::1", port, 0, 0)),
            (socket.AF_INET, 1, 6, "", ("1.2.3.4", port)),
            (socket.AF_INET, 1, 6, "", ("1.2.3.4", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert default_resolver("x.example", 80) == ["2606:2800::1", "1.2.3.4"]


def test_inga_kakor_mellan_hopp() -> None:
    routes = {
        "http://example.com/": {"status": 302, "headers": {"set-cookie": "a=1", "location": "/b"}},
        "http://example.com/b": _ok(),
    }
    fetcher, transport = _fetcher(routes)
    assert isinstance(fetcher.fetch("http://example.com/"), Fetched)
    assert len(transport.seen) == 2
    assert all("cookie" not in s.headers for s in transport.seen)


# --- äkta socket mot lokal server (loopback tillåts bara här, via monkeypatch) ------


class _Handler(BaseHTTPRequestHandler):
    hosts: list[str] = []

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        type(self).hosts.append(self.headers.get("Host", ""))
        if self.path == "/big":
            self.send_response(200)
            self.end_headers()
            try:
                for _ in range(5000):
                    self.wfile.write(b"x" * 1024)
            except OSError:
                pass
        elif self.path == "/slow":
            time.sleep(1.5)
            self.send_response(200)
            self.end_headers()
        elif self.path == "/drip":
            # Ett huvudfält var 0,3 s: varje enskild läsning lyckas, men huvudet blir aldrig klart.
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                for i in range(30):
                    self.wfile.write(f"X-Drip-{i}: x\r\n".encode())
                    self.wfile.flush()
                    time.sleep(0.3)
            except OSError:
                pass
        elif self.path == "/gzip":
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(b"zzz")
        elif self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "http://pin.example/ok")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")


@pytest.fixture
def local_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[int]:
    _Handler.hosts = []
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("ssrf_fetch.url.is_blocked_ip", lambda ip: False)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _real(port: int, **cfg: Any) -> SafeFetcher:
    dns = FakeDns({"pin.example": ["127.0.0.1"]})
    return SafeFetcher(FetchConfig(**cfg), resolver=dns)


def test_akta_socket_ansluter_till_pinnad_ip_och_behaller_host(local_server: int) -> None:
    with _real(local_server) as fetcher:
        result = fetcher.fetch(f"http://pin.example:{local_server}/")
    assert isinstance(result, Fetched) and result.body == b"ok"
    assert _Handler.hosts == [f"pin.example:{local_server}"]


def test_akta_socket_storleksgrans_lasar_inte_allt(local_server: int) -> None:
    with _real(local_server, max_bytes=2048) as fetcher:
        start = time.perf_counter()
        result = fetcher.fetch(f"http://pin.example:{local_server}/big")
    assert _failed(result).code is ErrorCode.TOO_LARGE
    assert time.perf_counter() - start < 5


def test_akta_socket_trunkering(local_server: int) -> None:
    with _real(local_server, max_bytes=3000, truncate_oversize=True) as fetcher:
        result = fetcher.fetch(f"http://pin.example:{local_server}/big")
    assert isinstance(result, Fetched) and len(result.body) == 3000 and result.truncated


def test_akta_socket_lastimeout(local_server: int) -> None:
    with _real(local_server, read_timeout=0.3) as fetcher:
        result = fetcher.fetch(f"http://pin.example:{local_server}/slow")
    assert _failed(result).code is ErrorCode.TIMEOUT


def test_akta_socket_komprimerat_nekas(local_server: int) -> None:
    with _real(local_server) as fetcher:
        result = fetcher.fetch(f"http://pin.example:{local_server}/gzip")
    assert _failed(result).code is ErrorCode.UNSUPPORTED_ENCODING


def test_akta_socket_omdirigering_valideras_pa_nytt(local_server: int) -> None:
    # Omdirigeringen pekar på pin.example utan port (80): ingen server där -> anslutningsfel,
    # och namnet lästes upp på nytt för det hoppet.
    dns = FakeDns({"pin.example": ["127.0.0.1"]})
    with SafeFetcher(resolver=dns) as fetcher:
        result = fetcher.fetch(f"http://pin.example:{local_server}/redir")
    assert dns.calls["pin.example"] == 2
    assert isinstance(result, Failed)


def test_utan_monkeypatch_nekas_loopback_aven_via_namn() -> None:
    dns = FakeDns({"pin.example": ["127.0.0.1"]})
    with SafeFetcher(resolver=dns) as fetcher:
        assert _failed(fetcher.fetch("http://pin.example:1/")).code is ErrorCode.BLOCKED_IP


def test_location_som_inte_gar_att_tolka_ar_bad_redirect() -> None:
    fetcher, _ = _fetcher(
        {"http://example.com/": {"status": 302, "headers": {"location": "http://[bad/"}}}
    )
    assert _failed(fetcher.fetch("http://example.com/")).code is ErrorCode.BAD_REDIRECT


def test_asynkron_ström_från_transport_nekas() -> None:
    import httpx

    class AsyncOnly(httpx.AsyncByteStream):
        async def __aiter__(self) -> Any:
            yield b"x"

    class T(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, stream=AsyncOnly())

    fetcher = SafeFetcher(resolver=FakeDns(DNS), transport=T(), clock=FakeClock())
    assert _failed(fetcher.fetch("http://example.com/")).code is ErrorCode.INTERNAL_ERROR


def test_vantan_som_tar_slut_pa_totaltiden_ger_timeout() -> None:
    clock = FakeClock()
    limiter = HostLimiter(5.0, clock)
    fetcher, transport = _fetcher(
        {"http://example.com/": _ok()},
        limiter=limiter,
        clock=clock,
        config=FetchConfig(total_timeout=5),
    )
    assert isinstance(fetcher.fetch("http://example.com/"), Fetched)
    assert _failed(fetcher.fetch("http://example.com/")).code is ErrorCode.TIMEOUT
    assert len(transport.seen) == 1


# --- deadline gäller även svarshuvudet ------------------------------------------------


def test_akta_socket_totaltid_galler_medan_svarshuvudet_droppas(local_server: int) -> None:
    with _real(local_server, total_timeout=1.5, read_timeout=1.0) as fetcher:
        start = time.perf_counter()
        result = fetcher.fetch(f"http://pin.example:{local_server}/drip")
        elapsed = time.perf_counter() - start
    assert _failed(result).code is ErrorCode.TIMEOUT
    assert elapsed < 4, elapsed  # utan deadline: ~9 s (30 x 0,3 s)


# --- Failed.url maskeras ----------------------------------------------------------------

_SECRETS = ("hunter2", "admin", "token=abc", "abc", "frag-secret")


@pytest.mark.parametrize(
    "url",
    [
        "http://admin:hunter2@example.com/x?token=abc#frag-secret",
        "http://admin:hunter2@127.0.0.1/x?token=abc#frag-secret",
        "ftp://admin:hunter2@example.com/x?token=abc#frag-secret",
        "http://admin:hunter2@nope.example/x?token=abc#frag-secret",
        "http://example.com/x?token=abc#frag-secret",
        "http://admin:hunter2@[::1/x?token=abc#frag-secret",
        "http://admin:hunter2@exa mple.com/x?token=abc#frag-secret",
        "http://admin:hunter2@example.com:99999999/x?token=abc#frag-secret",
        "http://admin:hunter2@\\example.com/x?token=abc#frag-secret",
        "http://admin:hunter2@%65xample.com/x?token=abc#frag-secret",
    ],
)
def test_failed_url_innehaller_aldrig_userinfo_query_eller_fragment(url: str) -> None:
    fetcher, _ = _fetcher({"http://example.com/x?token=abc": {"status": 500}})
    result = _failed(fetcher.fetch(url))
    for secret in _SECRETS:
        assert secret not in repr(result), (secret, result)


def test_failed_url_ar_maskerad_men_anvandbar() -> None:
    fetcher, _ = _fetcher({})
    result = _failed(fetcher.fetch("http://admin:hunter2@example.com/x?token=abc"))
    assert result.url == "http://example.com/x"
    assert redact_url("https://example.com:8443") == "https://example.com:8443"


@pytest.mark.parametrize("url", ["http://[::1", "mailto:a@b", "", "http://a b/", 12345, None])
def test_redact_url_trasig_indata_ger_platshallare(url: Any) -> None:
    assert redact_url(url) == URL_PLACEHOLDER


def test_failed_url_vid_internt_fel_och_omdirigering_ar_maskerad() -> None:
    class Boom(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise RuntimeError("hunter2")

    fetcher = SafeFetcher(resolver=FakeDns(DNS), transport=Boom(), clock=FakeClock())
    result = _failed(fetcher.fetch("http://example.com/x?token=abc"))
    assert result.code is ErrorCode.INTERNAL_ERROR and "abc" not in repr(result)
    fetcher, _ = _fetcher(
        {"http://example.com/r?token=abc": {"status": 302, "headers": {"location": "/r?token=abc"}}}
    )
    result = _failed(fetcher.fetch("http://example.com/r?token=abc"))
    assert result.code is ErrorCode.TOO_MANY_REDIRECTS and "abc" not in repr(result)


# --- DNS har tidsgräns ------------------------------------------------------------------


def test_langsam_resolver_ger_timeout_inom_totaltiden() -> None:
    release = threading.Event()

    def hanging(host: str, port: int) -> list[str]:
        release.wait(10)
        return [PUB]

    fetcher = SafeFetcher(
        FetchConfig(total_timeout=0.5), resolver=hanging, transport=FakeTransport({})
    )
    try:
        start = time.perf_counter()
        result = fetcher.fetch("http://example.com/")
        elapsed = time.perf_counter() - start
    finally:
        release.set()
    assert _failed(result).code is ErrorCode.TIMEOUT
    assert elapsed < 3, elapsed


def test_validate_url_dns_timeout_och_utgangen_tid() -> None:
    release = threading.Event()

    def hanging(host: str, port: int) -> list[str]:
        release.wait(10)
        return [PUB]

    try:
        slow = validate_url("http://example.com/", hanging, dns_timeout=0.2)
        expired = validate_url("http://example.com/", FakeDns(DNS), dns_timeout=0)
    finally:
        release.set()
    assert isinstance(slow, Failed) and slow.code is ErrorCode.TIMEOUT
    assert isinstance(expired, Failed) and expired.code is ErrorCode.TIMEOUT


def _dns_threads() -> int:
    return sum(1 for t in threading.enumerate() if t.name == "ssrf-dns")


def test_dns_uppslag_har_tak_och_nekas_direkt_nar_fullt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_module, "_dns_slots", threading.BoundedSemaphore(3))
    release = threading.Event()
    before = _dns_threads()

    def slow(host: str, port: int) -> list[str]:
        release.wait(10)
        return [PUB]

    try:
        results = [resolve_with_timeout(slow, "example.com", 80, 0.05) for _ in range(3)]
        start = time.perf_counter()
        extra = [resolve_with_timeout(slow, "example.com", 80, 5) for _ in range(20)]
        elapsed = time.perf_counter() - start
        assert _dns_threads() - before <= 3
    finally:
        release.set()
    assert all(isinstance(r, Failed) and r.code is ErrorCode.TIMEOUT for r in results)
    assert all(isinstance(r, Failed) and r.code is ErrorCode.TIMEOUT for r in extra)
    assert elapsed < 1, elapsed


def test_dns_platser_frigors_nar_tradarna_ar_klara(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_module, "_dns_slots", threading.BoundedSemaphore(2))
    release = threading.Event()

    def slow(host: str, port: int) -> list[str]:
        release.wait(10)
        return [PUB]

    for _ in range(2):
        assert isinstance(resolve_with_timeout(slow, "example.com", 80, 0.05), Failed)
    full = resolve_with_timeout(FakeDns(DNS), "example.com", 80, 1)
    assert isinstance(full, Failed) and full.code is ErrorCode.TIMEOUT
    release.set()
    deadline = time.monotonic() + 5
    while _dns_threads() and time.monotonic() < deadline:
        time.sleep(0.01)
    ok = resolve_with_timeout(FakeDns(DNS), "example.com", 80, 1)
    assert ok == DNS["example.com"]


def test_dns_plats_frigors_aven_nar_resolvern_kastar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_module, "_dns_slots", threading.BoundedSemaphore(1))

    def boom(host: str, port: int) -> list[str]:
        raise OSError("nej")

    for _ in range(3):
        r = resolve_with_timeout(boom, "example.com", 80, 1)
        assert isinstance(r, Failed) and r.code is ErrorCode.DNS_ERROR


# --- Content-Length strikt ASCII ----------------------------------------------------------


def test_content_length_med_unicodesiffra_ger_tydlig_felkod() -> None:
    fetcher, _ = _fetcher(
        {
            "http://example.com/": {
                "status": 200,
                "headers": [(b"content-length", "\u00b2".encode())],
            }
        }
    )
    assert _failed(fetcher.fetch("http://example.com/")).code is ErrorCode.NETWORK_ERROR


def test_content_length_med_tusentals_siffror_ar_for_stor_inte_internt_fel() -> None:
    fetcher, _ = _fetcher(
        {"http://example.com/": {"status": 200, "headers": {"content-length": "9" * 5000}}}
    )
    assert _failed(fetcher.fetch("http://example.com/")).code is ErrorCode.TOO_LARGE


def test_validate_url_maskerar_failed_url_direkt() -> None:
    for url in (
        "http://admin:hunter2@example.com/x?token=abc#frag-secret",
        "http://admin:hunter2@127.0.0.1/x?token=abc",
        "http://admin:hunter2@[::1/x?token=abc",
    ):
        result = validate_url(url, FakeDns(DNS))
        assert isinstance(result, Failed)
        for secret in _SECRETS:
            assert secret not in repr(result)
