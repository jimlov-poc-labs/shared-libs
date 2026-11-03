"""Fejkad transport, klocka och resolver. Inget här rör nätverket."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class CountingStream(httpx.SyncByteStream):
    """Strömmar i bitar om 8 KiB utan Content-Length och räknar vad som faktiskt lästs."""

    def __init__(self, data: bytes, state: FakeTransport) -> None:
        self._data = data
        self._state = state

    def __iter__(self) -> Iterator[bytes]:
        for i in range(0, len(self._data), 8192):
            chunk = self._data[i : i + 8192]
            self._state.bytes_read += len(chunk)
            yield chunk


@dataclass
class Seen:
    url: str
    ip: str
    sni: object
    headers: httpx.Headers
    method: str


@dataclass
class FakeTransport(httpx.BaseTransport):
    routes: dict[str, Any]
    clock: FakeClock | None = None
    step: float = 0.0
    ip_errors: dict[str, str] = field(default_factory=dict)
    seen: list[Seen] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    bytes_read: int = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host_header = request.headers["host"]
        url = f"{request.url.scheme}://{host_header}{request.url.raw_path.decode('ascii')}"
        ip = request.url.host
        self.seen.append(
            Seen(url, ip, request.extensions.get("sni_hostname"), request.headers, request.method)
        )
        self.counts[url] = self.counts.get(url, 0) + 1
        if self.clock is not None:
            self.clock.now += self.step
        error = self.ip_errors.get(ip)
        if error == "connect":
            raise httpx.ConnectError("fejkat anslutningsfel")
        if error == "timeout":
            raise httpx.ReadTimeout("fejkad timeout")
        route = self.routes.get(url)
        if isinstance(route, list):
            route = route[min(self.counts[url] - 1, len(route) - 1)]
        if route is None:
            return httpx.Response(404, headers={}, stream=CountingStream(b"", self))
        if route.get("fel") == "timeout":
            raise httpx.ReadTimeout("fejkad timeout")
        if route.get("fel") == "connect":
            raise httpx.ConnectError("fejkat anslutningsfel")
        if route.get("fel") == "network":
            raise httpx.RemoteProtocolError("fejkat protokollfel")
        if "body_len" in route:
            body = b"x" * route["body_len"]
        else:
            body = route.get("body_text", "").encode("utf-8")
        return httpx.Response(
            route["status"], headers=route.get("headers", {}), stream=CountingStream(body, self)
        )


class FakeDns:
    """Resolver med fasta svar; `sequence` ger olika svar per uppslag (DNS-rebinding)."""

    def __init__(
        self, table: dict[str, list[str]], sequence: dict[str, list[list[str]]] | None = None
    ) -> None:
        self.table = table
        self.sequence = sequence or {}
        self.calls: dict[str, int] = {}

    def __call__(self, host: str, port: int) -> list[str]:
        n = self.calls.get(host, 0)
        self.calls[host] = n + 1
        if host in self.sequence:
            seq = self.sequence[host]
            return seq[min(n, len(seq) - 1)]
        if host in self.table:
            return self.table[host]
        raise OSError(f"Name or service not known: {host}")
