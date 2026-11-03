"""Absolut tidsgräns på nätverksnivå.

httpx/httpcore nollställer läsgränsen för varje mottaget byte, så en server som droppar ett
huvudfält i taget kan hålla en hämtning vid liv hur länge som helst. Här klampas varje
connect/read/write/TLS-handskakning mot en absolut deadline (injicerbar klocka), så att
`total_timeout` gäller hela hämtningen, även medan svarshuvudet läses.
"""

from __future__ import annotations

import ssl
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from typing import Any

import httpcore
import httpx
from httpcore import SOCKET_OPTION, NetworkBackend, NetworkStream, SyncBackend


class _Deadline(threading.local):
    value: float | None = None


class DeadlineBackend(NetworkBackend):
    """Nätverksbackend som aldrig väntar längre än den aktiva deadlinen i anropande tråd."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._inner = SyncBackend()
        self._local = _Deadline()

    @contextmanager
    def scope(self, deadline: float) -> Iterator[None]:
        previous = self._local.value
        self._local.value = deadline
        try:
            yield
        finally:
            self._local.value = previous

    def remaining(self, timeout: float | None, error: type[Exception]) -> float | None:
        """Återstående tid, högst `timeout`. Är deadlinen passerad kastas `error`."""
        deadline = self._local.value
        if deadline is None:
            return timeout
        left = deadline - self._clock()
        if left <= 0:
            raise error("totaltiden är slut")
        return left if timeout is None else min(timeout, left)

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        timeout = self.remaining(timeout, httpcore.ConnectTimeout)
        stream = self._inner.connect_tcp(host, port, timeout, local_address, socket_options)
        return _DeadlineStream(stream, self)

    def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Any = None
    ) -> NetworkStream:
        raise httpcore.ConnectError("unix-sockets nekas")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class _DeadlineStream(NetworkStream):
    def __init__(self, inner: NetworkStream, backend: DeadlineBackend) -> None:
        self._inner = inner
        self._backend = backend

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, self._backend.remaining(timeout, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, self._backend.remaining(timeout, httpcore.WriteTimeout))

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> NetworkStream:
        limited = self._backend.remaining(timeout, httpcore.ConnectTimeout)
        return _DeadlineStream(
            self._inner.start_tls(ssl_context, server_hostname, limited), self._backend
        )

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


def build_transport(backend: DeadlineBackend) -> httpx.HTTPTransport:
    """httpx-transport utan keep-alive, ingen återförsök, med deadline-backenden inkopplad."""
    transport = httpx.HTTPTransport(limits=httpx.Limits(max_keepalive_connections=0), retries=0)
    pool = getattr(transport, "_pool", None)
    if not isinstance(pool, httpcore.ConnectionPool):
        # fail closed: om httpx byter internt upplägg ska vi inte tyst tappa deadline-skyddet
        raise RuntimeError("httpx-transporten har oväntat uppbyggnad; deadline kan inte kopplas in")
    pool.close()
    transport._pool = httpcore.ConnectionPool(  # noqa: SLF001
        ssl_context=httpx.create_ssl_context(),
        max_connections=httpx.Limits().max_connections,
        max_keepalive_connections=0,
        retries=0,
        network_backend=backend,
    )
    return transport
