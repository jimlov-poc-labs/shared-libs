"""Min-fördröjning per värd. Klockan injiceras; ingen sömn sker här (anroparen sover)."""

from __future__ import annotations

import threading
from collections.abc import Callable


class HostLimiter:
    """Reserverar tidsluckor per värd så att anrop ligger minst `min_interval` isär.

    `reserve` returnerar hur länge anroparen ska vänta, eller None om väntan skulle överstiga
    `max_wait` (då reserveras ingenting). Reservationen sker atomiskt, så samtidiga trådar får
    var sin lucka.
    """

    def __init__(
        self,
        min_interval: float,
        clock: Callable[[], float],
        max_hosts: int = 10_000,
    ) -> None:
        if min_interval <= 0 or max_hosts < 1:
            raise ValueError("min_interval måste vara > 0 och max_hosts >= 1")
        self._interval = min_interval
        self._clock = clock
        self._max_hosts = max_hosts
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}

    def reserve(self, host: str, max_wait: float) -> float | None:
        with self._lock:
            now = self._clock()
            slot = max(now, self._next.get(host, now))
            wait = slot - now
            if wait > max_wait:
                return None
            if len(self._next) >= self._max_hosts and host not in self._next:
                self._next = {h: t for h, t in self._next.items() if t > now}
                if len(self._next) >= self._max_hosts:
                    return None  # fail closed: hellre nekat än obegränsat tillstånd
            self._next[host] = slot + self._interval
            return wait
