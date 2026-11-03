"""robots.txt enligt RFC 9309: tolkning, matchning och cache. Ingen nätverks-I/O här.

Egen tolkare i stället för urllib.robotparser, vars svar skiljer mellan Python-versioner
(Portis mätte det 2026-09-16). Matchningen använder ingen regex: robots.txt kommer från
den främmande servern, och `*`-mönster som regex kan ge katastrofal backtracking.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass

_LINE_SPLIT = re.compile(r"\r\n|\r|\n")
_MAX_PATTERN = 4096
_PCT = re.compile(r"%[0-9a-fA-F]{2}")


def normalize_path(text: str) -> str:
    """Procentkoda icke-ASCII (UTF-8) och versalisera %xx så att ekvivalenta former matchar."""
    out: list[str] = []
    for ch in text:
        out.append(ch if ord(ch) < 0x80 else "".join(f"%{b:02X}" for b in ch.encode("utf-8")))
    return _PCT.sub(lambda m: m.group(0).upper(), "".join(out))


def _matches(pattern: str, anchored: bool, path: str) -> bool:
    parts = pattern.split("*")
    if not path.startswith(parts[0]):
        return False
    pos = len(parts[0])
    if len(parts) == 1:
        return pos == len(path) if anchored else True
    for middle in parts[1:-1]:
        found = path.find(middle, pos)
        if found < 0:
            return False
        pos = found + len(middle)
    last = parts[-1]
    if anchored:
        return len(path) - len(last) >= pos and path.endswith(last)
    return path.find(last, pos) >= 0


@dataclass(frozen=True)
class _Rule:
    allow: bool
    pattern: str
    anchored: bool
    length: int  # mönstrets längd inkl. avslutande $, avgör specificitet


@dataclass(frozen=True)
class RobotsRules:
    """Reglerna som gäller en agent. `deny_all` används när filen inte gick att tolka säkert."""

    rules: tuple[_Rule, ...] = ()
    deny_all: bool = False

    def allows(self, path_query: str) -> bool:
        """Längsta matchande mönster vinner; vid lika längd vinner Allow (RFC 9309 2.2.2)."""
        if self.deny_all:
            return False
        path = normalize_path(path_query)
        best: _Rule | None = None
        for rule in self.rules:
            if not _matches(rule.pattern, rule.anchored, path):
                continue
            if (
                best is None
                or rule.length > best.length
                or (rule.length == best.length and rule.allow and not best.allow)
            ):
                best = rule
        return True if best is None else best.allow


ALLOW_ALL = RobotsRules()
DENY_ALL = RobotsRules(deny_all=True)


def parse_robots(text: str, agent: str, max_rules: int = 10_000) -> RobotsRules:
    """Reglerna för `agent` (produkttoken, skiftlägesokänsligt), annars gruppen `*`.

    En grupp som namnger agenten gäller även om den bara har tom `Disallow:`; då späds den
    inte ut av `*`-gruppen. Flera grupper för samma agent slås ihop. Fler än `max_rules`
    regler ger DENY_ALL (fail closed).
    """
    token = agent.lower()
    named: list[_Rule] = []
    star: list[_Rule] = []
    named_seen = False
    agents: list[str] = []
    in_header = False
    count = 0

    for raw in _LINE_SPLIT.split(text.removeprefix("﻿")):
        line = raw.split("#", 1)[0].strip()
        field, sep, value = line.partition(":")
        if not sep:
            continue
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            if not in_header:
                agents = []
                in_header = True
            agents.append(value.lower())
            named_seen = named_seen or value.lower() == token
            continue
        if field not in ("allow", "disallow"):
            continue
        in_header = False
        if not value or len(value) > _MAX_PATTERN:
            continue  # tom Disallow = inget förbjudet; orimligt långt mönster ignoreras
        count += 1
        if count > max_rules:
            return DENY_ALL
        anchored = value.endswith("$")
        pattern = normalize_path(value[:-1] if anchored else value)
        rule = _Rule(field == "allow", pattern, anchored, len(pattern) + anchored)
        if token in agents:
            named.append(rule)
        elif "*" in agents:
            star.append(rule)

    return RobotsRules(tuple(named if named_seen else star))


class RobotsCache:
    """Per-ursprung-cache med TTL. Klockan injiceras; tillståndet ägs av instansen."""

    def __init__(self, ttl: float, max_entries: int, clock: Callable[[], float]) -> None:
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[float, RobotsRules]] = {}

    def get(self, origin: str) -> RobotsRules | None:
        with self._lock:
            entry = self._entries.get(origin)
            if entry is None:
                return None
            if self._clock() >= entry[0]:
                del self._entries[origin]
                return None
            return entry[1]

    def put(self, origin: str, rules: RobotsRules) -> None:
        with self._lock:
            now = self._clock()
            if len(self._entries) >= self._max:
                self._entries = {k: v for k, v in self._entries.items() if v[0] > now}
            if len(self._entries) >= self._max:
                self._entries.pop(next(iter(self._entries)))
            self._entries[origin] = (now + self._ttl, rules)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
