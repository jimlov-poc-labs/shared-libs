"""Mutationskontroll: tar bort ett skydd i taget i en kopia av källkoden och kräver att testerna
faller. Kör: `.venv/bin/python mutationskontroll.py` (exit 0 = alla mutanter fångades).

Varje mutant är en textersättning i en kopia under en temporärkatalog; originalet rörs aldrig.
Ersättningen måste träffa exakt en gång, annars avbryts körningen (så att en refaktorering
inte tyst gör en mutant verkningslös).

Medvetet utelämnad: "ta bort is_global-kravet". Den explicita listan täcker redan allt som
is_global nekar (stickprov 600 000 adresser, 0 avvikelser), så mutanten är ekvivalent;
kravet behålls som andra lager ifall en framtida Python-version utökar sitt svar.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src" / "ssrf_fetch"

# (namn, fil, gammal text, ny text, antal träffar)
MUTANTER: list[tuple[str, str, str, str, int]] = [
    (
        "taket för samtidiga DNS-uppslag borttaget",
        "url.py",
        "    if not slots.acquire(blocking=False):",
        "    if not slots.acquire(blocking=False) and False:",
        1,
    ),
    (
        "DNS-plats frigörs aldrig",
        "url.py",
        "        finally:\n            slots.release()\n",
        "        finally:\n            pass\n",
        1,
    ),
    (
        "IP-spärren avstängd",
        "address.py",
        "    if any(addr in n for n in networks):\n        return True\n    return not addr.is_global",  # noqa: E501
        "    return False",
        1,
    ),
    (
        "bara is_global, ingen explicit lista",
        "address.py",
        "    if any(addr in n for n in networks):\n        return True\n",
        "",
        1,
    ),
    (
        "IPv4-mappade IPv6-adresser packas inte upp",
        "address.py",
        "        addr = addr.ipv4_mapped  # ::ffff:127.0.0.1 bedöms som 127.0.0.1",
        "        pass",
        1,
    ),
    (
        "omdirigeringshopp valideras inte",
        "fetcher.py",
        "            target = validate_url(\n                current,\n"
        "                self._resolver,\n"
        "                cfg.allowed_ports,\n"
        "                dns_timeout=deadline - self._clock(),\n"
        "            )\n",
        "            target = validate_url(current, self._resolver, cfg.allowed_ports) if hop == 0 "
        "else Target(urlsplit(current).scheme, urlsplit(current).hostname or '', "
        "urlsplit(current).port or 80, '/', (urlsplit(current).hostname or '',), True)\n",
        1,
    ),
    (
        "omdirigeringstaket avstängt",
        "fetcher.py",
        "for hop in range(cfg.max_redirects + 1):",
        "for hop in range(1000):",
        1,
    ),
    (
        "schema-nedgradering tillåten",
        "fetcher.py",
        '            if target.scheme == "https" and next_scheme == "http":',
        "            if False:",
        1,
    ),
    (
        "storlekstaket avstängt (strömmen)",
        "fetcher.py",
        "            if len(body) > max_bytes:",
        "            if False:",
        1,
    ),
    (
        "storlekstaket avstängt (Content-Length)",
        "fetcher.py",
        "            if too_big and not truncate:",
        "            if False:",
        1,
    ),
    (
        "pinning avstängd: anslut till namnet, inte den validerade IP:n",
        "fetcher.py",
        '        netloc = f"[{ip}]" if ":" in ip else ip',
        '        netloc = f"[{target.host}]" if ":" in target.host else target.host',
        1,
    ),
    (
        "SNI/certifikatnamn tas bort",
        "fetcher.py",
        '                        if target.scheme == "https" and not target.is_ip_literal',
        "                        if False",
        1,
    ),
    (
        "en intern adress bland flera nekar inte längre",
        "url.py",
        "    if any(is_blocked_ip(a) for a in addresses):",
        "    if all(is_blocked_ip(a) for a in addresses):",
        1,
    ),
    (
        "tom adresslista släpps igenom",
        "url.py",
        "    if not addresses:",
        "    if False:",
        1,
    ),
    (
        "användaruppgifter i URL tillåts",
        "url.py",
        '    if "@" in parts.netloc:',
        "    if False:",
        1,
    ),
    (
        "schemakontrollen avstängd",
        "url.py",
        '    if scheme not in ("http", "https"):',
        "    if False:",
        1,
    ),
    (
        "hex/oktal/korta IP-former tolkas inte",
        "url.py",
        '    if is_numeric_label(name.rsplit(".", 1)[-1]):',
        "    if False:",
        1,
    ),
    (
        "localhost-spärren avstängd",
        "url.py",
        '    if name == "localhost" or labels[-1] == "localhost":',
        "    if False:",
        1,
    ),
    (
        "robots 5xx/nätverksfel tolkas som tillåtet",
        "fetcher.py",
        "        # Cachas inte; ett tillfälligt fel ska inte låsa ute en sajt i en timme.\n",
        "        return ALLOW_ALL\n",
        1,
    ),
    (
        "robots-cachen lagrar inget",
        "fetcher.py",
        "            cache.put(target.origin, rules)",
        "            pass",
        1,
    ),
    (
        "robots gäller inte hopp efter omdirigering",
        "fetcher.py",
        "            if use_robots:\n                denial",
        "            if use_robots and hop == 0:\n                denial",
        1,
    ),
    (
        "namngiven grupp med tom Disallow späds ut av jokern",
        "robots.py",
        "tuple(named if named_seen else star)",
        "tuple(named or star)",
        1,
    ),
    (
        "robots: lika långa mönster ger Disallow",
        "robots.py",
        "(rule.length == best.length and rule.allow and not best.allow)",
        "False",
        1,
    ),
    (
        "robots: kortaste mönstret vinner",
        "robots.py",
        "                or rule.length > best.length",
        "                or rule.length < best.length",
        1,
    ),
    (
        "totaltimeout avstängd",
        "fetcher.py",
        "if remaining <= 0:",
        "if False:",
        2,
    ),
    (
        "totaltimeout avstängd under läsning",
        "fetcher.py",
        "            if self._clock() >= deadline:",
        "            if False:",
        1,
    ),
    (
        "absolut deadline avstängd under svarshuvudet",
        "fetcher.py",
        "            with self._backend.scope(deadline):",
        '            with self._backend.scope(float("inf")):',
        1,
    ),
    (
        "Failed.url ej maskerad i url.py",
        "url.py",
        "    return Failed(url=redact_url(url), code=code, detail=detail)",
        "    return Failed(url=url, code=code, detail=detail)",
        1,
    ),
    (
        "Failed.url ej maskerad i fetcher.py",
        "fetcher.py",
        "        shown = redact_url(url)  # allt som",
        "        shown = url  # allt som",
        1,
    ),
    (
        "Failed.url ej maskerad vid internt fel",
        "fetcher.py",
        "return Failed(redact_url(url), ErrorCode.INTERNAL_ERROR",
        "return Failed(url, ErrorCode.INTERNAL_ERROR",
        1,
    ),
    (
        "redact_url godtar vilken värd som helst",
        "url.py",
        "or not _SHOWN_HOSTPORT.fullmatch(hostport)",
        "or False",
        1,
    ),
    (
        "DNS utan tidsgräns",
        "url.py",
        "    thread.join(timeout)",
        "    thread.join()",
        1,
    ),
    (
        "Content-Length: isdigit i stället för strikt ASCII",
        "fetcher.py",
        "            if not _ASCII_DIGITS.fullmatch(declared):",
        "            if not declared.isdigit():",
        1,
    ),
    (
        "Content-Length: ingen längdspärr före int()",
        "fetcher.py",
        "len(declared) > _MAX_LENGTH_DIGITS or ",
        "",
        1,
    ),
    (
        "content-type-allowlist avstängd",
        "fetcher.py",
        "if content_types is not None and not _type_allowed(",
        "if False and not _type_allowed(",
        1,
    ),
    (
        "komprimerat svar accepteras",
        "fetcher.py",
        '        if encoding not in ("", "identity"):',
        "        if False:",
        1,
    ),
    (
        "hastighetsgränsen avstängd",
        "fetcher.py",
        "            wait = self._limiter.reserve(target.host, remaining)",
        "            wait = 0.0",
        1,
    ),
    (
        "robots 4xx (utom 404/410) nekar alltid",
        "fetcher.py",
        "            if status in (404, 410) or (lenient and not robots.strict_client_errors):",
        "            if status in (404, 410):",
        1,
    ),
    (
        "robots: tom cache räknas som saknad (falsy-fällan)",
        "fetcher.py",
        "                if robots_cache is not None",
        "                if robots_cache",
        1,
    ),
]


# Mutanter som kräver flera ändringar samtidigt (annars är varje del ekvivalent med originalet).
EXTRA: dict[str, list[tuple[str, str, str]]] = {
    "omdirigeringstaket avstängt": [
        ("fetcher.py", "            if hop >= cfg.max_redirects:", "            if False:")
    ],
}


def _run(src_root: Path) -> int:
    env = {**os.environ, "PYTHONPATH": str(src_root)}
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "--no-header"],
        cwd=HERE,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode


def main() -> int:
    survivors: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        shutil.copytree(SRC, base / "ssrf_fetch")
        if _run(base) != 0:
            print(
                "Grundkörningen mot oförändrad kopia föll; mutationskontrollen är inte meningsfull."
            )
            return 2
        print("grundkörning (oförändrad kopia): grön")
        for i, (name, fil, old, new, expected) in enumerate(MUTANTER):
            root = Path(tmp) / f"m{i}"
            shutil.copytree(SRC, root / "ssrf_fetch")
            path = root / "ssrf_fetch" / fil
            text = path.read_text(encoding="utf-8")
            if text.count(old) != expected:
                print(f"AVBRYTER: '{name}' träffar {text.count(old)} gånger, väntade {expected}")
                return 2
            path.write_text(text.replace(old, new), encoding="utf-8")
            for ofil, oold, onew in EXTRA.get(name, []):
                other = root / "ssrf_fetch" / ofil
                otext = other.read_text(encoding="utf-8")
                if otext.count(oold) != 1:
                    print(f"AVBRYTER: tilläggsändring för '{name}' träffar inte exakt en gång")
                    return 2
                other.write_text(otext.replace(oold, onew), encoding="utf-8")
            fell = _run(root) != 0
            print(f"{'FÅNGAD ' if fell else 'ÖVERLEVDE'}  {name}")
            if not fell:
                survivors.append(name)
    print(f"\n{len(MUTANTER) - len(survivors)}/{len(MUTANTER)} mutanter fångade")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
