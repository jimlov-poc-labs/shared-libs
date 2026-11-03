"""IP-spärren: vilka adresser får aldrig kontaktas. Ingen nätverks-I/O här.

Listan är uttrycklig i stället för att lita på `ipaddress.is_global`, vars svar har
ändrats mellan Python-patchversioner. `is_global` krävs *dessutom*.
"""

from __future__ import annotations

import ipaddress
import re

_V4_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "detta nätverk", inkl. 0.0.0.0
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT / Tailscale
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, inkl. molnens metadata 169.254.169.254
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserverat, inkl. 255.255.255.255
    )
)
_V6_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::/8",  # ::, ::1 och föråldrade IPv4-kompatibla ::a.b.c.d
        "64:ff9b::/96",  # NAT64
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",  # IETF-protokoll, inkl. Teredo
        "2001:db8::/32",
        "2002::/16",  # 6to4
        "3fff::/20",  # dokumentation (RFC 9637)
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)


def is_blocked_ip(text: str) -> bool:
    """True om adressen inte får kontaktas. Allt som inte är en giltig adress är blockerat."""
    if not isinstance(text, str) or "%" in text:
        return True
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # ::ffff:127.0.0.1 bedöms som 127.0.0.1
    networks = _V4_BLOCKED if addr.version == 4 else _V6_BLOCKED
    if any(addr in n for n in networks):
        return True
    return not addr.is_global


_DECIMAL_QUAD = re.compile(r"(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}")
_NUMERIC_LABEL = re.compile(r"0[xX][0-9a-fA-F]*|[0-9]+")


def is_numeric_label(label: str) -> bool:
    """Sista etiketten ser ut som ett tal: då är värden en IPv4-form, inte ett DNS-namn."""
    return bool(_NUMERIC_LABEL.fullmatch(label))


def is_canonical_ipv4(host: str) -> bool:
    """Strikt punktnotation a.b.c.d, decimalt, utan inledande nollor."""
    return bool(_DECIMAL_QUAD.fullmatch(host)) and all(int(p) <= 255 for p in host.split("."))


def _legacy_part(part: str) -> int | None:
    try:
        if part[:2] in ("0x", "0X"):
            return int(part[2:] or "0", 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part, 8)
        return int(part, 10)
    except ValueError:
        return None


def parse_legacy_ipv4(host: str) -> str | None:
    """Tolka inet_aton-former (hex, oktal, korta, heltal) till punktdecimal, annars None."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(is_numeric_label(p) for p in parts):
        return None
    values = [_legacy_part(p) for p in parts]
    if any(v is None for v in values):
        return None
    nums = [v for v in values if v is not None]
    *head, last = nums
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(nums)):
        return None
    total = last
    for i, v in enumerate(head):
        total += v << (8 * (3 - i))
    return str(ipaddress.IPv4Address(total))
