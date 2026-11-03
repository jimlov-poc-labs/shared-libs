"""Se spec/_exempel/vektorer.json för det språkoberoende kontraktet."""

_SIFFROR = frozenset("0123456789")


def strikt_port(text: str) -> int | None:
    """Returnera porten (1-65535) eller None. Allt tvetydigt nekas (fail closed)."""
    if not text or not set(text) <= _SIFFROR or text.startswith("0"):
        return None
    värde = int(text)
    return värde if 1 <= värde <= 65535 else None
