"""Resolve a single `*_ref` secret reference. Fail closed, never log the value.

Mirrors the prefix contract of memaix/gateway/src/memaix_gateway/config.py's `secret()`,
pulled out so it has no dependency on the Memaix gateway package. See the package
docstring (secretref/__init__.py) for the full contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

_KNOWN_SCHEMES = ("env", "file", "vault", "kms")
_NOT_WIRED_SCHEMES = ("vault", "kms")


class SecretRefError(Exception):
    """A `*_ref` could not be resolved. Never includes the resolved value (there is none)."""


class BackendNotWired(SecretRefError, NotImplementedError):
    """The ref's scheme (vault:/kms:) is recognised but no client is wired here.

    Still a SecretRefError, so callers that catch that base class fail closed on this
    too instead of accidentally treating an unwired backend as a plain crash to ignore.
    """


def resolve(ref: str, *, env: dict[str, str] | None = None) -> str:
    """Resolve a `*_ref` string to its secret value.

    `env` defaults to `os.environ`; pass an explicit mapping in tests instead of
    mutating the real environment. Fails closed: every error path raises
    SecretRefError, there is no code path that returns None or "" for a bad ref.
    """
    if env is None:
        import os

        env = os.environ  # type: ignore[assignment]
    env = cast("dict[str, str]", env)  # narrows for mypy; always a mapping by this point

    if not isinstance(ref, str) or ref == "":
        raise SecretRefError("secret ref is empty or not a string")

    scheme, sep, rest = ref.partition(":")
    if not sep or not rest:
        # Bare name, no recognised "scheme:rest" shape -> treat the whole thing as an
        # env var name (backward-compatible default, same as Memaix's config.py).
        scheme, rest = "env", ref

    if scheme == "env":
        val = env.get(rest)
        if val is None:
            raise SecretRefError(f"secret ref not set in environment: {rest}")
        if val == "":
            raise SecretRefError(f"secret ref is set but empty in environment: {rest}")
        return val

    if scheme == "file":
        path = Path(rest)
        try:
            if not path.is_file():
                raise SecretRefError(f"secret file not found: {rest}")
            text = path.read_text()
        except (OSError, UnicodeDecodeError) as exc:
            raise SecretRefError(f"secret file could not be read: {rest}") from exc
        value = text.strip()
        if not value:
            raise SecretRefError(f"secret file is empty: {rest}")
        return value

    if scheme in _NOT_WIRED_SCHEMES:
        raise BackendNotWired(
            f"secret backend not wired in this library yet: {scheme} (ref scheme recognised, "
            "but no vault/kms client is configured here)"
        )

    raise SecretRefError(f"unknown secret ref scheme: {scheme!r} (use env:/file:/vault:/kms:)")


def resolve_optional(ref: str | None, *, env: dict[str, str] | None = None) -> str | None:
    """Like resolve(), but an absent reference (None or "") is a valid "not configured".

    Use this only for fields that are genuinely optional in the config schema. A field
    that IS set but points at a broken ref still fails closed via resolve().
    """
    if ref is None or ref == "":
        return None
    return resolve(ref, env=env)
