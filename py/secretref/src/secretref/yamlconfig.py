"""Load a YAML config file and resolve its `*_ref` fields.

See secretref/__init__.py for the contract. This module has no Memaix dependency: it
only needs PyYAML and the stdlib.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

from .refs import SecretRefError, resolve


def load_yaml(path: Path | str, *, required: bool = True) -> dict[str, Any]:
    """Read a YAML file and return its top-level mapping.

    Fails closed by default: a missing file raises FileNotFoundError and a file whose
    top-level content is not a mapping (or is empty/unparseable to a mapping) raises
    SecretRefError, because a config loader that silently returns {} for a typo'd path
    is exactly the kind of "missing input treated as pass" the Definition of done
    forbids. Pass `required=False` only for a genuinely optional overlay file (e.g. a
    local dev override) where "file absent" is a real, intended case — not for the
    primary config file of a service.
    """
    p = Path(path)
    if not p.is_file():
        if required:
            raise FileNotFoundError(f"config file not found: {p}")
        return {}

    try:
        loaded = yaml.safe_load(p.read_text())
    except yaml.YAMLError as exc:
        raise SecretRefError(f"config file is not valid YAML: {p}") from exc

    if loaded is None:
        if required:
            raise SecretRefError(f"config file is empty: {p}")
        return {}

    if not isinstance(loaded, dict):
        raise SecretRefError(f"config file does not contain a YAML mapping at top level: {p}")

    return loaded


def resolve_refs_in(
    config: dict[str, Any],
    *,
    suffix: str = "_ref",
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return a copy of `config` with every `<name>{suffix}` key resolved to `<name>`.

    Walks nested dicts and lists (e.g. `oauth_providers.google.client_secret_ref` ->
    adds `oauth_providers.google.client_secret`), so one call covers a whole config
    tree, not just the top level. The original `*_ref` key is kept alongside the
    resolved one (it is a pointer string like "env:FOO", not a secret, so keeping it is
    safe and useful for debugging).

    Fails closed: any key ending in `suffix` whose value is not a non-empty string is
    treated as a broken reference and raises SecretRefError — there is no silent
    None/"" result for a present-but-malformed `*_ref` key. Resolution of any ref
    anywhere in the tree raises immediately (no partial result, no swallowed errors).
    """
    return cast(dict[str, Any], _walk(config, suffix, env))


def _walk(node: Any, suffix: str, env: dict[str, str] | None) -> Any:
    if isinstance(node, dict):
        ref_keys = [
            key for key in node if isinstance(key, str) and key.endswith(suffix) and key != suffix
        ]
        resolved_bases = {key[: -len(suffix)] for key in ref_keys}
        # A plain key that collides with a *_ref key's target name is a config bug,
        # whichever order the keys appear in: the config must hold a reference OR a
        # plaintext value for that name, never both ("the config holds a reference,
        # never a value" — a sibling plaintext key would silently win or lose
        # depending on dict order, which is exactly the kind of order-dependent,
        # fail-open behaviour the Definition of done forbids).
        plain_collisions = sorted(key for key in node if key in resolved_bases)
        if plain_collisions:
            raise SecretRefError(
                f"both a plaintext key and a {suffix} key resolve to the same name: "
                f"{plain_collisions}"
            )

        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in ref_keys:
                if not isinstance(value, str) or value == "":
                    raise SecretRefError(
                        f"broken secret ref at key {key!r}: expected a non-empty string, "
                        f"got {type(value).__name__}"
                    )
                resolved_key = key[: -len(suffix)]
                out[key] = value
                out[resolved_key] = resolve(value, env=env)
            else:
                out[key] = _walk(value, suffix, env)
        return out
    if isinstance(node, list):
        return [_walk(item, suffix, env) for item in node]
    return node
