"""secretref — *_ref secret indirection + YAML config loading.

Extracted from the Memaix gateway's `config.py` (memaix/gateway/src/memaix_gateway/config.py,
see memaix/docs/SECRETS.md), which is the most mature pattern of this kind in the
jimlov-poc-labs portfolio. This library carries the same contract into Portis so the
family's five services (harvester, inbox, evidence, gate, smtp-guard, ...) can share one
secret-reference resolver instead of five hand-rolled ones.

Contract (unchanged from Memaix):
    A `*_ref` field in YAML config is a REFERENCE, never a value. It is resolved by prefix:
        env:NAME         -> environment variable NAME
        file:/path       -> file contents (Docker/systemd secrets, tmpfs), stripped
        vault:path#field -> OpenBao/HashiCorp Vault   [not wired here; raises NotImplementedError]
        kms:id           -> cloud KMS / Secret Manager [not wired here; raises NotImplementedError]
    A bare name with no recognised prefix is treated as `env:` (backward compatible with
    Memaix's existing on-disk configs).

Security rules (non-negotiable, see Definition of done):
    - Fail closed. A missing, empty, or unresolvable reference raises SecretRefError. It
      never falls back to a default value and never resolves to None silently.
    - Never log or print a resolved value. Nothing in this package calls logging, print,
      repr() on a resolved secret, or includes one in an exception message.
"""

from __future__ import annotations

from .refs import BackendNotWired, SecretRefError, resolve, resolve_optional
from .yamlconfig import load_yaml, resolve_refs_in

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SecretRefError",
    "BackendNotWired",
    "resolve",
    "resolve_optional",
    "load_yaml",
    "resolve_refs_in",
]
