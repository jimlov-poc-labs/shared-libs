# secretref

`*_ref` secret indirection + YAML config loading. Fail closed: a missing, empty,
unresolvable, or malformed reference always raises — never a silent `None`/`""`.

A service's config carries a *reference*, never a value:

```yaml
oauth_providers:
  google:
    client_id: "demo-id"
    client_secret_ref: "env:GOOGLE_CLIENT_SECRET"
smtp:
  password_ref: "file:/run/secrets/smtp_password"
```

```python
from pathlib import Path
from secretref import load_yaml, resolve_refs_in

config = resolve_refs_in(load_yaml(Path("config.yaml")))
client_secret = config["oauth_providers"]["google"]["client_secret"]  # resolved value
```

## Prefixes

| Prefix | Source | Status |
|---|---|---|
| `env:NAME` (or a bare name, no prefix) | environment variable, used verbatim (not stripped) | wired |
| `file:/path` | file contents, stripped (Docker/systemd secrets, tmpfs) | wired |
| `vault:path#field` | OpenBao / HashiCorp Vault | recognised, raises `BackendNotWired` (a `SecretRefError` that is also a `NotImplementedError`) — no client wired here |
| `kms:id` | cloud KMS / Secret Manager | recognised, raises `BackendNotWired` — no client wired here |

`file:` is stripped and `env:` is not — deliberately, not an oversight. A secret file
written by a human or a text editor routinely picks up a trailing newline that is never
part of the actual secret, so stripping it is a correctness fix, not data loss. An
environment variable is set by the deployment system, not hand-edited, so there is no
equivalent "obviously not part of the value" whitespace to strip — and silently
stripping it risks quietly altering a secret that is legitimately whitespace or has
significant leading/trailing characters.

## Functions and their failure shapes

- `resolve(ref, *, env=None) -> str`: resolve a single `*_ref` string. `env` defaults
  to `os.environ`; pass an explicit mapping in tests.
- `resolve_optional(ref, *, env=None) -> str | None`: like `resolve`, but `None`/`""`
  is a valid "not configured" — a *present but broken* ref still raises.
- `load_yaml(path, *, required=True) -> dict`: read a YAML file's top-level mapping.
  **Raises `FileNotFoundError`** (not `SecretRefError`) for a missing *required* file —
  a port must preserve this distinction, since a caller may catch the two differently.
  `required=False` returns `{}` for a missing file instead.
- `resolve_refs_in(config, *, suffix="_ref", env=None) -> dict`: walk a config tree
  (dicts and lists) and resolve every `<name>{suffix}` key to `<name>`, keeping the
  original `*_ref` key alongside the resolved one.

`BackendNotWired` subclasses **both** `SecretRefError` and `NotImplementedError`: a
caller that only catches the fail-closed base class (`SecretRefError`) still fails
closed on an unwired backend instead of getting an uncaught crash, while a caller that
checks for `NotImplementedError` specifically (e.g. to say "not built yet" vs. "bad
input") can still do so.

## Säkerhetsregler

- **Fail closed.** A missing, empty, or unresolvable `*_ref` raises `SecretRefError`
  (or `BackendNotWired` for the two unwired backends). There is no code path that
  returns `None`/`""` for a broken reference — only `resolve_optional()` treats a truly
  *absent* reference (`None` or `""`) as "not configured"; a present-but-broken one
  still raises even through that function.
- **Never logs or prints a resolved value.** No `logging`, `print`, or value
  interpolation into an exception message anywhere in this package. Error messages name
  the *reference* (e.g. `env:GOOGLE_CLIENT_SECRET`) or the scheme, never the secret.
  `test_resolve_never_prints_or_logs_a_resolved_value` in `test_refs.py` enforces this;
  a port must carry an equivalent test.
- **Config loading fails closed too.** `load_yaml()` raises on a missing file by
  default; `required=False` is only for a genuinely optional overlay (e.g. a local dev
  override), never a service's primary config file.
- **`*_ref` fields must NEVER contain plaintext.** If one does by misconfiguration
  (e.g. someone pastes the actual secret into `password_ref` instead of
  `env:PASSWORD`), the unresolved string is echoed verbatim in the resulting
  `SecretRefError` message (e.g. `secret ref not set in environment: <that string>`),
  and it also survives into `resolve_refs_in`'s output because the original `*_ref`
  key is kept alongside the resolved one. That exception/output can reach stderr,
  application logs, or a debug dump via caller code this library does not control.
  There is no way to tell "this is a broken reference string" apart from "this happens
  to be a secret" from inside the library, so it cannot detect or guard against this —
  the field must simply never hold plaintext in the first place. This is a known,
  accepted limitation (confirmed across three review rounds on the original code in
  portis), not something the move introduced or is expected to fix.

## Avdelningar i vektorer.json

- `prefix_parsning`: `{ref, klass, rest}`. Given a `*_ref` string, which scheme it is
  classified into and what the "rest" portion (the part after the first `:`) is.
  `klass` is one of `env`, `not_wired`, `unknown`. This is the one part of
  `resolve()`'s behaviour that is a genuinely pure function of the input string: it
  does not touch the environment or the filesystem to determine *which branch* a ref
  takes. The vectors prove classification by observable outcome without needing real
  secrets:
  - `env` vectors are proven without any I/O side effect mattering: resolution
    succeeds given `env={rest: <any sentinel>}`, which proves both the scheme AND the
    extracted `rest` in one assertion (the returned value IS the sentinel).
  - `not_wired` vectors assert `BackendNotWired` is raised — the type alone is the
    signal, no message inspection needed.
  - `unknown` vectors assert a plain `SecretRefError` is raised that is **not**
    `BackendNotWired`.
  - Parsing is **not** keyed to any particular exception message text — messages are
    not a cross-language contract here (unlike ssrf_fetch's stable error codes,
    secretref has no error-code enum). Only the exception *type* and, where
    applicable, the *resolved value*, are the actual contract.
  - `file:` classification is deliberately **not** vectorized here, even though it is
    conceptually the same parsing step: proving it needs a real filesystem check
    (`Path.is_file()`), which is a side effect, not a pure function of the input
    string. It stays a `test_refs.py` pytest case (`TestFileScheme`), alongside the
    rest of `file:`'s actual-file-content behaviour.
  - Several entries exist specifically to pin down surprising-but-real edge cases of
    `ref.partition(":")`-based parsing, so a port reproduces them rather than "fixing"
    them: only the **first** colon splits (`"env:A:B"` → rest `"A:B"`); an empty rest
    (`"env:"`, `"file:"`, `"vault:"`, `"kms:"`) falls back to treating the **whole
    original string** as a bare env-var name — so `"vault:"` resolves as `env`, it
    does **not** raise `BackendNotWired`; an empty scheme (`":foo"`) is `unknown`;
    scheme matching is case-sensitive (`"ENV:FOO"` is `unknown`, not `env`). These are
    documented as current behaviour, not asserted as good design — if they ever bite
    in practice, revisit; until then a port must match them exactly.

- `krockdetektion`: `{nycklar, suffix?, kolliderar}`. Given an ordered list of
  `[key, value]` pairs (an **ordered list, not a JSON object** — key order is part of
  what is being proven, and some test cases would be indistinguishable if the two
  orderings of the same keys collapsed to the same object), does `resolve_refs_in`
  raise a same-target-name collision? `value` is either a plain string (a plaintext
  value, or an `"env:NAME"` reference string to be resolved) or itself a list of
  `[key, value]` pairs, denoting a nested mapping at that key (covers the "one nested
  collision" case). `suffix` defaults to `"_ref"` when omitted. When `kolliderar` is
  `false`, every `*_ref` value in the case must be resolvable (the test supplies an
  `env` mapping covering every `env:NAME` reference used), so a false-negative ("no
  collision raised, but only because resolution itself failed first") can't hide
  behind a green test.

## What is covered by vectors vs. by pytest fixtures only

`resolve()`'s and `load_yaml()`'s *full* resolution paths — actually reading an
environment variable's value, actually reading file contents off disk, actually
parsing a YAML document — are **not** expressed as `vektorer.json` entries, even
though `resolve_refs_in`'s tests (in `py/secretref/tests/test_yamlconfig.py`) exercise
them indirectly. The reason is structural, not laziness: a static JSON vector is data
describing a pure input → output mapping. Reading `os.environ` or the filesystem are
side effects whose actual values depend on what the test harness sets up (a `tmp_path`
fixture, an injected `env` dict), not on anything expressible as a JSON literal in a
shared contract file. Forcing them into `vektorer.json` would mean either baking
fake filesystem paths into the contract (meaningless across languages/OSes) or
re-inventing a fixture-description mini-language that pytest's own fixtures already
solve better. These stay as ordinary pytest tests in `py/secretref/tests/`:
- `test_refs.py`: env/file resolution success and failure paths (missing/empty var,
  missing/empty/non-UTF-8/directory-instead-of-file), that a resolved value is never
  printed/logged/leaked into an unrelated error message.
- `test_yamlconfig.py`: `load_yaml`'s file-reading and YAML-parsing failure shapes
  (missing required/optional file, empty file, non-mapping top level, invalid YAML),
  and `resolve_refs_in`'s end-to-end resolution (top-level, nested, inside lists,
  custom suffix) layered on top of the already-vectorized collision detection.

A future TypeScript port must match the pytest-only behaviour too, even though it has
no `vektorer.json` entries for it — this README is the contract for that part, the
vectors are the contract for the two pure-function parts above.
