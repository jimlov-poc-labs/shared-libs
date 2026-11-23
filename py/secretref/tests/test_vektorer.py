"""Kör de delade testvektorerna i spec/secretref/vektorer.json.

Se spec/secretref/README.md för varför bara prefix_parsning och krockdetektion är
vektoriserade: resolve()s och load_yaml()s fulla sidoeffektsflöden (riktig
miljö/filsystem) testas i stället i test_refs.py / test_yamlconfig.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from secretref import SecretRefError
from secretref.refs import BackendNotWired, resolve
from secretref.yamlconfig import resolve_refs_in

_FIL = Path(__file__).resolve().parents[3] / "spec" / "secretref" / "vektorer.json"
_V: dict[str, Any] = json.loads(_FIL.read_text(encoding="utf-8"))


def _ids(key: str) -> list[str]:
    return [str(f["namn"]) for f in _V[key]]


def test_vektorfilen_ar_inte_tom() -> None:
    # Fail closed: en tom eller saknad avdelning får inte ge ett grönt test.
    assert len(_V["prefix_parsning"]) >= 10
    assert len(_V["krockdetektion"]) >= 5


@pytest.mark.parametrize("fall", _V["prefix_parsning"], ids=_ids("prefix_parsning"))
def test_prefix_parsning(fall: dict[str, Any]) -> None:
    ref = fall["ref"]
    rest = fall["rest"]
    klass = fall["klass"]

    if klass == "env":
        sentinel = "sentinel-for-" + fall["namn"]
        assert resolve(ref, env={rest: sentinel}) == sentinel
    elif klass == "not_wired":
        with pytest.raises(BackendNotWired):
            resolve(ref, env={})
    elif klass == "unknown":
        with pytest.raises(SecretRefError) as exc_info:
            resolve(ref, env={})
        assert not isinstance(exc_info.value, BackendNotWired)
    else:  # pragma: no cover - fail closed on an unrecognised vector shape
        pytest.fail(f"okänd klass i vektorfilen: {klass!r}")


def _to_mapping(pairs: list[list[Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if isinstance(value, list):
            out[key] = _to_mapping(value)
        else:
            out[key] = value
    return out


def _env_for(pairs: list[list[Any]], suffix: str, env: dict[str, str]) -> None:
    for key, value in pairs:
        if isinstance(value, list):
            _env_for(value, suffix, env)
        elif key.endswith(suffix) and key != suffix and isinstance(value, str):
            scheme, sep, rest = value.partition(":")
            if sep and scheme == "env" and rest:
                env[rest] = "sentinel-for-" + rest


@pytest.mark.parametrize("fall", _V["krockdetektion"], ids=_ids("krockdetektion"))
def test_krockdetektion(fall: dict[str, Any]) -> None:
    suffix = fall.get("suffix", "_ref")
    config = _to_mapping(fall["nycklar"])
    env: dict[str, str] = {}
    _env_for(fall["nycklar"], suffix, env)

    if fall["kolliderar"]:
        with pytest.raises(SecretRefError):
            resolve_refs_in(config, suffix=suffix, env=env)
    else:
        # Får inte svälja ett verkligt upplösningsfel som om det var "ingen krock".
        resolve_refs_in(config, suffix=suffix, env=env)
