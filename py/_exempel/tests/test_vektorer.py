import json
from pathlib import Path
from typing import Any

import pytest

from exempel import strikt_port

_FIL = Path(__file__).resolve().parents[3] / "spec" / "_exempel" / "vektorer.json"
_FALL: list[dict[str, Any]] = json.loads(_FIL.read_text(encoding="utf-8"))["fall"]


@pytest.mark.parametrize("fall", _FALL, ids=[f["namn"] for f in _FALL])
def test_delad_testvektor(fall: dict[str, Any]) -> None:
    assert strikt_port(fall["in"]) == fall["ut"]


def test_vektorfilen_är_inte_tom() -> None:
    # Fail closed: en tom eller saknad vektorfil får inte ge ett grönt test.
    assert len(_FALL) >= 10
