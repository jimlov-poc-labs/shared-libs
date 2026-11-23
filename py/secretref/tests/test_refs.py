"""Unit tests for secretref.refs. All values below are obviously-fake test fixtures,
never real credentials."""

from __future__ import annotations

from pathlib import Path

import pytest

from secretref import SecretRefError, resolve, resolve_optional


class TestEnvScheme:
    def test_env_ref_resolves_from_given_mapping(self) -> None:
        env = {"FAKE_API_KEY": "fake-test-value-not-real-0001"}
        assert resolve("env:FAKE_API_KEY", env=env) == "fake-test-value-not-real-0001"

    def test_bare_name_defaults_to_env_scheme(self) -> None:
        env = {"BARE_NAME": "fake-test-value-not-real-0002"}
        assert resolve("BARE_NAME", env=env) == "fake-test-value-not-real-0002"

    def test_missing_env_var_fails_closed(self) -> None:
        with pytest.raises(SecretRefError):
            resolve("env:DOES_NOT_EXIST_FAKE", env={})

    def test_empty_env_var_fails_closed(self) -> None:
        with pytest.raises(SecretRefError):
            resolve("env:SET_BUT_EMPTY_FAKE", env={"SET_BUT_EMPTY_FAKE": ""})


class TestFileScheme:
    def test_file_ref_resolves_and_strips_whitespace(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "fake_secret"
        secret_file.write_text("fake-test-value-not-real-0003\n")
        assert resolve(f"file:{secret_file}") == "fake-test-value-not-real-0003"

    def test_missing_file_fails_closed(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        with pytest.raises(SecretRefError):
            resolve(f"file:{missing}")

    def test_empty_file_fails_closed(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty_secret"
        empty.write_text("")
        with pytest.raises(SecretRefError):
            resolve(f"file:{empty}")

    def test_directory_instead_of_file_fails_closed(self, tmp_path: Path) -> None:
        with pytest.raises(SecretRefError):
            resolve(f"file:{tmp_path}")

    def test_invalid_utf8_file_fails_closed_as_secretreferror(self, tmp_path: Path) -> None:
        # UnicodeDecodeError inherits from ValueError, not OSError, so the old
        # `except OSError` let it escape as a raw UnicodeDecodeError instead of the
        # SecretRefError the docstring/README promise for every error path here.
        bad_file = tmp_path / "invalid_utf8_secret"
        bad_file.write_bytes(b"\xff\xfe\x00invalid-utf8-bytes")
        with pytest.raises(SecretRefError):
            resolve(f"file:{bad_file}")


class TestUnwiredSchemes:
    def test_vault_scheme_is_recognised_but_not_wired(self) -> None:
        with pytest.raises(NotImplementedError):
            resolve("vault:portis/smtp#password")

    def test_kms_scheme_is_recognised_but_not_wired(self) -> None:
        with pytest.raises(NotImplementedError):
            resolve("kms:projects/fake/secrets/fake")

    def test_unwired_backend_is_still_a_secretreferror(self) -> None:
        # A caller that only catches SecretRefError (the fail-closed base class) must
        # still fail closed on an unwired backend, not get an uncaught crash.
        with pytest.raises(SecretRefError):
            resolve("vault:portis/smtp#password")


class TestBrokenInput:
    def test_unknown_scheme_fails_closed(self) -> None:
        with pytest.raises(SecretRefError):
            resolve("ldap:fake")

    def test_empty_ref_fails_closed(self) -> None:
        with pytest.raises(SecretRefError):
            resolve("")

    def test_none_ref_fails_closed(self) -> None:
        with pytest.raises(SecretRefError):
            resolve(None)  # type: ignore[arg-type]


class TestResolveOptional:
    def test_none_is_a_valid_not_configured(self) -> None:
        assert resolve_optional(None) is None

    def test_empty_string_is_a_valid_not_configured(self) -> None:
        assert resolve_optional("") is None

    def test_present_ref_still_resolves(self) -> None:
        env = {"OPTIONAL_FAKE": "fake-test-value-not-real-0004"}
        assert resolve_optional("env:OPTIONAL_FAKE", env=env) == "fake-test-value-not-real-0004"

    def test_present_but_broken_ref_still_fails_closed(self) -> None:
        with pytest.raises(SecretRefError):
            resolve_optional("env:MISSING_FAKE", env={})


def test_resolve_never_prints_or_logs_a_resolved_value(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    env = {"FAKE_LOUD_KEY": "fake-test-value-not-real-0005"}
    value = resolve("env:FAKE_LOUD_KEY", env=env)
    assert value == "fake-test-value-not-real-0005"

    captured = capsys.readouterr()
    assert "fake-test-value-not-real-0005" not in captured.out
    assert "fake-test-value-not-real-0005" not in captured.err
    assert "fake-test-value-not-real-0005" not in caplog.text


def test_resolved_value_never_appears_in_a_failure_message_for_a_different_ref() -> None:
    # Even when some other secret is resolvable in the same environment, a failure
    # about a DIFFERENT ref must never echo that unrelated value.
    env = {"SET_BUT_UNUSED": "fake-test-value-not-real-0006"}
    try:
        resolve("env:OTHER_NAME", env=env)
    except SecretRefError as exc:
        assert "fake-test-value-not-real-0006" not in str(exc)
    else:
        pytest.fail("expected SecretRefError")
