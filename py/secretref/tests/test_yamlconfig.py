"""Unit tests for secretref.yamlconfig. All secret values are obviously-fake fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from secretref import SecretRefError, load_yaml, resolve_refs_in


class TestLoadYaml:
    def test_loads_a_mapping(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text("service:\n  name: demo\n")
        assert load_yaml(cfg) == {"service": {"name": "demo"}}

    def test_missing_required_file_fails_closed(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_yaml(tmp_path / "nope.yaml")

    def test_missing_optional_file_returns_empty(self, tmp_path: Path) -> None:
        assert load_yaml(tmp_path / "nope.yaml", required=False) == {}

    def test_empty_required_file_fails_closed(self, tmp_path: Path) -> None:
        cfg = tmp_path / "empty.yaml"
        cfg.write_text("")
        with pytest.raises(SecretRefError):
            load_yaml(cfg)

    def test_non_mapping_top_level_fails_closed(self, tmp_path: Path) -> None:
        cfg = tmp_path / "list.yaml"
        cfg.write_text("- a\n- b\n")
        with pytest.raises(SecretRefError):
            load_yaml(cfg)

    def test_invalid_yaml_fails_closed(self, tmp_path: Path) -> None:
        cfg = tmp_path / "broken.yaml"
        cfg.write_text("service: [unterminated\n")
        with pytest.raises(SecretRefError):
            load_yaml(cfg)


class TestResolveRefsIn:
    def test_top_level_ref_is_resolved_and_original_kept(self) -> None:
        env = {"API_KEY": "fake-test-value-not-real-0010"}
        config = {"api_key_ref": "env:API_KEY", "name": "demo"}
        out = resolve_refs_in(config, env=env)
        assert out["api_key"] == "fake-test-value-not-real-0010"
        assert out["api_key_ref"] == "env:API_KEY"
        assert out["name"] == "demo"

    def test_nested_oauth_style_config_is_resolved(self) -> None:
        # Mirrors memaix.yaml's oauth_providers.{google,microsoft}.client_secret_ref.
        env = {
            "GOOGLE_CLIENT_SECRET": "fake-test-value-not-real-0011",
            "MS_CLIENT_SECRET": "fake-test-value-not-real-0012",
        }
        config = {
            "oauth_providers": {
                "google": {"client_id": "demo-id", "client_secret_ref": "env:GOOGLE_CLIENT_SECRET"},
                "microsoft": {
                    "client_id": "demo-id-2",
                    "client_secret_ref": "env:MS_CLIENT_SECRET",
                },
            }
        }
        out = resolve_refs_in(config, env=env)
        assert out["oauth_providers"]["google"]["client_secret"] == "fake-test-value-not-real-0011"
        assert (
            out["oauth_providers"]["microsoft"]["client_secret"] == "fake-test-value-not-real-0012"
        )
        # Non-ref sibling keys are untouched.
        assert out["oauth_providers"]["google"]["client_id"] == "demo-id"

    def test_refs_inside_lists_are_resolved(self) -> None:
        env = {"ONE": "fake-test-value-not-real-0013", "TWO": "fake-test-value-not-real-0014"}
        config = {"accounts": [{"token_ref": "env:ONE"}, {"token_ref": "env:TWO"}]}
        out = resolve_refs_in(config, env=env)
        assert out["accounts"][0]["token"] == "fake-test-value-not-real-0013"
        assert out["accounts"][1]["token"] == "fake-test-value-not-real-0014"

    def test_missing_target_env_var_fails_closed(self) -> None:
        config = {"api_key_ref": "env:NOT_SET_FAKE"}
        with pytest.raises(SecretRefError):
            resolve_refs_in(config, env={})

    def test_null_ref_value_fails_closed_instead_of_being_treated_as_absent(self) -> None:
        # A *_ref key that is present but null/empty is a config bug, not "not configured".
        # Omitting the key entirely is how "not configured" must be spelled.
        config = {"api_key_ref": None}
        with pytest.raises(SecretRefError):
            resolve_refs_in(config, env={})

    def test_non_string_ref_value_fails_closed(self) -> None:
        config = {"api_key_ref": 12345}
        with pytest.raises(SecretRefError):
            resolve_refs_in(config, env={})

    def test_custom_suffix_is_honoured(self) -> None:
        env = {"X": "fake-test-value-not-real-0015"}
        config = {"token__secret": "env:X"}
        out = resolve_refs_in(config, suffix="__secret", env=env)
        assert out["token"] == "fake-test-value-not-real-0015"

    def test_plaintext_sibling_after_ref_key_is_a_collision(self) -> None:
        # *_ref key first, then a plaintext key with the resolved name — must not let
        # the plaintext value silently overwrite the resolved secret.
        config = {"api_key_ref": "env:X", "api_key": "plaintext-should-never-win"}
        with pytest.raises(SecretRefError):
            resolve_refs_in(config, env={"X": "fake-test-value-not-real-0016"})

    def test_plaintext_sibling_before_ref_key_is_a_collision(self) -> None:
        # Same collision, opposite key order — must not depend on dict order.
        config = {"api_key": "plaintext-should-never-win", "api_key_ref": "env:X"}
        with pytest.raises(SecretRefError):
            resolve_refs_in(config, env={"X": "fake-test-value-not-real-0017"})

    def test_config_without_any_refs_is_unchanged(self) -> None:
        config = {"name": "demo", "nested": {"a": 1, "b": [1, 2, 3]}}
        assert resolve_refs_in(config, env={}) == config

    def test_ref_key_targeting_another_ref_key_is_a_collision(self) -> None:
        # "token_ref_ref" resolves to the name "token_ref" — the same name that
        # "token_ref" itself is a *_ref key for. The old check only excluded keys
        # that are themselves in ref_keys from plain_collisions, so a *_ref key
        # could still collide with ANOTHER *_ref key's target and leak its
        # resolved secret into a key the docs call safe to log. Must fail closed
        # in both key orders.
        env = {"A": "fake-test-value-not-real-0018"}
        config_order_1 = {"token_ref_ref": "env:A", "token_ref": "env:B"}
        with pytest.raises(SecretRefError):
            resolve_refs_in(config_order_1, env=env)

        config_order_2 = {"token_ref": "env:B", "token_ref_ref": "env:A"}
        with pytest.raises(SecretRefError):
            resolve_refs_in(config_order_2, env=env)
