"""Tests for the policy command logic: vault_client.read_policy / write_policy,
and the HCL file → policy name derivation.
"""

from pathlib import Path

from hvac.exceptions import InvalidPath

from yaml_to_vault.vault_client import VaultClient


class FakeHvacSys:
    """Mimics hvac.Client.sys with policy read/write.

    Raises InvalidPath when a policy doesn't exist, matching the real
    hvac behavior (Vault returns HTTP 404 → hvac raises InvalidPath).
    """

    def __init__(self, policies: dict[str, str] | None = None) -> None:
        self._policies: dict[str, str] = dict(policies or {})
        self.written: list[tuple[str, str]] = []

    def read_policy(self, name: str) -> dict:
        if name not in self._policies:
            raise InvalidPath(f"policy {name!r} not found")
        return {"data": {"rules": self._policies[name]}}

    def create_or_update_policy(self, name: str, policy: str) -> None:
        self._policies[name] = policy
        self.written.append((name, policy))


class FakeHvacClient:
    def __init__(self, sys: FakeHvacSys) -> None:
        self.sys = sys

    def is_authenticated(self) -> bool:
        return True


def _make_vault_client(policies: dict[str, str] | None = None) -> VaultClient:
    """Build a VaultClient with a fake hvac backend (bypasses __init__)."""
    vc = VaultClient.__new__(VaultClient)
    fake_sys = FakeHvacSys(policies)
    vc._client = FakeHvacClient(fake_sys)  # type: ignore[assignment]
    vc._env = None  # type: ignore[assignment]
    return vc


# -- read_policy ---------------------------------------------------------


def test_read_policy_returns_none_when_missing():
    vc = _make_vault_client()
    assert vc.read_policy("nonexistent") is None


def test_read_policy_returns_rules():
    hcl = 'path "secret/*" { capabilities = ["read"] }'
    vc = _make_vault_client({"my-policy": hcl})
    assert vc.read_policy("my-policy") == hcl


# -- write_policy --------------------------------------------------------


def test_write_policy_creates():
    vc = _make_vault_client()
    hcl = 'path "secret/*" { capabilities = ["read"] }'
    vc.write_policy("new-policy", hcl)
    assert vc.read_policy("new-policy") == hcl


def test_write_policy_updates():
    old = 'path "secret/*" { capabilities = ["read"] }'
    new = 'path "secret/*" { capabilities = ["read", "list"] }'
    vc = _make_vault_client({"my-policy": old})
    vc.write_policy("my-policy", new)
    assert vc.read_policy("my-policy") == new


# -- policy name from filename -------------------------------------------


def _policy_name(filename: str) -> str:
    """Reproduce the CLI naming logic: stem without the 'policy-' prefix."""
    return Path(filename).stem.removeprefix("policy-")


def test_policy_name_strips_prefix():
    assert _policy_name("policy-dns-manager.hcl") == "dns-manager"
    assert _policy_name("policy-master-test.hcl") == "master-test"
    assert _policy_name("/some/dir/policy-app.hcl") == "app"


def test_policy_name_no_prefix():
    assert _policy_name("my-policy.hcl") == "my-policy"
    assert _policy_name("simple.hcl") == "simple"


# -- action detection logic (mirrors the CLI) ----------------------------


def _detect_action(current: str | None, desired: str) -> str:
    """Reproduce the same logic as the CLI policy command."""
    if current is None:
        return "CREATE"
    if current.strip() != desired.strip():
        return "UPDATE"
    return "NO_CHANGE"


def test_action_create():
    assert _detect_action(None, "policy {}") == "CREATE"


def test_action_update():
    assert _detect_action("old {}", "new {}") == "UPDATE"


def test_action_no_change():
    assert _detect_action("policy {}", "policy {}") == "NO_CHANGE"


def test_action_no_change_ignores_trailing_whitespace():
    assert _detect_action("policy {} \n", "policy {}\n\n") == "NO_CHANGE"


# -- diff rendering (mirrors the CLI) ------------------------------------


def _render_diff(current: str, desired: str, name: str = "test") -> str:
    """Reproduce the same diff logic as the CLI policy command."""
    import difflib

    diff_lines = difflib.unified_diff(
        current.splitlines(keepends=True),
        desired.splitlines(keepends=True),
        fromfile=f"vault:{name}",
        tofile=f"local:{name}",
    )
    return "".join(diff_lines)


def test_diff_shows_added_line():
    old = 'path "secret/*" {\n  capabilities = ["read"]\n}\n'
    new = 'path "secret/*" {\n  capabilities = ["read", "list"]\n}\n'
    diff = _render_diff(old, new)
    assert "vault:test" in diff
    assert "local:test" in diff
    assert '-  capabilities = ["read"]' in diff
    assert '+  capabilities = ["read", "list"]' in diff


def test_diff_shows_removed_line():
    old = 'path "secret/a" {\n  capabilities = ["read"]\n}\n\npath "secret/b" {\n  capabilities = ["list"]\n}\n'
    new = 'path "secret/a" {\n  capabilities = ["read"]\n}\n'
    diff = _render_diff(old, new)
    assert "-path" in diff or '- capabilities = ["list"]' in diff.replace(" ", "")


def test_diff_empty_when_identical():
    content = 'path "secret/*" {\n  capabilities = ["read"]\n}\n'
    diff = _render_diff(content, content)
    assert diff == ""


def test_diff_full_create():
    old = ""
    new = 'path "secret/*" {\n  capabilities = ["read"]\n}\n'
    diff = _render_diff(old, new)
    assert "+path" in diff.replace(" ", "")


def test_diff_multiline_change():
    old = (
        'path "secret/data/*" {\n'
        '  capabilities = ["create", "read"]\n'
        "}\n"
        "\n"
        'path "secret/metadata/*" {\n'
        '  capabilities = ["list"]\n'
        "}\n"
    )
    new = (
        'path "secret/data/*" {\n'
        '  capabilities = ["create", "read", "update", "delete"]\n'
        "}\n"
        "\n"
        'path "secret/metadata/*" {\n'
        '  capabilities = ["list", "read"]\n'
        "}\n"
    )
    diff = _render_diff(old, new)
    assert "update" in diff
    assert "delete" in diff
    assert '"list", "read"' in diff
