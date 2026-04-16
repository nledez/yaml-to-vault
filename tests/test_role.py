"""Tests for the role command logic: VaultClient.read_role / write_role,
the JSON file → role name derivation, and the action-detection rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from yaml_to_vault.cli import RoleAction, _detect_role_action, app

runner = CliRunner()

ENV_YAML = """\
vault:
  address: http://127.0.0.1:8200
  token: op://V/I/token
"""

ENV_YAML_CUSTOM_MOUNT = """\
vault:
  address: http://127.0.0.1:8200
  token: op://V/I/token
  jwt_mount: jwt-custom
"""


def _mock_vault_client() -> MagicMock:
    mock_vc = MagicMock()
    mock_vc.mount = "secret"
    mock_vc.read_role.return_value = None
    mock_vc.write_role.return_value = None
    return mock_vc


def _mock_op_resolver() -> MagicMock:
    mock_op = MagicMock()
    mock_op.resolve.side_effect = lambda ref: f"resolved-{ref}"
    return mock_op


# -- role name derivation -------------------------------------------------


def _role_name(filename: str) -> str:
    return Path(filename).stem.removeprefix("role-")


def test_role_name_strips_prefix():
    assert _role_name("role-my-app.json") == "my-app"
    assert _role_name("role-api-service.json") == "api-service"
    assert _role_name("/some/dir/role-web.json") == "web"


def test_role_name_no_prefix():
    assert _role_name("my-app.json") == "my-app"
    assert _role_name("simple.json") == "simple"


# -- _detect_role_action --------------------------------------------------


def test_action_create_when_role_missing():
    assert _detect_role_action(None, {"role_type": "jwt"}) is RoleAction.CREATE


def test_action_update_when_key_differs():
    current = {"role_type": "jwt", "user_claim": "sub"}
    desired = {"role_type": "jwt", "user_claim": "email"}
    assert _detect_role_action(current, desired) is RoleAction.UPDATE


def test_action_update_when_key_missing_in_current():
    current = {"role_type": "jwt"}
    desired = {"role_type": "jwt", "user_claim": "sub"}
    assert _detect_role_action(current, desired) is RoleAction.UPDATE


def test_action_no_change_ignores_drift():
    # extra keys in current (drift) are ignored
    current = {"role_type": "jwt", "user_claim": "sub", "token_ttl": 3600}
    desired = {"role_type": "jwt", "user_claim": "sub"}
    assert _detect_role_action(current, desired) is RoleAction.NO_CHANGE


def test_action_no_change_on_lists():
    current = {"bound_audiences": ["vault", "nomad"]}
    desired = {"bound_audiences": ["vault", "nomad"]}
    assert _detect_role_action(current, desired) is RoleAction.NO_CHANGE


# -- CLI: role command ----------------------------------------------------


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_create(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt", "user_claim": "sub"}))
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 0, result.output
    assert "CREATE" in result.output
    assert "my-app" in result.output
    assert "auth/jwt-nomad/role/my-app" in result.output
    assert "✓" in result.output
    mock_vc.write_role.assert_called_once_with(
        "my-app", "jwt-nomad", {"role_type": "jwt", "user_claim": "sub"}
    )


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_update_shows_diff(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt", "user_claim": "email"}))
    mock_vc = _mock_vault_client()
    mock_vc.read_role.return_value = {"role_type": "jwt", "user_claim": "sub"}
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 0, result.output
    assert "UPDATE" in result.output
    assert "Diff" in result.output
    assert "email" in result.output
    mock_vc.write_role.assert_called_once()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_no_change(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    payload = {"role_type": "jwt", "user_claim": "sub"}
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps(payload))
    mock_vc = _mock_vault_client()
    # Vault returns extra drift fields — they must be ignored.
    mock_vc.read_role.return_value = {**payload, "token_ttl": 3600}
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 0, result.output
    assert "NO_CHANGE" in result.output
    assert "Nothing to do" in result.output
    mock_vc.write_role.assert_not_called()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_aborted(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt"}))
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", str(role)], input="n\n")
    assert result.exit_code == 1
    assert "Aborted" in result.output
    mock_vc.write_role.assert_not_called()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_confirmed(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt"}))
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", str(role)], input="y\n")
    assert result.exit_code == 0, result.output
    assert "✓" in result.output
    mock_vc.write_role.assert_called_once()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_uses_custom_jwt_mount(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML_CUSTOM_MOUNT)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt"}))
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 0, result.output
    assert "auth/jwt-custom/role/my-app" in result.output
    mock_vc.read_role.assert_called_once_with("my-app", "jwt-custom")
    mock_vc.write_role.assert_called_once_with(
        "my-app", "jwt-custom", {"role_type": "jwt"}
    )


# -- error paths ----------------------------------------------------------


def test_role_env_not_found(tmp_path: Path):
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt"}))
    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_role_invalid_json(tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text("{not json")
    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 1
    assert "Invalid JSON" in result.output


def test_role_json_not_object(tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps(["not", "an", "object"]))
    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 1
    assert "must be an object" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_read_error(mock_vc_cls, mock_op_cls, tmp_path: Path):
    from yaml_to_vault.vault_client import VaultClientError

    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt"}))
    mock_vc = _mock_vault_client()
    mock_vc.read_role.side_effect = VaultClientError("read boom")
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 1
    assert "read boom" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_write_error(mock_vc_cls, mock_op_cls, tmp_path: Path):
    from yaml_to_vault.vault_client import VaultClientError

    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    role = tmp_path / "role-my-app.json"
    role.write_text(json.dumps({"role_type": "jwt"}))
    mock_vc = _mock_vault_client()
    mock_vc.write_role.side_effect = VaultClientError("write boom")
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(app, ["role", "--env", "dev", "--yes", str(role)])
    assert result.exit_code == 1
    assert "write boom" in result.output


# -- multiple files -------------------------------------------------------


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_role_multiple_files(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    r1 = tmp_path / "role-app1.json"
    r1.write_text(json.dumps({"role_type": "jwt"}))
    r2 = tmp_path / "role-app2.json"
    r2.write_text(json.dumps({"role_type": "jwt"}))
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op_cls.return_value = _mock_op_resolver()

    result = runner.invoke(
        app, ["role", "--env", "dev", "--yes", str(r1), str(r2)]
    )
    assert result.exit_code == 0, result.output
    assert "app1" in result.output
    assert "app2" in result.output
    assert mock_vc.write_role.call_count == 2
