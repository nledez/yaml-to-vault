"""Tests for the CLI commands via typer.testing.CliRunner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from yaml_to_vault.cli import app

runner = CliRunner()

ENV_YAML = """\
vault:
  address: http://127.0.0.1:8200
  token: op://V/I/token
"""

SECRET_YAML = """\
env: dev
documents:
  - path: app/db
    fields:
      username: op://V/I/username
      password: op://V/I/password
"""


def _setup(tmp_path: Path) -> Path:
    """Write env + secret files and return the secret file path."""
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    secret = tmp_path / "secret-app.yaml"
    secret.write_text(SECRET_YAML)
    return secret


def _mock_vault_client():
    """Return a mock that patches VaultClient.__init__ to skip real Vault."""
    mock_vc = MagicMock()
    mock_vc.mount = "secret"
    mock_vc.read.return_value = None  # all documents are new (CREATE)
    mock_vc.write.return_value = None
    mock_vc.read_policy.return_value = None
    mock_vc.write_policy.return_value = None
    return mock_vc


def _mock_op_resolver():
    mock_op = MagicMock()
    mock_op.resolve.side_effect = lambda ref: f"resolved-{ref}"
    return mock_op


# -- plan command --------------------------------------------------------


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_plan_shows_create(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["plan", str(secret)])
    assert result.exit_code == 0
    assert "CREATE" in result.output
    assert "secret/data/app/db" in result.output
    assert "username" in result.output
    assert "password" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_plan_show_secrets(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["plan", "--show-secrets", str(secret)])
    assert result.exit_code == 0
    assert "WARNING" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_plan_no_change(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    mock_vc.read.return_value = {
        "username": "resolved-op://V/I/username",
        "password": "resolved-op://V/I/password",
    }
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["plan", str(secret)])
    assert result.exit_code == 0
    assert "NO_CHANGE" in result.output


# -- apply command -------------------------------------------------------


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_apply_with_yes(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["apply", "--yes", str(secret)])
    assert result.exit_code == 0
    assert "CREATE" in result.output
    assert "✓" in result.output
    mock_vc.write.assert_called_once()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_apply_aborted(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["apply", str(secret)], input="n\n")
    assert result.exit_code == 1
    assert "Aborted" in result.output
    mock_vc.write.assert_not_called()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_apply_nothing_to_do(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    mock_vc.read.return_value = {
        "username": "resolved-op://V/I/username",
        "password": "resolved-op://V/I/password",
    }
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["apply", "--yes", str(secret)])
    assert result.exit_code == 0
    assert "Nothing to do" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_apply_write_error(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    from yaml_to_vault.vault_client import VaultClientError

    mock_vc.write.side_effect = VaultClientError("write failed")
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["apply", "--yes", str(secret)])
    assert result.exit_code == 1
    assert "write failed" in result.output


# -- apply with confirmed prompt ----------------------------------------


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_apply_confirmed(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = _setup(tmp_path)
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["apply", str(secret)], input="y\n")
    assert result.exit_code == 0
    assert "✓" in result.output
    mock_vc.write.assert_called_once()


# -- error handling ------------------------------------------------------


def test_plan_missing_file():
    result = runner.invoke(app, ["plan", "/nonexistent/file.yaml"])
    assert result.exit_code != 0


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_plan_config_error(mock_vc_cls, mock_op_cls, tmp_path: Path):
    secret = tmp_path / "secret-bad.yaml"
    secret.write_text("env: dev\ndocuments:\n  - path: x\n    fields:\n      k: op://V/I/f\n")
    # No env-dev.yaml → ConfigError
    result = runner.invoke(app, ["plan", str(secret)])
    assert result.exit_code == 1
    assert "not found" in result.output


# -- policy command ------------------------------------------------------


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_policy_create(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    hcl = tmp_path / "policy-test.hcl"
    hcl.write_text('path "secret/*" { capabilities = ["read"] }')
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["policy", "--env", "dev", "--yes", str(hcl)])
    assert result.exit_code == 0
    assert "CREATE" in result.output
    assert "test" in result.output
    assert "✓" in result.output
    mock_vc.write_policy.assert_called_once()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_policy_update_shows_diff(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    hcl = tmp_path / "policy-app.hcl"
    hcl.write_text('path "secret/*" { capabilities = ["read", "list"] }\n')
    mock_vc = _mock_vault_client()
    mock_vc.read_policy.return_value = 'path "secret/*" { capabilities = ["read"] }\n'
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["policy", "--env", "dev", "--yes", str(hcl)])
    assert result.exit_code == 0
    assert "UPDATE" in result.output
    assert "Diff" in result.output
    assert "list" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_policy_no_change(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    content = 'path "secret/*" { capabilities = ["read"] }\n'
    hcl = tmp_path / "policy-app.hcl"
    hcl.write_text(content)
    mock_vc = _mock_vault_client()
    mock_vc.read_policy.return_value = content
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["policy", "--env", "dev", "--yes", str(hcl)])
    assert result.exit_code == 0
    assert "Nothing to do" in result.output
    mock_vc.write_policy.assert_not_called()


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_policy_aborted(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    hcl = tmp_path / "policy-test.hcl"
    hcl.write_text('path "secret/*" { capabilities = ["read"] }')
    mock_vc = _mock_vault_client()
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["policy", "--env", "dev", str(hcl)], input="n\n")
    assert result.exit_code == 1
    assert "Aborted" in result.output
    mock_vc.write_policy.assert_not_called()


# -- apply error during _build ------------------------------------------


def test_apply_config_error(tmp_path: Path):
    secret = tmp_path / "secret-bad.yaml"
    secret.write_text("env: dev\ndocuments:\n  - path: x\n    fields:\n      k: op://V/I/f\n")
    result = runner.invoke(app, ["apply", "--yes", str(secret)])
    assert result.exit_code == 1
    assert "not found" in result.output


# -- policy error branches -----------------------------------------------


def test_policy_env_not_found(tmp_path: Path):
    hcl = tmp_path / "policy-test.hcl"
    hcl.write_text("content")
    # No env-dev.yaml → ConfigError in policy init
    result = runner.invoke(app, ["policy", "--env", "dev", "--yes", str(hcl)])
    assert result.exit_code == 1
    assert "not found" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_policy_read_error(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    hcl = tmp_path / "policy-test.hcl"
    hcl.write_text("content")
    mock_vc = _mock_vault_client()
    from yaml_to_vault.vault_client import VaultClientError

    mock_vc.read_policy.side_effect = VaultClientError("read boom")
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["policy", "--env", "dev", "--yes", str(hcl)])
    assert result.exit_code == 1
    assert "read boom" in result.output


@patch("yaml_to_vault.cli.OnePasswordResolver")
@patch("yaml_to_vault.cli.VaultClient")
def test_policy_write_error(mock_vc_cls, mock_op_cls, tmp_path: Path):
    (tmp_path / "env-dev.yaml").write_text(ENV_YAML)
    hcl = tmp_path / "policy-test.hcl"
    hcl.write_text("content")
    mock_vc = _mock_vault_client()
    from yaml_to_vault.vault_client import VaultClientError

    mock_vc.write_policy.side_effect = VaultClientError("write boom")
    mock_vc_cls.return_value = mock_vc
    mock_op = _mock_op_resolver()
    mock_op_cls.return_value = mock_op

    result = runner.invoke(app, ["policy", "--env", "dev", "--yes", str(hcl)])
    assert result.exit_code == 1
    assert "write boom" in result.output
