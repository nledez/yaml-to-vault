"""Tests for VaultClient with a fully mocked hvac.Client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from hvac.exceptions import InvalidPath, VaultError

from yaml_to_vault.models import EnvironmentConfig
from yaml_to_vault.onepassword import OnePasswordResolver
from yaml_to_vault.vault_client import VaultClient, VaultClientError


def _env(ca_path: str | None = None) -> EnvironmentConfig:
    data: dict = {
        "vault": {
            "address": "http://127.0.0.1:8200",
            "token": "op://V/I/token",
        }
    }
    if ca_path is not None:
        data["vault"]["ca_path"] = ca_path
    return EnvironmentConfig.model_validate(data)


def _op_resolver() -> MagicMock:
    mock = MagicMock(spec=OnePasswordResolver)
    mock.resolve.return_value = "fake-token"
    return mock


# -- __init__ -----------------------------------------------------------


@patch("yaml_to_vault.vault_client.hvac.Client")
def test_init_success(mock_hvac_cls):
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_hvac_cls.return_value = mock_client

    vc = VaultClient(_env(), _op_resolver())

    mock_hvac_cls.assert_called_once_with(
        url="http://127.0.0.1:8200",
        token="fake-token",
        namespace=None,
        verify=True,
    )
    assert vc.mount == "secret"


@patch("yaml_to_vault.vault_client.hvac.Client")
def test_init_with_ca_path(mock_hvac_cls):
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_hvac_cls.return_value = mock_client

    VaultClient(_env(ca_path="/ca.pem"), _op_resolver())

    mock_hvac_cls.assert_called_once_with(
        url="http://127.0.0.1:8200",
        token="fake-token",
        namespace=None,
        verify="/ca.pem",
    )


@patch("yaml_to_vault.vault_client.hvac.Client")
def test_init_not_authenticated(mock_hvac_cls):
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = False
    mock_hvac_cls.return_value = mock_client

    with pytest.raises(VaultClientError, match="not valid"):
        VaultClient(_env(), _op_resolver())


@patch("yaml_to_vault.vault_client.hvac.Client")
def test_init_vault_error(mock_hvac_cls):
    mock_client = MagicMock()
    mock_client.is_authenticated.side_effect = VaultError("connection refused")
    mock_hvac_cls.return_value = mock_client

    with pytest.raises(VaultClientError, match="authentication check failed"):
        VaultClient(_env(), _op_resolver())


# -- helpers to build a VaultClient with mocked internals ----------------


def _make_vc(mock_client: MagicMock) -> VaultClient:
    vc = VaultClient.__new__(VaultClient)
    vc._client = mock_client
    vc._env = _env()
    return vc


# -- read ----------------------------------------------------------------


def test_read_success():
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"user": "alice", "pass": "s3cret"}}
    }
    vc = _make_vc(mock_client)
    result = vc.read("app/db")
    assert result == {"user": "alice", "pass": "s3cret"}


def test_read_not_found():
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.side_effect = InvalidPath()
    vc = _make_vc(mock_client)
    assert vc.read("missing") is None


def test_read_vault_error():
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.side_effect = VaultError("boom")
    vc = _make_vc(mock_client)
    with pytest.raises(VaultClientError, match="Failed to read"):
        vc.read("app/db")


# -- write ---------------------------------------------------------------


def test_write_success():
    mock_client = MagicMock()
    vc = _make_vc(mock_client)
    vc.write("app/db", {"key": "value"})
    mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
        path="app/db",
        secret={"key": "value"},
        mount_point="secret",
    )


def test_write_vault_error():
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.create_or_update_secret.side_effect = VaultError("denied")
    vc = _make_vc(mock_client)
    with pytest.raises(VaultClientError, match="Failed to write"):
        vc.write("app/db", {"key": "value"})


# -- read_policy ---------------------------------------------------------


def test_read_policy_success():
    mock_client = MagicMock()
    mock_client.sys.read_policy.return_value = {
        "data": {"rules": 'path "secret/*" {}'}
    }
    vc = _make_vc(mock_client)
    assert vc.read_policy("my-policy") == 'path "secret/*" {}'


def test_read_policy_not_found():
    mock_client = MagicMock()
    mock_client.sys.read_policy.side_effect = InvalidPath()
    vc = _make_vc(mock_client)
    assert vc.read_policy("missing") is None


def test_read_policy_vault_error():
    mock_client = MagicMock()
    mock_client.sys.read_policy.side_effect = VaultError("forbidden")
    vc = _make_vc(mock_client)
    with pytest.raises(VaultClientError, match="Failed to read policy"):
        vc.read_policy("my-policy")


def test_read_policy_returns_none_when_result_is_none():
    mock_client = MagicMock()
    mock_client.sys.read_policy.return_value = None
    vc = _make_vc(mock_client)
    assert vc.read_policy("empty") is None


def test_read_policy_fallback_to_rules_key():
    mock_client = MagicMock()
    mock_client.sys.read_policy.return_value = {"rules": 'path "kv/*" {}'}
    vc = _make_vc(mock_client)
    assert vc.read_policy("alt") == 'path "kv/*" {}'


# -- write_policy --------------------------------------------------------


def test_write_policy_success():
    mock_client = MagicMock()
    vc = _make_vc(mock_client)
    vc.write_policy("my-policy", "content")
    mock_client.sys.create_or_update_policy.assert_called_once_with(
        name="my-policy", policy="content"
    )


def test_write_policy_vault_error():
    mock_client = MagicMock()
    mock_client.sys.create_or_update_policy.side_effect = VaultError("denied")
    vc = _make_vc(mock_client)
    with pytest.raises(VaultClientError, match="Failed to write policy"):
        vc.write_policy("my-policy", "content")
