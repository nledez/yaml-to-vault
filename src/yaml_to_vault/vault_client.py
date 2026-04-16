"""Thin wrapper around hvac for KV v2 read/write."""

from __future__ import annotations

import hvac
from hvac.exceptions import InvalidPath, VaultError

from .models import EnvironmentConfig
from .onepassword import OnePasswordResolver


class VaultClientError(Exception):
    """Raised when Vault interaction fails."""


class VaultClient:
    def __init__(self, env: EnvironmentConfig, op_resolver: OnePasswordResolver) -> None:
        self._env = env
        token = op_resolver.resolve(env.vault.token)
        # ca_path takes precedence: when set, it replaces the bool verify_tls.
        verify: bool | str = (
            env.vault.ca_path if env.vault.ca_path is not None else env.vault.verify_tls
        )
        proxies = (
            {"http": env.vault.proxy, "https": env.vault.proxy}
            if env.vault.proxy
            else None
        )
        self._client = hvac.Client(
            url=env.vault.address,
            token=token,
            namespace=env.vault.namespace,
            verify=verify,
            proxies=proxies,
        )
        try:
            authenticated = self._client.is_authenticated()
        except VaultError as exc:
            raise VaultClientError(f"Vault authentication check failed: {exc}") from exc
        if not authenticated:
            raise VaultClientError(
                f"Vault token resolved from {env.vault.token} is not valid for "
                f"{env.vault.address}"
            )

    @property
    def mount(self) -> str:
        return self._env.vault.mount

    def read(self, path: str) -> dict[str, str] | None:
        try:
            response = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount,
                raise_on_deleted_version=True,
            )
        except InvalidPath:
            return None
        except VaultError as exc:
            raise VaultClientError(f"Failed to read {self.mount}/{path}: {exc}") from exc
        return response["data"]["data"]

    def write(self, path: str, data: dict[str, str]) -> None:
        try:
            self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=self.mount,
            )
        except VaultError as exc:
            raise VaultClientError(f"Failed to write {self.mount}/{path}: {exc}") from exc

    def read_policy(self, name: str) -> str | None:
        try:
            result = self._client.sys.read_policy(name=name)
        except InvalidPath:
            return None
        except VaultError as exc:
            raise VaultClientError(f"Failed to read policy '{name}': {exc}") from exc
        if result is None:
            return None
        return result.get("data", {}).get("rules") or result.get("rules")

    def write_policy(self, name: str, policy: str) -> None:
        try:
            self._client.sys.create_or_update_policy(name=name, policy=policy)
        except VaultError as exc:
            raise VaultClientError(f"Failed to write policy '{name}': {exc}") from exc

    def read_role(self, name: str, jwt_mount: str) -> dict | None:
        """Read a JWT auth role at ``auth/<jwt_mount>/role/<name>``.

        Returns the ``data`` dict from the Vault response, or ``None`` if the
        role does not exist.
        """
        path = f"auth/{jwt_mount}/role/{name}"
        try:
            response = self._client.read(path)
        except InvalidPath:
            return None
        except VaultError as exc:
            raise VaultClientError(f"Failed to read role '{name}': {exc}") from exc
        if response is None:
            return None
        return response.get("data")

    def write_role(self, name: str, jwt_mount: str, data: dict) -> None:
        """Write a JWT auth role at ``auth/<jwt_mount>/role/<name>``.

        Equivalent to ``vault write auth/<jwt_mount>/role/<name> @<file>.json``.
        """
        path = f"auth/{jwt_mount}/role/{name}"
        try:
            self._client.write_data(path, data=data)
        except VaultError as exc:
            raise VaultClientError(f"Failed to write role '{name}': {exc}") from exc
