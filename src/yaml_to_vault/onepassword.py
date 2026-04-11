"""Resolve op:// references using the 1Password CLI (`op`)."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterable


class OnePasswordError(Exception):
    """Raised when the 1Password CLI fails or is unavailable."""


class OnePasswordResolver:
    """Resolve op:// references via `op read`. Caches results in-memory."""

    def __init__(self, op_binary: str = "op") -> None:
        self._op_binary = op_binary
        self._cache: dict[str, str] = {}
        self._checked = False

    def _ensure_available(self) -> None:
        if self._checked:
            return
        if shutil.which(self._op_binary) is None:
            raise OnePasswordError(
                f"1Password CLI '{self._op_binary}' not found in PATH. "
                "Install it from https://developer.1password.com/docs/cli/"
            )
        self._checked = True

    def resolve(self, ref: str) -> str:
        if ref in self._cache:
            return self._cache[ref]
        self._ensure_available()
        try:
            result = subprocess.run(
                [self._op_binary, "read", ref],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise OnePasswordError(f"Failed to invoke `op read {ref}`: {exc}") from exc

        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            raise OnePasswordError(
                f"`op read {ref}` failed (exit {result.returncode}): {stderr}"
            )

        value = result.stdout.rstrip("\n")
        self._cache[ref] = value
        return value

    def resolve_many(self, refs: Iterable[str]) -> dict[str, str]:
        return {ref: self.resolve(ref) for ref in dict.fromkeys(refs)}
