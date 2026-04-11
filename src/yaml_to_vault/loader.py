"""Load and validate YAML files into Pydantic models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from .models import Document, EnvironmentConfig, SecretsFile


class ConfigError(Exception):
    """Raised when a YAML file is missing, malformed, or fails validation."""


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        raise ConfigError(f"File not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if data is None:
        raise ConfigError(f"Empty YAML file: {path}")
    if not isinstance(data, dict):
        raise ConfigError(f"Top-level YAML in {path} must be a mapping")
    return data


def load_environment(name: str, search_dir: Path) -> EnvironmentConfig:
    """Load env-<name>.yaml from ``search_dir``."""
    path = search_dir / f"env-{name}.yaml"
    data = _read_yaml(path)
    try:
        return EnvironmentConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid environment file {path}:\n{exc}") from exc


def load_secrets_file(path: Path) -> SecretsFile:
    """Load a single secrets YAML file."""
    data = _read_yaml(path)
    try:
        return SecretsFile.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid secrets file {path}:\n{exc}") from exc


@dataclass
class LoadedInputs:
    env_name: str
    environment: EnvironmentConfig
    documents: list[Document]


def load_inputs(secret_files: list[Path]) -> LoadedInputs:
    """Load secret files, ensure they target a single environment, and load it.

    - Each secret file declares ``env: <name>`` at the top.
    - All files must declare the same environment.
    - For every distinct parent directory among the secret files, ``env-<name>.yaml``
      is loaded; all loaded environments must be identical.
    - Duplicate Vault paths across files are rejected.
    """
    if not secret_files:
        raise ConfigError("At least one secret file is required.")

    loaded: list[tuple[Path, SecretsFile]] = []
    for path in secret_files:
        loaded.append((path, load_secrets_file(path)))

    env_names = {sf.env for _, sf in loaded}
    if len(env_names) > 1:
        listing = ", ".join(
            f"{p} → env={sf.env}" for p, sf in loaded
        )
        raise ConfigError(
            "All secret files must target the same environment, got: " + listing
        )
    env_name = env_names.pop()

    env_config: EnvironmentConfig | None = None
    env_source: Path | None = None
    seen_dirs: set[Path] = set()
    for path, _ in loaded:
        parent = path.parent.resolve()
        if parent in seen_dirs:
            continue
        seen_dirs.add(parent)
        candidate = load_environment(env_name, parent)
        if env_config is None:
            env_config = candidate
            env_source = parent / f"env-{env_name}.yaml"
        elif candidate != env_config:
            raise ConfigError(
                f"Environment '{env_name}' has divergent definitions: "
                f"{env_source} vs {parent / f'env-{env_name}.yaml'}"
            )

    assert env_config is not None  # guaranteed by non-empty secret_files

    documents: list[Document] = []
    seen_paths: dict[str, Path] = {}
    for path, secrets in loaded:
        for doc in secrets.documents:
            if doc.path in seen_paths:
                raise ConfigError(
                    f"Duplicate Vault path '{doc.path}' "
                    f"in {path} (already declared in {seen_paths[doc.path]})"
                )
            seen_paths[doc.path] = path
            documents.append(doc)

    return LoadedInputs(env_name=env_name, environment=env_config, documents=documents)
