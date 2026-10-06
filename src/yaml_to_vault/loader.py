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
    """Load env-<name>.yaml from ``search_dir``.

    A relative ``ca_path`` is resolved against the directory of the env file, so the
    tool can be run from any directory.
    """
    path = search_dir / f"env-{name}.yaml"
    data = _read_yaml(path)
    try:
        env = EnvironmentConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"Invalid environment file {path}:\n{exc}") from exc
    ca_path = env.vault.ca_path
    if ca_path is not None and not Path(ca_path).is_absolute():
        resolved = str((path.parent / ca_path).resolve())
        env = env.model_copy(update={"vault": env.vault.model_copy(update={"ca_path": resolved})})
    return env


def _shared_env_dir(name: str, cwd: Path) -> Path:
    """Directory holding env-<name>.yaml for a shared file: ``cwd``, then ``cwd/<name>``."""
    candidates = [cwd, cwd / name]
    for candidate in candidates:
        if (candidate / f"env-{name}.yaml").exists():
            return candidate.resolve()
    searched = ", ".join(str(c / f"env-{name}.yaml") for c in candidates)
    raise ConfigError(f"Environment file not found, searched: {searched}")


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


def load_inputs(
    secret_files: list[Path],
    env_override: str | None = None,
    cwd: Path | None = None,
) -> LoadedInputs:
    """Load secret files, ensure they target a single environment, and load it.

    - Each secret file declares ``env: <name>`` at the top, or omits it to be shared
      by every environment: the environment then comes from ``env_override``
      (``--env``), which must agree with every file that does declare one.
    - All files must declare the same environment.
    - ``env-<name>.yaml`` is loaded from the parent directory of every file that
      declares ``env``, and for shared files from ``cwd`` or else ``cwd/<name>`` (so
      the tool runs from the env directory or from the repository root); all loaded
      environments must be identical.
    - In every document, ``{env}`` is replaced in the path and the op:// refs, and
      documents whose ``envs`` list excludes the environment are skipped.
    - Duplicate Vault paths across files are rejected (after substitution).
    """
    if not secret_files:
        raise ConfigError("At least one secret file is required.")

    loaded: list[tuple[Path, SecretsFile]] = []
    for path in secret_files:
        loaded.append((path, load_secrets_file(path)))

    shared = [p for p, sf in loaded if sf.env is None]
    if shared and env_override is None:
        raise ConfigError(
            "These files declare no 'env' and need the environment passed with --env: "
            + ", ".join(str(p) for p in shared)
        )

    env_names = {sf.env for _, sf in loaded if sf.env is not None}
    if env_override is not None:
        env_names.add(env_override)
    if len(env_names) > 1:
        listing = ", ".join(
            f"{p} → env={sf.env}" for p, sf in loaded if sf.env is not None
        )
        if env_override is not None:
            listing += f", --env={env_override}"
        raise ConfigError(
            "All secret files must target the same environment, got: " + listing
        )
    env_name = env_names.pop()

    env_config: EnvironmentConfig | None = None
    env_source: Path | None = None
    seen_dirs: set[Path] = set()
    for path, sf in loaded:
        if sf.env is not None:
            parent = path.parent.resolve()
        else:
            parent = _shared_env_dir(env_name, cwd or Path.cwd())
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
        for raw in secrets.documents:
            if raw.envs is not None and env_name not in raw.envs:
                continue
            doc = raw.for_env(env_name)
            if doc.path in seen_paths:
                raise ConfigError(
                    f"Duplicate Vault path '{doc.path}' "
                    f"in {path} (already declared in {seen_paths[doc.path]})"
                )
            seen_paths[doc.path] = path
            documents.append(doc)

    return LoadedInputs(env_name=env_name, environment=env_config, documents=documents)
