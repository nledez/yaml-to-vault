import shutil
from pathlib import Path

import pytest

from yaml_to_vault.loader import (
    ConfigError,
    load_environment,
    load_inputs,
    load_secrets_file,
)
from yaml_to_vault.models import is_op_ref

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_SECRET = REPO_ROOT / "secret-example.yaml"
EXAMPLE_ENV = REPO_ROOT / "env-dev.yaml.example"

ENV_YAML = "vault:\n  address: http://v\n  token: op://V/Item/token\n"


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _secret_yaml(env: str, path: str, field: str, ref: str = "op://V/I/f") -> str:
    return (
        f"env: {env}\n"
        f"documents:\n"
        f"  - path: {path}\n"
        f"    fields:\n"
        f"      {field}: {ref}\n"
    )


def test_load_environment_ok(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", ENV_YAML)
    cfg = load_environment("dev", tmp_path)
    assert cfg.vault.address == "http://v"


def test_load_environment_missing(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found"):
        load_environment("nope", tmp_path)


def test_load_environment_invalid_yaml(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", "vault: [unclosed")
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_environment("dev", tmp_path)


def test_load_environment_validation_error(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", "vault:\n  address: http://v\n  token: literal\n")
    with pytest.raises(ConfigError, match="Invalid environment file"):
        load_environment("dev", tmp_path)


def test_load_secrets_file_ok(tmp_path: Path):
    f = _write(tmp_path / "s.yaml", _secret_yaml("dev", "app/db", "password"))
    sf = load_secrets_file(f)
    assert sf.env == "dev"
    assert sf.documents[0].path == "app/db"


def test_load_inputs_single_file(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", ENV_YAML)
    f = _write(tmp_path / "secret-app.yaml", _secret_yaml("dev", "app/db", "x"))
    inputs = load_inputs([f])
    assert inputs.env_name == "dev"
    assert inputs.environment.vault.address == "http://v"
    assert [d.path for d in inputs.documents] == ["app/db"]


def test_load_inputs_rejects_mixed_environments(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", ENV_YAML)
    _write(tmp_path / "env-prod.yaml", ENV_YAML)
    f1 = _write(tmp_path / "a.yaml", _secret_yaml("dev", "app/db", "x"))
    f2 = _write(tmp_path / "b.yaml", _secret_yaml("prod", "app/api", "y"))
    with pytest.raises(ConfigError, match="same environment"):
        load_inputs([f1, f2])


def test_load_inputs_detects_duplicate_paths(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", ENV_YAML)
    f1 = _write(tmp_path / "a.yaml", _secret_yaml("dev", "app/db", "x"))
    f2 = _write(tmp_path / "b.yaml", _secret_yaml("dev", "app/db", "y"))
    with pytest.raises(ConfigError, match="Duplicate Vault path"):
        load_inputs([f1, f2])


def test_load_inputs_merges_documents(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", ENV_YAML)
    f1 = _write(tmp_path / "a.yaml", _secret_yaml("dev", "app/db", "x"))
    f2 = _write(tmp_path / "b.yaml", _secret_yaml("dev", "app/api", "y"))
    inputs = load_inputs([f1, f2])
    assert {d.path for d in inputs.documents} == {"app/db", "app/api"}


def test_load_inputs_loads_env_from_each_directory(tmp_path: Path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write(dir_a / "env-dev.yaml", ENV_YAML)
    _write(dir_b / "env-dev.yaml", ENV_YAML)
    f1 = _write(dir_a / "secret-app1.yaml", _secret_yaml("dev", "app1/db", "x"))
    f2 = _write(dir_b / "secret-app2.yaml", _secret_yaml("dev", "app2/db", "y"))
    inputs = load_inputs([f1, f2])
    assert inputs.env_name == "dev"


def test_load_inputs_rejects_divergent_env_definitions(tmp_path: Path):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    _write(dir_a / "env-dev.yaml", ENV_YAML)
    _write(
        dir_b / "env-dev.yaml",
        "vault:\n  address: http://OTHER\n  token: op://V/Item/token\n",
    )
    f1 = _write(dir_a / "secret-app1.yaml", _secret_yaml("dev", "app1/db", "x"))
    f2 = _write(dir_b / "secret-app2.yaml", _secret_yaml("dev", "app2/db", "y"))
    with pytest.raises(ConfigError, match="divergent definitions"):
        load_inputs([f1, f2])


def test_load_inputs_missing_env_file(tmp_path: Path):
    f = _write(tmp_path / "secret-app.yaml", _secret_yaml("dev", "app/db", "x"))
    with pytest.raises(ConfigError, match="not found"):
        load_inputs([f])


def test_load_inputs_requires_at_least_one_file():
    with pytest.raises(ConfigError, match="At least one secret file"):
        load_inputs([])


# ---------------------------------------------------------------------------
# Edge cases: empty YAML, non-mapping, invalid secrets
# ---------------------------------------------------------------------------


def test_load_empty_yaml_file(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", "")
    with pytest.raises(ConfigError, match="Empty YAML file"):
        load_environment("dev", tmp_path)


def test_load_non_mapping_yaml(tmp_path: Path):
    _write(tmp_path / "env-dev.yaml", "- item1\n- item2\n")
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_environment("dev", tmp_path)


def test_load_secrets_file_validation_error(tmp_path: Path):
    f = _write(
        tmp_path / "bad.yaml",
        "env: dev\ndocuments:\n  - path: x\n    fields:\n      k: not-an-op-ref\n",
    )
    with pytest.raises(ConfigError, match="Invalid secrets file"):
        load_secrets_file(f)


# ---------------------------------------------------------------------------
# Real example files shipped with the repo
# ---------------------------------------------------------------------------


def test_example_secret_file_parses_with_quoted_values():
    """secret-example.yaml uses a mix of single-quoted, double-quoted and
    unquoted values, including refs whose segments contain spaces and
    dashes. load_secrets_file must accept all of them and store clean
    op:// refs (without surrounding YAML quote characters).
    """
    sf = load_secrets_file(EXAMPLE_SECRET)
    assert sf.env == "dev"

    all_values: list[str] = []
    for doc in sf.documents:
        for value in doc.fields.values():
            assert is_op_ref(value), f"not a clean op ref: {value!r}"
            # The surrounding YAML quotes must not have leaked into the value
            assert not (value.startswith('"') or value.endswith('"'))
            assert not (value.startswith("'") or value.endswith("'"))
            all_values.append(value)

    assert "op://Dev/app1-db/username" in all_values
    assert "op://Dev/app1-db/password" in all_values
    assert "op://Dev/app1-api/credential" in all_values
    assert (
        "op://Infrastructure/Customer - dev - secure-app/database_name" in all_values
    )
    assert (
        "op://Infrastructure/Customer - dev - secure-app/database_password" in all_values
    )


def test_example_env_file_example_is_valid_when_renamed(tmp_path: Path):
    shutil.copy(EXAMPLE_ENV, tmp_path / "env-dev.yaml")
    cfg = load_environment("dev", tmp_path)
    assert cfg.vault.address == "http://127.0.0.1:8200"
    assert cfg.vault.token == "op://Dev/vault-dev/token"
    assert cfg.vault.mount == "secret"
    assert cfg.vault.verify_tls is True


def test_example_files_load_end_to_end(tmp_path: Path):
    """Copy the shipped example files into a temp dir under their canonical
    names and run the full load_inputs pipeline against them.
    """
    shutil.copy(EXAMPLE_ENV, tmp_path / "env-dev.yaml")
    secret_path = tmp_path / "secret-example.yaml"
    shutil.copy(EXAMPLE_SECRET, secret_path)

    inputs = load_inputs([secret_path])
    assert inputs.env_name == "dev"
    assert inputs.environment.vault.address == "http://127.0.0.1:8200"
    assert {d.path for d in inputs.documents} == {
        "app1/database",
        "app1/api",
        "infra/secure-app",
    }

    db = next(d for d in inputs.documents if d.path == "app1/database")
    assert db.fields == {
        "username": "op://Dev/app1-db/username",
        "password": "op://Dev/app1-db/password",
    }
    api = next(d for d in inputs.documents if d.path == "app1/api")
    assert api.fields == {"api_key": "op://Dev/app1-api/credential"}
    secureapp = next(d for d in inputs.documents if d.path == "infra/secure-app")
    assert secureapp.fields == {
        "database_name": "op://Infrastructure/Customer - dev - secure-app/database_name",
        "database_password": (
            "op://Infrastructure/Customer - dev - secure-app/database_password"
        ),
    }
