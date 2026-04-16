# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`yaml-to-vault` declares a desired HashiCorp Vault state in YAML and applies it. Field values are **never** literal — they must be 1Password references (`op://vault/item/field`) resolved at runtime via the `op` CLI. The Vault token is itself stored in 1Password and referenced from the environment YAML.

## Tooling

- Python ≥ 3.14, managed by **uv** (do not use pip/venv directly).
- Add deps with `uv add <pkg>` / `uv add --dev <pkg>` — never edit `pyproject.toml` dependency lists by hand.
- Lint: `uv run ruff check`. Tests: `uv run pytest`.
- Run the CLI in dev: `uv run yaml-to-vault <command>`.

## Layout

```
src/yaml_to_vault/
  models.py        # Pydantic models, OpRef constrained type
  loader.py        # YAML → models, ConfigError
  onepassword.py   # `op read` wrapper, OnePasswordResolver (caches refs)
  vault_client.py  # hvac KV v2 wrapper + policy + JWT-role helpers
  planner.py       # Action enum, build_plan(), render_plan(show_secrets)
  cli.py           # Typer app: `plan`, `apply`, `policy`, `role`
tests/             # pytest + pytest-mock, no network/Vault required
env-<name>.yaml    # one file per environment (gitignored except *.example)
secret-<app>.yaml  # one file per app, declares N Vault documents
role-<app>.json    # one file per app, literal JSON body for
                   # `vault write auth/<jwt_mount>/role/<app>`
```

## File naming and CLI invocation

- **Secret files**: `secret-<app>.yaml`. Each declares `env: <name>` at the top, plus a list of `documents`.
- **Environment files**: `env-<name>.yaml`. Loaded from **the parent directory of each secret file** (NOT from a fixed location). Do not reintroduce `environments/`/`secrets/` subdirectories or a `--dir` flag.
- **Role files**: `role-<app>.json`. Literal JSON body, one role per file. The role name is the filename stem minus the `role-` prefix. Equivalent to `vault write auth/<jwt_mount>/role/<app> @role-<app>.json`. No `env` header — the `role` command takes `--env <name>` on the CLI (like `policy`). Drift is ignored: keys in Vault that are not declared in the JSON file are left alone.
- The CLI takes secret files as **positional arguments** for `plan`/`apply`: `yaml-to-vault plan secret-app1.yaml secret-app2.yaml`. The environment is read from the YAML. `policy` and `role` take `--env <name>` explicitly (the HCL/JSON files themselves carry no env metadata).
- **Single-environment invariant**: a single invocation handles exactly one environment. `load_inputs` rejects mismatched `env` values across files, and rejects divergent `env-<name>.yaml` definitions if files come from multiple directories. Preserve this invariant.

## Non-negotiable rules

- **Never** accept literal secrets in YAML. Both `vault.token` and every `documents[].fields[*]` value MUST match the `OpRef` regex (`^op://[^/\s]+/[^/\s]+/.+$`). Validation lives in `models.py` — keep it strict.
- **Never** print secret values by default. The diff masks values (`(set)`, `(changed)`, `(unchanged)`). Plain values are gated behind `--show-secrets`, which must always emit the red WARNING line first.
- **Drift is ignored on purpose**. If a key exists in Vault but not in the YAML, leave it alone. Do not introduce a "sync strict" / delete mode without explicit user approval.
- **KV v2 only** for now. If you add KV v1 support, make it opt-in per environment, do not change defaults.
- **Auth = token only** for now. Token is always resolved from 1Password — never from an env var or a literal field.
- Do not log resolved secret values, even in error messages. Reference fields by *name*, never value.
- `extra="forbid"` is set on every Pydantic model. Keep it that way so typos in YAML are caught.

## Conventions

- New runtime errors should subclass or be raised as `ConfigError`, `OnePasswordError`, or `VaultClientError` — the CLI catches exactly those and exits cleanly. Don't leak raw `hvac` / `subprocess` exceptions to the user.
- The 1Password resolver caches results per process; preserve that to keep `op` invocations minimal.
- Tests must not hit a real Vault or call `op`. Use the `FakeResolver` / `FakeVault` patterns from `tests/test_planner.py` and `mocker.patch` for `subprocess.run` / `shutil.which`.
- When adding a CLI flag, expose it on **both** `plan` and `apply` if it affects rendering or resolution, so the two commands stay symmetric.

## Verification before declaring done

1. `uv run ruff check`
2. `uv run pytest`
3. `uv run yaml-to-vault --help` and `uv run yaml-to-vault plan --help` still render the expected options.

End-to-end testing against a real Vault is manual: see the "Verification" section of `README.md`.
