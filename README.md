# yaml-to-vault

Apply a desired HashiCorp Vault state declared in YAML, with values resolved from 1Password.

## How it works

- **Secret files** named `secret-<app>.yaml` declare an `env: <name>` and a list of `documents`, each with a Vault path and a set of fields. Field values **must** be 1Password references (`op://vault/item/field`) — literal values are rejected.
- **Environment files** named `env-<name>.yaml` define the target Vault: address, mount, optional namespace, and a 1Password reference for the Vault token. The env file is loaded from **the same directory as the secret file** that references it.
- A single invocation handles **one environment**: every secret file passed on the command line must declare the same `env`. Mixing environments is rejected.
- At runtime, the tool resolves every `op://` reference via the local `op` CLI, compares the desired state to the current Vault state, prints a diff, and (on `apply`) writes the changes after confirmation.

Drift is **ignored**: keys present in Vault but absent from the YAML are left untouched.

## Requirements

- Python ≥ 3.14 (managed by `uv`)
- HashiCorp Vault (KV v2 mount)
- 1Password CLI (`op`), signed in

## Setup

```bash
uv sync
cp env-dev.yaml.example env-dev.yaml
# edit env-dev.yaml: set the address and the op:// reference of your token
```

## Usage

`plan` and `apply` take one or more secret YAML files as positional arguments. Each file declares its environment internally.

```bash
# Show what would change
uv run yaml-to-vault plan secret-example.yaml

# Apply (Terraform-style: shows the plan, then asks for confirmation)
uv run yaml-to-vault apply secret-example.yaml

# Apply non-interactively (CI / scripts)
uv run yaml-to-vault apply secret-example.yaml --yes

# Several files at once (must all declare the same env)
uv run yaml-to-vault plan secret-app1.yaml secret-app2.yaml

# Files in another directory — env-<name>.yaml is loaded from each file's parent dir
uv run yaml-to-vault apply ./config/secret-app1.yaml

# Reveal the actual values in the diff (use with care)
uv run yaml-to-vault plan secret-example.yaml --show-secrets
```

By default the diff masks values (`(set)`, `(changed)`, `(unchanged)`). `--show-secrets` reveals them in clear text and prints a warning.

## File formats

### `secret-<app>.yaml`

```yaml
env: dev
documents:
  - path: app1/database
    fields:
      username: op://Dev/app1-db/username
      password: op://Dev/app1-db/password
```

### `env-<name>.yaml` (next to the secret file)

```yaml
vault:
  address: https://vault.example.com
  mount: secret
  namespace: my-namespace            # optional
  token: op://Prod/vault-prod/token  # 1Password reference
  verify_tls: true
```

## Tests

```bash
uv run pytest
```
