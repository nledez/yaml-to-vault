"""Pydantic models for environment and secrets YAML files."""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints

# op://<vault>/<item>/<field>  or  op://<vault>/<item>/<section>/<field>
# Each segment must be non-empty and cannot contain `/`. Spaces, dashes, dots,
# apostrophes, etc. are allowed inside segments — 1Password vault/item/field
# names routinely contain them (e.g. "Customer - dev - secure-app").
OP_REF_REGEX = r"^op://[^/]+/[^/]+(?:/[^/]+)+$"


def normalize_op_ref(value: Any) -> Any:
    """Strip surrounding whitespace and one matching pair of single/double quotes.

    Allows YAML authors to write any of these and end up with the same op:// ref:
        op://V/I/f
        "op://V/I/f"
        'op://V/I/f'
        '  op://V/I/f  '
    Mismatched or unmatched quotes are left alone so the regex check rejects them.
    """
    if not isinstance(value, str):
        return value
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1].strip()
    return v


OpRef = Annotated[
    str,
    BeforeValidator(normalize_op_ref),
    StringConstraints(pattern=OP_REF_REGEX),
]


def is_op_ref(value: str) -> bool:
    """Return True iff ``value`` (after normalization) matches the op:// shape."""
    if not isinstance(value, str):
        return False
    return bool(re.match(OP_REF_REGEX, normalize_op_ref(value)))


class VaultConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    mount: str = "secret"
    namespace: str | None = None
    token: OpRef
    verify_tls: bool = True
    ca_path: str | None = None
    proxy: str | None = None
    ssh_tunnel: str | None = None


class EnvironmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vault: VaultConfig


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    fields: dict[str, OpRef] = Field(min_length=1)


class SecretsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    env: str = Field(min_length=1)
    documents: list[Document] = Field(min_length=1)
