import pytest
from pydantic import ValidationError

from yaml_to_vault.models import (
    Document,
    EnvironmentConfig,
    SecretsFile,
    is_op_ref,
    normalize_op_ref,
)


def test_is_op_ref_accepts_valid():
    assert is_op_ref("op://Vault/Item/field")
    assert is_op_ref("op://Vault/Item/section/field")


def test_is_op_ref_rejects_invalid():
    assert not is_op_ref("plain")
    assert not is_op_ref("op://Vault/Item")
    assert not is_op_ref("https://example.com")


def test_is_op_ref_rejects_non_string():
    assert not is_op_ref(None)  # type: ignore[arg-type]
    assert not is_op_ref(42)  # type: ignore[arg-type]
    assert not is_op_ref(["op://V/I/f"])  # type: ignore[arg-type]


def test_environment_config_requires_op_ref_token():
    with pytest.raises(ValidationError):
        EnvironmentConfig.model_validate(
            {"vault": {"address": "http://v", "token": "literal-token"}}
        )


def test_environment_config_accepts_op_ref_token():
    cfg = EnvironmentConfig.model_validate(
        {"vault": {"address": "http://v", "token": "op://V/Item/token"}}
    )
    assert cfg.vault.token == "op://V/Item/token"
    assert cfg.vault.mount == "secret"


def test_vault_config_ca_path_defaults_to_none():
    cfg = EnvironmentConfig.model_validate(
        {"vault": {"address": "http://v", "token": "op://V/Item/token"}}
    )
    assert cfg.vault.ca_path is None
    assert cfg.vault.verify_tls is True


def test_vault_config_ca_path_accepts_string():
    cfg = EnvironmentConfig.model_validate(
        {
            "vault": {
                "address": "https://v",
                "token": "op://V/I/t",
                "ca_path": "/etc/ssl/certs/vault-ca.pem",
            }
        }
    )
    assert cfg.vault.ca_path == "/etc/ssl/certs/vault-ca.pem"


def test_vault_config_ca_path_with_verify_tls_false():
    cfg = EnvironmentConfig.model_validate(
        {
            "vault": {
                "address": "https://v",
                "token": "op://V/I/t",
                "verify_tls": False,
                "ca_path": "/ca.pem",
            }
        }
    )
    assert cfg.vault.verify_tls is False
    assert cfg.vault.ca_path == "/ca.pem"


def test_document_rejects_literal_field_value():
    with pytest.raises(ValidationError):
        Document.model_validate({"path": "app/db", "fields": {"password": "hunter2"}})


def test_secrets_file_accepts_valid_documents():
    sf = SecretsFile.model_validate(
        {
            "env": "dev",
            "documents": [
                {
                    "path": "app/db",
                    "fields": {"username": "op://V/Item/u", "password": "op://V/Item/p"},
                }
            ],
        }
    )
    assert sf.env == "dev"
    assert len(sf.documents) == 1
    assert sf.documents[0].path == "app/db"


def test_secrets_file_requires_env():
    with pytest.raises(ValidationError):
        SecretsFile.model_validate(
            {
                "documents": [
                    {"path": "app/db", "fields": {"x": "op://V/I/f"}},
                ]
            }
        )


def test_secrets_file_requires_at_least_one_document():
    with pytest.raises(ValidationError):
        SecretsFile.model_validate({"env": "dev", "documents": []})


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        EnvironmentConfig.model_validate(
            {
                "vault": {
                    "address": "http://v",
                    "token": "op://V/Item/t",
                    "unknown": True,
                }
            }
        )


# ---------------------------------------------------------------------------
# normalize_op_ref + quote stripping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("op://V/I/f", "op://V/I/f"),
        ('"op://V/I/f"', "op://V/I/f"),
        ("'op://V/I/f'", "op://V/I/f"),
        ("  op://V/I/f  ", "op://V/I/f"),
        ('"  op://V/I/f  "', "op://V/I/f"),
        ("'  op://V/I/f  '", "op://V/I/f"),
        ('  "op://V/I/f"  ', "op://V/I/f"),
        ("  'op://V/I/f'  ", "op://V/I/f"),
        ("op://V/I/section/field", "op://V/I/section/field"),
    ],
)
def test_normalize_op_ref_strips_quotes_and_whitespace(raw, expected):
    assert normalize_op_ref(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        '"op://V/I/f',          # only opening double quote
        "op://V/I/f\"",         # only trailing double quote
        "'op://V/I/f",          # only opening single quote
        "op://V/I/f'",          # only trailing single quote
        "\"op://V/I/f'",        # mismatched
        "'op://V/I/f\"",        # mismatched
    ],
)
def test_normalize_op_ref_leaves_unmatched_quotes(raw):
    # Unmatched quotes are NOT stripped — they survive normalization so the
    # downstream regex check rejects them.
    assert normalize_op_ref(raw) == raw.strip()


def test_normalize_op_ref_passes_through_non_strings():
    assert normalize_op_ref(None) is None
    assert normalize_op_ref(42) == 42
    assert normalize_op_ref(["x"]) == ["x"]


@pytest.mark.parametrize(
    "raw",
    [
        "op://V/I/f",
        '"op://V/I/f"',
        "'op://V/I/f'",
        '  "op://V/I/f"  ',
        "'  op://V/I/f  '",
    ],
)
def test_is_op_ref_accepts_quoted_variants(raw):
    assert is_op_ref(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        '""',
        "''",
        "plain",
        "op://V/I",            # missing field segment
        '"op://V/I"',          # quoted but still missing field
        "https://example.com",
        "\"op://V/I/f'",       # mismatched quotes
    ],
)
def test_is_op_ref_rejects_invalid_variants(raw):
    assert not is_op_ref(raw)


@pytest.mark.parametrize(
    "raw",
    [
        '"op://V/Item/token"',
        "'op://V/Item/token'",
        '   "op://V/Item/token"   ',
        '"   op://V/Item/token   "',
    ],
)
def test_environment_config_accepts_quoted_token(raw):
    cfg = EnvironmentConfig.model_validate(
        {"vault": {"address": "http://v", "token": raw}}
    )
    assert cfg.vault.token == "op://V/Item/token"


@pytest.mark.parametrize(
    "raw",
    [
        '"',
        '""',
        "''",
        "'op://V/Item/token\"",
        '"not-an-op-ref"',
        '"op://V/Item"',
    ],
)
def test_environment_config_rejects_invalid_quoted_token(raw):
    with pytest.raises(ValidationError):
        EnvironmentConfig.model_validate(
            {"vault": {"address": "http://v", "token": raw}}
        )


def test_document_accepts_quoted_field_values():
    doc = Document.model_validate(
        {
            "path": "app/db",
            "fields": {
                "username": '"op://V/I/u"',
                "password": "'op://V/I/p'",
                "api_key": "  op://V/I/k  ",
            },
        }
    )
    assert doc.fields == {
        "username": "op://V/I/u",
        "password": "op://V/I/p",
        "api_key": "op://V/I/k",
    }


def test_secrets_file_accepts_quoted_values_round_trip():
    sf = SecretsFile.model_validate(
        {
            "env": "dev",
            "documents": [
                {
                    "path": "app/db",
                    "fields": {"password": '"op://V/I/p"'},
                }
            ],
        }
    )
    assert sf.documents[0].fields["password"] == "op://V/I/p"


# ---------------------------------------------------------------------------
# Segments containing spaces, dashes and other "real world" characters
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        # The exact case the user reported
        "op://Infrastructure/Customer - dev - secure-app/database_name",
        # Same, with the YAML-stripped quote variants
        '"op://Infrastructure/Customer - dev - secure-app/database_name"',
        "'op://Infrastructure/Customer - dev - secure-app/database_name'",
        # Spaces in vault, item and field segments
        "op://Vault With Spaces/Item Name/field name",
        # Section + field
        "op://V/I/Section Name/field name",
        # Apostrophes inside a segment
        "op://V/I/Bob's password",
        # Dashes, dots, underscores, digits
        "op://V/I/field-with-dashes",
        "op://V/I/field.with.dots",
        "op://V/I/field_with_underscores",
        "op://V/I/field123",
        # Section path beyond two levels (1Password supports section/field)
        "op://V/I/Section/sub/field",
    ],
)
def test_op_ref_accepts_real_world_segments(raw):
    assert is_op_ref(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "op://",                # only the prefix
        "op://V",               # only one segment
        "op://V/I",             # only two segments (no field)
        "op://V/I/",            # third segment empty
        "op://V//f",            # second segment empty
        "op:///I/f",            # first segment empty
        "op:////",              # all segments empty
    ],
)
def test_op_ref_rejects_empty_or_missing_segments(raw):
    assert not is_op_ref(raw)


def test_environment_config_accepts_token_with_spaces_and_dashes():
    raw = "op://Infrastructure/Customer - dev - vault/token"
    cfg = EnvironmentConfig.model_validate(
        {"vault": {"address": "http://v", "token": raw}}
    )
    assert cfg.vault.token == raw


def test_document_accepts_real_world_field_value():
    doc = Document.model_validate(
        {
            "path": "infra/secure-app",
            "fields": {
                "database_name": (
                    "op://Infrastructure/Customer - dev - secure-app/database_name"
                ),
                "quoted": (
                    '"op://Infrastructure/Customer - dev - secure-app/database_password"'
                ),
            },
        }
    )
    assert doc.fields == {
        "database_name": "op://Infrastructure/Customer - dev - secure-app/database_name",
        "quoted": "op://Infrastructure/Customer - dev - secure-app/database_password",
    }
