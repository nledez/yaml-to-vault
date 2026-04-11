from io import StringIO

from rich.console import Console

from yaml_to_vault.models import Document
from yaml_to_vault.planner import Action, build_plan, render_plan


class FakeResolver:
    def __init__(self, mapping: dict[str, str]) -> None:
        self._mapping = mapping

    def resolve(self, ref: str) -> str:
        return self._mapping[ref]


class FakeVault:
    def __init__(self, state: dict[str, dict[str, str] | None]) -> None:
        self._state = state

    def read(self, path: str):
        return self._state.get(path)


def _doc(path: str, fields: dict[str, str]) -> Document:
    return Document.model_validate({"path": path, "fields": fields})


def test_build_plan_create():
    docs = [_doc("app/db", {"u": "op://V/I/u", "p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/u": "alice", "op://V/I/p": "s3cret"})
    vault = FakeVault({})
    plans = build_plan(docs, vault, resolver)
    assert len(plans) == 1
    assert plans[0].action is Action.CREATE
    assert plans[0].desired == {"u": "alice", "p": "s3cret"}


def test_build_plan_no_change():
    docs = [_doc("app/db", {"u": "op://V/I/u"})]
    resolver = FakeResolver({"op://V/I/u": "alice"})
    vault = FakeVault({"app/db": {"u": "alice"}})
    plans = build_plan(docs, vault, resolver)
    assert plans[0].action is Action.NO_CHANGE


def test_build_plan_update():
    docs = [_doc("app/db", {"u": "op://V/I/u", "p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/u": "alice", "op://V/I/p": "new"})
    vault = FakeVault({"app/db": {"u": "alice", "p": "old"}})
    plans = build_plan(docs, vault, resolver)
    assert plans[0].action is Action.UPDATE
    assert plans[0].changed_field_names == ["p"]


def _render(plans, show_secrets: bool, mount: str = "secret") -> str:
    buf = StringIO()
    console = Console(file=buf, color_system=None, width=200, record=True)
    render_plan(plans, console, show_secrets=show_secrets, mount=mount)
    return buf.getvalue()


def test_render_masks_by_default():
    docs = [_doc("app/db", {"p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/p": "s3cret"})
    vault = FakeVault({"app/db": {"p": "old"}})
    plans = build_plan(docs, vault, resolver)
    output = _render(plans, show_secrets=False)
    assert "s3cret" not in output
    assert "old" not in output
    assert "(changed)" in output


def test_render_show_secrets_reveals_values():
    docs = [_doc("app/db", {"p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/p": "s3cret"})
    vault = FakeVault({"app/db": {"p": "old"}})
    plans = build_plan(docs, vault, resolver)
    output = _render(plans, show_secrets=True)
    assert "s3cret" in output
    assert "old" in output
    assert "WARNING" in output


def test_render_shows_full_path_with_mount():
    docs = [_doc("app/db", {"p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/p": "val"})
    vault = FakeVault({})
    plans = build_plan(docs, vault, resolver)
    output = _render(plans, show_secrets=False, mount="secret")
    assert "secret/data/app/db" in output


def test_render_shows_custom_mount():
    docs = [_doc("app/db", {"p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/p": "val"})
    vault = FakeVault({})
    plans = build_plan(docs, vault, resolver)
    output = _render(plans, show_secrets=False, mount="kv-prod")
    assert "kv-prod/data/app/db" in output


def test_render_no_change_shows_unchanged():
    docs = [_doc("app/db", {"p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/p": "same"})
    vault = FakeVault({"app/db": {"p": "same"}})
    plans = build_plan(docs, vault, resolver)
    output = _render(plans, show_secrets=False)
    assert "(unchanged)" in output


def test_render_plan_with_empty_changes():
    """Cover the branch where plan.changes is empty."""
    from yaml_to_vault.planner import DocumentPlan

    plan = DocumentPlan(path="x", action=Action.NO_CHANGE, desired={}, changes=[])
    output = _render([plan], show_secrets=False)
    assert "NO_CHANGE" in output


def test_mask_none_returns_dash():
    from yaml_to_vault.planner import _mask

    assert _mask(None) == "-"
    assert _mask("something") == "***"


def test_render_show_secrets_create():
    """show_secrets on a CREATE shows '-' for before and the actual value for after."""
    docs = [_doc("app/db", {"p": "op://V/I/p"})]
    resolver = FakeResolver({"op://V/I/p": "newval"})
    vault = FakeVault({})
    plans = build_plan(docs, vault, resolver)
    output = _render(plans, show_secrets=True)
    assert "newval" in output
