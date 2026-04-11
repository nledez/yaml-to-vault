"""Build and render plans (desired YAML state vs current Vault state)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from rich.console import Console
from rich.table import Table

from .models import Document
from .onepassword import OnePasswordResolver
from .vault_client import VaultClient


class Action(str, Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    NO_CHANGE = "NO_CHANGE"


@dataclass
class FieldChange:
    name: str
    before: str | None
    after: str

    @property
    def changed(self) -> bool:
        return self.before != self.after


@dataclass
class DocumentPlan:
    path: str
    action: Action
    desired: dict[str, str]
    changes: list[FieldChange] = field(default_factory=list)

    @property
    def changed_field_names(self) -> list[str]:
        return [c.name for c in self.changes if c.changed]


def build_plan(
    documents: list[Document],
    vault_client: VaultClient,
    op_resolver: OnePasswordResolver,
) -> list[DocumentPlan]:
    plans: list[DocumentPlan] = []
    for doc in documents:
        desired = {name: op_resolver.resolve(ref) for name, ref in doc.fields.items()}
        current = vault_client.read(doc.path)

        changes = [
            FieldChange(
                name=name,
                before=(current.get(name) if current is not None else None),
                after=value,
            )
            for name, value in desired.items()
        ]

        if current is None:
            action = Action.CREATE
        elif any(c.changed for c in changes):
            action = Action.UPDATE
        else:
            action = Action.NO_CHANGE

        plans.append(
            DocumentPlan(path=doc.path, action=action, desired=desired, changes=changes)
        )
    return plans


_ACTION_STYLE = {
    Action.CREATE: "green",
    Action.UPDATE: "yellow",
    Action.NO_CHANGE: "dim",
}


def _mask(value: str | None) -> str:
    if value is None:
        return "-"
    return "***"


def render_plan(
    plans: list[DocumentPlan],
    console: Console,
    show_secrets: bool = False,
    mount: str = "secret",
) -> None:
    if show_secrets:
        console.print(
            "[bold red]WARNING:[/bold red] --show-secrets is enabled; "
            "secret values will be displayed in clear text."
        )

    table = Table(title="yaml-to-vault plan", show_lines=True)
    table.add_column("Path", style="cyan", no_wrap=True)
    table.add_column("Action")
    table.add_column("Field")
    table.add_column("Before")
    table.add_column("After")

    for plan in plans:
        full_path = f"{mount}/data/{plan.path}"
        action_text = f"[{_ACTION_STYLE[plan.action]}]{plan.action.value}[/]"
        if not plan.changes:
            table.add_row(full_path, action_text, "", "", "")
            continue
        for idx, change in enumerate(plan.changes):
            if show_secrets:
                before = "-" if change.before is None else change.before
                after = change.after
            else:
                if plan.action is Action.CREATE:
                    before, after = "-", "(set)"
                elif change.changed:
                    before, after = _mask(change.before), "(changed)"
                else:
                    before, after = _mask(change.before), "(unchanged)"
            table.add_row(
                full_path if idx == 0 else "",
                action_text if idx == 0 else "",
                change.name,
                before,
                after,
            )

    console.print(table)

    summary = {a: 0 for a in Action}
    for plan in plans:
        summary[plan.action] += 1
    console.print(
        f"[green]{summary[Action.CREATE]} to create[/], "
        f"[yellow]{summary[Action.UPDATE]} to update[/], "
        f"[dim]{summary[Action.NO_CHANGE]} unchanged[/]"
    )
