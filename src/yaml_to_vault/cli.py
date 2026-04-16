"""CLI entry point: `yaml-to-vault plan`, `apply`, `policy` and `role`."""

from __future__ import annotations

import difflib
import json
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Iterator

import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from .loader import ConfigError, load_environment, load_inputs
from .models import EnvironmentConfig
from .onepassword import OnePasswordError, OnePasswordResolver
from .planner import Action, build_plan, render_plan
from .ssh_tunnel import SshTunnelError, ssh_tunnel
from .vault_client import VaultClient, VaultClientError

app = typer.Typer(
    add_completion=False,
    help="Apply a desired Vault state declared in YAML, with values resolved from 1Password.",
)

FilesArgument = Annotated[
    list[Path],
    typer.Argument(
        help="Secret YAML files. Each must declare 'env: <name>'; all must agree.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
]
ShowSecretsOption = Annotated[
    bool,
    typer.Option(
        "--show-secrets",
        help="Display secret values in clear text in the diff (DANGEROUS).",
    ),
]
YesOption = Annotated[
    bool,
    typer.Option("--yes", "-y", help="Skip the interactive confirmation prompt."),
]


@contextmanager
def _maybe_tunnel(env: EnvironmentConfig) -> Iterator[None]:
    """Open an SSH tunnel if ``ssh_tunnel`` is configured, otherwise no-op."""
    if env.vault.ssh_tunnel:
        with ssh_tunnel(env.vault.ssh_tunnel):
            yield
    else:
        yield



@app.command("plan")
def plan_cmd(
    files: FilesArgument,
    show_secrets: ShowSecretsOption = False,
) -> None:
    """Show what would change in Vault without writing anything."""
    console = Console()
    try:
        inputs = load_inputs(files)
        with _maybe_tunnel(inputs.environment):
            op_resolver = OnePasswordResolver()
            vault_client = VaultClient(inputs.environment, op_resolver)
            plans = build_plan(inputs.documents, vault_client, op_resolver)
    except (ConfigError, OnePasswordError, VaultClientError, SshTunnelError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    console.print(f"[bold]Environment:[/bold] {inputs.env_name}")
    render_plan(plans, console, show_secrets=show_secrets, mount=inputs.environment.vault.mount)


@app.command("apply")
def apply_cmd(
    files: FilesArgument,
    show_secrets: ShowSecretsOption = False,
    yes: YesOption = False,
) -> None:
    """Build a plan, ask for confirmation, then apply the YAML state to Vault."""
    console = Console()
    try:
        inputs = load_inputs(files)
    except ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    try:
        with _maybe_tunnel(inputs.environment):
            op_resolver = OnePasswordResolver()
            vault_client = VaultClient(inputs.environment, op_resolver)
            plans = build_plan(inputs.documents, vault_client, op_resolver)
            env_name = inputs.env_name
            mount = inputs.environment.vault.mount

            console.print(f"[bold]Environment:[/bold] {env_name}")
            render_plan(plans, console, show_secrets=show_secrets, mount=mount)

            to_write = [p for p in plans if p.action is not Action.NO_CHANGE]
            if not to_write:
                console.print("[dim]Nothing to do.[/dim]")
                return

            if not yes:
                confirm = typer.confirm(
                    f"Apply {len(to_write)} change(s) to Vault environment '{env_name}'?",
                    default=False,
                )
                if not confirm:
                    console.print("[yellow]Aborted.[/yellow]")
                    raise typer.Exit(code=1)

            for plan in to_write:
                vault_client.write(plan.path, plan.desired)
                console.print(
                    f"[green]✓[/green] {plan.action.value} {mount}/data/{plan.path}"
                )
    except (OnePasswordError, VaultClientError, SshTunnelError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


class PolicyAction(str, Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    NO_CHANGE = "NO_CHANGE"


_POLICY_ACTION_STYLE = {
    PolicyAction.CREATE: "green",
    PolicyAction.UPDATE: "yellow",
    PolicyAction.NO_CHANGE: "dim",
}


HclFilesArgument = Annotated[
    list[Path],
    typer.Argument(
        help="HCL policy files. Policy name is derived from the filename (without .hcl).",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
]
EnvOption = Annotated[
    str,
    typer.Option("--env", "-e", help="Environment name (resolves to env-<name>.yaml)."),
]


@app.command("policy")
def policy_cmd(
    env: EnvOption,
    files: HclFilesArgument,
    yes: YesOption = False,
) -> None:
    """Upload HCL policy files to Vault."""
    console = Console()
    try:
        search_dir = files[0].resolve().parent
        env_config = load_environment(env, search_dir)
    except ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    try:
        with _maybe_tunnel(env_config):
            op_resolver = OnePasswordResolver()
            vault_client = VaultClient(env_config, op_resolver)

            console.print(f"[bold]Environment:[/bold] {env}")

            policies: list[tuple[str, str, str | None, PolicyAction]] = []
            for path in files:
                name = path.stem.removeprefix("policy-")
                desired = path.read_text(encoding="utf-8")
                current = vault_client.read_policy(name)
                if current is None:
                    action = PolicyAction.CREATE
                elif current.strip() != desired.strip():
                    action = PolicyAction.UPDATE
                else:
                    action = PolicyAction.NO_CHANGE
                policies.append((name, desired, current, action))

            table = Table(title="yaml-to-vault policy", show_lines=True)
            table.add_column("Policy", style="cyan", no_wrap=True)
            table.add_column("Source")
            table.add_column("Action")
            for (name, _, _, action), path in zip(policies, files):
                style = _POLICY_ACTION_STYLE[action]
                table.add_row(name, str(path), f"[{style}]{action.value}[/]")
            console.print(table)

            for name, desired, current, action in policies:
                if action is not PolicyAction.UPDATE:
                    continue
                assert current is not None
                diff_lines = difflib.unified_diff(
                    current.splitlines(keepends=True),
                    desired.splitlines(keepends=True),
                    fromfile=f"vault:{name}",
                    tofile=f"local:{name}",
                )
                diff_text = "".join(diff_lines)
                if diff_text:
                    console.print(
                        f"\n[bold yellow]Diff for policy [cyan]{name}[/cyan]:[/bold yellow]"
                    )
                    console.print(Syntax(diff_text, "diff", theme="ansi_dark"))

            summary = {a: 0 for a in PolicyAction}
            for _, _, _, action in policies:
                summary[action] += 1
            console.print(
                f"\n[green]{summary[PolicyAction.CREATE]} to create[/], "
                f"[yellow]{summary[PolicyAction.UPDATE]} to update[/], "
                f"[dim]{summary[PolicyAction.NO_CHANGE]} unchanged[/]"
            )

            to_write = [
                (n, d, a) for n, d, _, a in policies if a is not PolicyAction.NO_CHANGE
            ]
            if not to_write:
                console.print("[dim]Nothing to do.[/dim]")
                return

            if not yes:
                confirm = typer.confirm(
                    f"Upload {len(to_write)} policy/policies to Vault environment '{env}'?",
                    default=False,
                )
                if not confirm:
                    console.print("[yellow]Aborted.[/yellow]")
                    raise typer.Exit(code=1)

            for name, desired, action in to_write:
                vault_client.write_policy(name, desired)
                console.print(f"[green]✓[/green] {action.value} policy {name}")
    except (OnePasswordError, VaultClientError, SshTunnelError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


class RoleAction(str, Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    NO_CHANGE = "NO_CHANGE"


_ROLE_ACTION_STYLE = {
    RoleAction.CREATE: "green",
    RoleAction.UPDATE: "yellow",
    RoleAction.NO_CHANGE: "dim",
}


JsonFilesArgument = Annotated[
    list[Path],
    typer.Argument(
        help="JSON role files. Role name is derived from the filename "
        "(role-<name>.json → <name>).",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
]


def _detect_role_action(current: dict | None, desired: dict) -> RoleAction:
    """CREATE if role is missing, UPDATE if any declared key differs, else NO_CHANGE.

    Drift is ignored: keys present in Vault but not in the JSON file are left alone.
    """
    if current is None:
        return RoleAction.CREATE
    for key, value in desired.items():
        if current.get(key) != value:
            return RoleAction.UPDATE
    return RoleAction.NO_CHANGE


def _load_role_file(path: Path) -> dict[str, Any]:
    """Parse a role JSON file, raising ConfigError on any problem."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Top-level JSON in {path} must be an object")
    return data


@app.command("role")
def role_cmd(
    env: EnvOption,
    files: JsonFilesArgument,
    yes: YesOption = False,
) -> None:
    """Upload JWT auth role definitions (role-<name>.json) to Vault."""
    console = Console()
    try:
        search_dir = files[0].resolve().parent
        env_config = load_environment(env, search_dir)
        roles_input: list[tuple[str, dict[str, Any]]] = []
        for path in files:
            name = path.stem.removeprefix("role-")
            roles_input.append((name, _load_role_file(path)))
    except ConfigError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    jwt_mount = env_config.vault.jwt_mount

    try:
        with _maybe_tunnel(env_config):
            op_resolver = OnePasswordResolver()
            vault_client = VaultClient(env_config, op_resolver)

            console.print(f"[bold]Environment:[/bold] {env}")

            roles: list[tuple[str, dict, dict | None, RoleAction]] = []
            for name, desired in roles_input:
                current = vault_client.read_role(name, jwt_mount)
                action = _detect_role_action(current, desired)
                roles.append((name, desired, current, action))

            table = Table(title="yaml-to-vault role", show_lines=True)
            table.add_column("Role", style="cyan", no_wrap=True)
            table.add_column("Source")
            table.add_column("Vault path")
            table.add_column("Action")
            for (name, _, _, action), path in zip(roles, files):
                style = _ROLE_ACTION_STYLE[action]
                table.add_row(
                    name,
                    str(path),
                    f"auth/{jwt_mount}/role/{name}",
                    f"[{style}]{action.value}[/]",
                )
            console.print(table)

            for name, desired, current, action in roles:
                if action is not RoleAction.UPDATE:
                    continue
                assert current is not None
                subset = {k: current.get(k) for k in desired}
                diff_lines = difflib.unified_diff(
                    json.dumps(subset, indent=2, sort_keys=True).splitlines(
                        keepends=True
                    ),
                    json.dumps(desired, indent=2, sort_keys=True).splitlines(
                        keepends=True
                    ),
                    fromfile=f"vault:{name}",
                    tofile=f"local:{name}",
                )
                diff_text = "".join(diff_lines)
                if diff_text:
                    if not diff_text.endswith("\n"):
                        diff_text += "\n"
                    console.print(
                        f"\n[bold yellow]Diff for role [cyan]{name}[/cyan]:[/bold yellow]"
                    )
                    console.print(Syntax(diff_text, "diff", theme="ansi_dark"))

            summary = {a: 0 for a in RoleAction}
            for _, _, _, action in roles:
                summary[action] += 1
            console.print(
                f"\n[green]{summary[RoleAction.CREATE]} to create[/], "
                f"[yellow]{summary[RoleAction.UPDATE]} to update[/], "
                f"[dim]{summary[RoleAction.NO_CHANGE]} unchanged[/]"
            )

            to_write = [
                (n, d, a) for n, d, _, a in roles if a is not RoleAction.NO_CHANGE
            ]
            if not to_write:
                console.print("[dim]Nothing to do.[/dim]")
                return

            if not yes:
                confirm = typer.confirm(
                    f"Upload {len(to_write)} role(s) to Vault environment '{env}'?",
                    default=False,
                )
                if not confirm:
                    console.print("[yellow]Aborted.[/yellow]")
                    raise typer.Exit(code=1)

            for name, desired, action in to_write:
                vault_client.write_role(name, jwt_mount, desired)
                console.print(f"[green]✓[/green] {action.value} role {name}")
    except (OnePasswordError, VaultClientError, SshTunnelError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":  # pragma: no cover
    app()
