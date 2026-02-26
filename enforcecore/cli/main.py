# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore CLI — operator-facing tools for policy management and auditing.

Commands:
    enforcecore validate <policy.yaml>  — validate a policy file
    enforcecore verify <audit.jsonl>    — verify Merkle chain integrity
    enforcecore eval [--policy ...]     — run evaluation suite
    enforcecore info                    — show version, platform, installed extras
    enforcecore dry-run <policy.yaml> --tool <name>  — preview policy decision
    enforcecore inspect <audit.jsonl>   — explore audit trail entries

Requires the ``cli`` extra::

    pip install enforcecore[cli]
"""

import json
import platform
import sys
from pathlib import Path
from typing import Annotated

try:
    import typer
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print(
        "Error: The EnforceCore CLI requires extra dependencies.\n"
        "Install them with:\n\n"
        "    pip install enforcecore[cli]\n",
        file=sys.stderr,
    )
    raise SystemExit(1)  # noqa: B904

import enforcecore


def _version_callback(value: bool) -> None:
    """Print version and exit when --version is passed."""
    if value:
        print(f"enforcecore {enforcecore.__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="enforcecore",
    help="EnforceCore — runtime enforcement for agentic AI systems.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """EnforceCore — runtime enforcement for agentic AI systems."""


console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# enforcecore info
# ---------------------------------------------------------------------------


@app.command()
def info() -> None:
    """Show version, platform, Python, and installed extras."""
    table = Table(title="EnforceCore Info", show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan")
    table.add_column("Value")

    table.add_row("Version", enforcecore.__version__)
    table.add_row(
        "Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    table.add_row("Platform", platform.platform())
    table.add_row("Architecture", platform.machine())

    # Check optional extras
    extras: list[str] = []
    try:
        from importlib.metadata import version as _get_version

        extras.append(f"cli (typer {_get_version('typer')})")
    except (ImportError, Exception):  # pragma: no cover
        pass
    try:
        from importlib.metadata import version as _get_version2

        extras.append(f"rich ({_get_version2('rich')})")
    except (ImportError, Exception):  # pragma: no cover
        pass
    try:
        from importlib.metadata import version as _get_otel

        extras.append(f"telemetry (opentelemetry-sdk {_get_otel('opentelemetry-sdk')})")
    except (ImportError, Exception):  # pragma: no cover
        pass
    try:
        from importlib.metadata import version as _get_presidio

        extras.append(f"redactor (presidio-analyzer {_get_presidio('presidio-analyzer')})")
    except (ImportError, Exception):  # pragma: no cover
        pass

    table.add_row("Extras", ", ".join(extras) if extras else "none")
    table.add_row("Exports", str(len(enforcecore.__all__)))

    console.print(table)


# ---------------------------------------------------------------------------
# enforcecore validate
# ---------------------------------------------------------------------------


@app.command()
def validate(
    path: Annotated[Path, typer.Argument(help="Path to policy YAML file")],
) -> None:
    """Validate a policy YAML file against the schema."""
    from enforcecore.core.policy import Policy

    errors = Policy.validate_file(path)

    if errors:
        for err in errors:
            err_console.print(f"[red]✗[/red] {err}")
        raise typer.Exit(code=1)

    # Load to show summary
    policy = Policy.from_file(path)
    console.print(f"[green]✓[/green] Policy [bold]{policy.name}[/bold] v{policy.version} is valid")

    table = Table(show_header=False, pad_edge=False)
    table.add_column("Key", style="dim")
    table.add_column("Value")

    rules = policy.rules
    table.add_row("Allowed tools", str(rules.allowed_tools) if rules.allowed_tools else "all")
    table.add_row("Denied tools", str(rules.denied_tools) if rules.denied_tools else "none")
    table.add_row("PII redaction", "enabled" if rules.pii_redaction.enabled else "disabled")
    table.add_row("Content rules", "enabled" if rules.content_rules.enabled else "disabled")
    table.add_row("Rate limits", "enabled" if rules.rate_limits.enabled else "disabled")
    table.add_row("Network policy", "enabled" if rules.network.enabled else "disabled")
    table.add_row("On violation", policy.on_violation.value)
    console.print(table)


# ---------------------------------------------------------------------------
# enforcecore verify
# ---------------------------------------------------------------------------


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="Path to audit JSONL file")],
) -> None:
    """Verify Merkle chain integrity of an audit trail."""
    from enforcecore.auditor.engine import verify_trail

    if not path.exists():
        err_console.print(f"[red]✗[/red] File not found: {path}")
        raise typer.Exit(code=1)

    result = verify_trail(str(path))

    if result.is_valid:
        console.print(
            f"[green]✓[/green] Audit trail is [bold green]valid[/bold green] "
            f"({result.entries_checked} entries, chain intact)"
        )
    else:
        err_console.print(
            f"[red]✗[/red] Audit trail is [bold red]INVALID[/bold red]: {'; '.join(result.errors)}"
        )
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# enforcecore eval
# ---------------------------------------------------------------------------


@app.command(name="eval")
def eval_cmd(
    policy: Annotated[
        Path, typer.Option("--policy", "-p", help="Policy YAML file to evaluate against")
    ],
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show individual scenario results")
    ] = False,
) -> None:
    """Run the adversarial evaluation suite against a policy."""
    from enforcecore.core.policy import Policy as PolicyModel
    from enforcecore.eval.runner import ScenarioRunner

    pol = PolicyModel.from_file(policy)
    runner = ScenarioRunner(pol)
    suite = runner.run_all()

    # Summary
    color = (
        "green"
        if suite.containment_rate >= 0.9
        else "yellow"
        if suite.containment_rate >= 0.7
        else "red"
    )
    console.print(
        Panel(
            f"Containment rate: [{color}]{suite.containment_rate:.0%}[/{color}]  "
            f"({suite.contained}/{suite.total} scenarios contained)",
            title=f"Eval: {pol.name}",
        )
    )

    if verbose:
        table = Table(title="Scenario Results")
        table.add_column("Scenario", style="bold")
        table.add_column("Category")
        table.add_column("Severity")
        table.add_column("Result", justify="center")

        for r in suite.results:
            outcome_str = (
                "[green]✓ PASS[/green]" if r.outcome.value == "contained" else "[red]✗ FAIL[/red]"
            )
            table.add_row(
                r.scenario_name,
                r.category.value,
                r.severity.value,
                outcome_str,
            )
        console.print(table)

    if suite.containment_rate < 1.0:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# enforcecore dry-run
# ---------------------------------------------------------------------------


@app.command(name="dry-run")
def dry_run(
    policy_path: Annotated[Path, typer.Argument(help="Policy YAML file")],
    tool: Annotated[str, typer.Option("--tool", "-t", help="Tool name to test")] = "example_tool",
    arg: Annotated[
        list[str] | None, typer.Option("--arg", "-a", help="Key=value arguments")
    ] = None,
) -> None:
    """Preview what a policy would decide for a tool call without executing."""
    from enforcecore.core.policy import Policy as PolicyModel

    pol = PolicyModel.from_file(policy_path)

    # Parse key=value args
    kwargs: dict[str, str] = {}
    if arg:
        for a in arg:
            if "=" in a:
                k, v = a.split("=", 1)
                kwargs[k] = v
            else:
                kwargs[a] = ""

    result = pol.dry_run(tool, **kwargs)

    # Display
    decision = result["decision"]
    color = "green" if decision == "allowed" else "red"
    console.print(f"Tool: [bold]{tool}[/bold]  →  [{color}]{decision}[/{color}]")

    if result.get("reason"):
        console.print(f"  Reason: {result['reason']}")

    if result.get("content_violations"):
        console.print("  [yellow]Content violations:[/yellow]")
        for v in result["content_violations"]:
            console.print(f"    - {v['rule']}: matched '{v['matched']}'")

    if result.get("pii_redaction"):
        pii = result["pii_redaction"]
        console.print(f"  PII redaction: {pii['strategy']} ({', '.join(pii['categories'])})")

    if result.get("rate_limit"):
        rl = result["rate_limit"]
        console.print(f"  Rate limit: per_tool={rl['per_tool']}, global={rl['global']}")

    if result.get("network_policy"):
        net = result["network_policy"]
        console.print(
            f"  Network: allowed={net['allowed_domains']}, denied={net['denied_domains']}"
        )


# ---------------------------------------------------------------------------
# enforcecore inspect
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# enforcecore audit (sub-app)
# ---------------------------------------------------------------------------

audit_app = typer.Typer(
    name="audit",
    help="Audit trail management and compliance export commands.",
    no_args_is_help=True,
)
app.add_typer(audit_app)


@audit_app.command(name="export")
def audit_export(
    format_name: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Report format: eu-ai-act | soc2 | gdpr",
        ),
    ],
    period_label: Annotated[
        str,
        typer.Option(
            "--period",
            "-p",
            help="Reporting period: YYYY-Q{1-4}, YYYY-H{1-2}, or YYYY (e.g. 2026-Q4)",
        ),
    ],
    trail: Annotated[
        Path | None,
        typer.Option("--trail", "-t", help="Path to audit JSONL file"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path (.json or .html)"),
    ] = None,
    html: Annotated[
        bool,
        typer.Option("--html", help="Render as HTML instead of JSON"),
    ] = False,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", help="POST report to this URL (Vanta, Drata, etc.)"),
    ] = None,
    webhook_token: Annotated[
        str | None,
        typer.Option("--webhook-token", help="Bearer token for webhook authorization"),
    ] = None,
) -> None:
    """Export an audit trail as a structured compliance report.

    Examples::

        # Print EU AI Act JSON to stdout
        enforcecore audit export --format eu-ai-act --period 2026-Q4

        # Write to file
        enforcecore audit export --format soc2 --period 2026 --output soc2_2026.json

        # HTML report from a specific trail
        enforcecore audit export --format gdpr --period 2026-H1 \\
            --trail audit_logs/trail.jsonl --html --output gdpr_h1.html

        # Push to Vanta
        enforcecore audit export --format eu-ai-act --period 2026-Q4 \\
            --webhook-url https://app.vanta.com/api/v1/custom-tests/upload \\
            --webhook-token $VANTA_TOKEN
    """
    from enforcecore.compliance.reporter import ComplianceReporter
    from enforcecore.compliance.types import ComplianceError, ComplianceFormat, CompliancePeriod

    # Parse format
    try:
        fmt = ComplianceFormat(format_name)
    except ValueError:
        valid = ", ".join(f.value for f in ComplianceFormat)
        err_console.print(f"[red]✗[/red] Unknown format {format_name!r}. Valid options: {valid}")
        raise typer.Exit(code=1) from None

    # Parse period
    try:
        period = CompliancePeriod.from_label(period_label)
    except ValueError as exc:
        err_console.print(f"[red]✗[/red] Invalid period: {exc}")
        raise typer.Exit(code=1) from exc

    reporter = ComplianceReporter(trail_path=trail)

    try:
        if html and output:
            reporter.export_html(fmt, period, output)
            console.print(f"[green]✓[/green] HTML report written to [bold]{output}[/bold]")
        elif output:
            reporter.export_json(fmt, period, output)
            console.print(f"[green]✓[/green] JSON report written to [bold]{output}[/bold]")
        else:
            # Print to stdout
            report = reporter.export(fmt, period)
            print(report.to_json())  # intentional stdout output

        if webhook_url:
            if not webhook_token:
                err_console.print(
                    "[red]✗[/red] --webhook-token is required when --webhook-url is set"
                )
                raise typer.Exit(code=1)
            report = reporter.export(fmt, period)
            try:
                reporter.send_webhook(report, url=webhook_url, token=webhook_token)
                console.print(f"[green]✓[/green] Report sent to webhook: {webhook_url}")
            except ComplianceError as exc:
                err_console.print(f"[red]✗[/red] Webhook failed: {exc}")
                raise typer.Exit(code=1) from exc

    except ComplianceError as exc:
        err_console.print(f"[red]✗[/red] Compliance export failed: {exc}")
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# enforcecore inspect
# ---------------------------------------------------------------------------


@app.command()
def inspect(
    path: Annotated[Path, typer.Argument(help="Path to audit JSONL file")],
    tail: Annotated[int, typer.Option("--tail", "-n", help="Show last N entries")] = 10,
    tool_filter: Annotated[
        str | None, typer.Option("--tool", "-t", help="Filter by tool name")
    ] = None,
    decision_filter: Annotated[
        str | None, typer.Option("--decision", "-d", help="Filter by decision (allowed/blocked)")
    ] = None,
) -> None:
    """Explore and filter audit trail entries."""
    if not path.exists():
        err_console.print(f"[red]✗[/red] File not found: {path}")
        raise typer.Exit(code=1)

    entries: list[dict[str, object]] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Apply filters
            if tool_filter and entry.get("tool_name") != tool_filter:
                continue
            if decision_filter and entry.get("decision") != decision_filter:
                continue

            entries.append(entry)

    if not entries:
        console.print("[dim]No matching entries found.[/dim]")
        return

    # Show last N
    shown = entries[-tail:]

    table = Table(title=f"Audit Trail ({len(shown)} of {len(entries)} entries)")
    table.add_column("#", style="dim")
    table.add_column("Tool", style="bold")
    table.add_column("Decision", justify="center")
    table.add_column("Policy")
    table.add_column("Duration", justify="right")
    table.add_column("Redactions", justify="right")

    for i, entry in enumerate(shown, 1):
        dec = entry.get("decision", "?")
        dec_color = "green" if dec == "allowed" else "red"
        duration = entry.get("call_duration_ms") or entry.get("duration_ms")
        dur_str = f"{duration:.1f}ms" if isinstance(duration, int | float) else "?"
        redactions = entry.get("input_redactions", 0)
        out_redactions = entry.get("output_redactions", 0)
        redact_in = int(redactions) if isinstance(redactions, int | float) else 0
        redact_out = int(out_redactions) if isinstance(out_redactions, int | float) else 0
        total_redactions = redact_in + redact_out

        table.add_row(
            str(i),
            str(entry.get("tool_name", "?")),
            f"[{dec_color}]{dec}[/{dec_color}]",
            str(entry.get("policy_name", "?")),
            dur_str,
            str(total_redactions) if total_redactions else "-",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# enforcecore plugin (sub-app)
# ---------------------------------------------------------------------------

plugin_app = typer.Typer(
    name="plugin",
    help="Discover and inspect installed EnforceCore plugins.",
    no_args_is_help=True,
)
app.add_typer(plugin_app)


@plugin_app.command(name="list")
def plugin_list(
    kind: Annotated[
        str | None,
        typer.Option(
            "--kind",
            "-k",
            help="Filter by plugin kind: guard | redactor | audit_backend",
        ),
    ] = None,
) -> None:
    """List all installed EnforceCore plugins.

    Plugins are discovered from installed packages via their
    ``enforcecore.guards``, ``enforcecore.redactors``, and
    ``enforcecore.audit_backends`` entry points.

    Examples::

        # List all plugins
        enforcecore plugin list

        # List only guard plugins
        enforcecore plugin list --kind guard
    """
    from enforcecore.plugins.manager import PluginManager

    manager = PluginManager()
    plugins = manager.discover()

    if kind:
        plugins = [p for p in plugins if p.kind == kind]

    if not plugins:
        console.print("[dim]No EnforceCore plugins found.[/dim]")
        console.print(
            "[dim]Install plugins with pip, e.g.: pip install enforcecore-guard-toxicity[/dim]"
        )
        return

    table = Table(title=f"Installed EnforceCore Plugins ({len(plugins)})")
    table.add_column("Name", style="bold")
    table.add_column("Kind", style="cyan")
    table.add_column("Version")
    table.add_column("Entry Point", style="dim")

    kind_colors = {
        "guard": "green",
        "redactor": "yellow",
        "audit_backend": "blue",
    }
    for p in sorted(plugins, key=lambda x: (x.kind, x.name)):
        color = kind_colors.get(p.kind, "white")
        table.add_row(
            p.name,
            f"[{color}]{p.kind}[/{color}]",
            p.version or "[dim]unknown[/dim]",
            p.package,
        )

    console.print(table)


@plugin_app.command(name="info")
def plugin_info(
    name: Annotated[str, typer.Argument(help="Plugin entry-point name")],
) -> None:
    """Show details about an installed EnforceCore plugin.

    Loads the plugin class to inspect its metadata.

    Examples::

        enforcecore plugin info toxicity-guard
        enforcecore plugin info employee-id-redactor
    """
    from enforcecore.plugins.manager import PluginLoadError, PluginManager

    manager = PluginManager()
    discovered = {p.name: p for p in manager.discover()}

    if name not in discovered:
        err_console.print(f"[red]✗[/red] Plugin {name!r} not found.")
        err_console.print(
            "[dim]Run [bold]enforcecore plugin list[/bold] to see available plugins.[/dim]"
        )
        raise typer.Exit(code=1)

    info = discovered[name]

    # Try to load it to get the instance repr
    instance_repr = "[dim]not loaded[/dim]"
    categories_str = ""
    try:
        manager.load(name)
        if manager.guards:
            g_inst = manager.guards[0]
            instance_repr = repr(g_inst)
        elif manager.redactors:
            r_inst = manager.redactors[0]
            instance_repr = repr(r_inst)
            categories_str = ", ".join(r_inst.categories)
        elif manager.audit_backends:
            b_inst = manager.audit_backends[0]
            instance_repr = repr(b_inst)
    except PluginLoadError as exc:
        instance_repr = f"[red]Load error: {exc}[/red]"

    panel_content = (
        f"[bold]Name:[/bold]        {info.name}\n"
        f"[bold]Kind:[/bold]        {info.kind}\n"
        f"[bold]Version:[/bold]     {info.version or 'unknown'}\n"
        f"[bold]Entry point:[/bold] {info.package}\n"
    )
    if categories_str:
        panel_content += f"[bold]Categories:[/bold]  {categories_str}\n"
    panel_content += f"[bold]Instance:[/bold]    {instance_repr}"

    console.print(Panel(panel_content, title=f"Plugin: {info.name}", expand=False))
