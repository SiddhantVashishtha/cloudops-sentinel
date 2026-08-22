"""
CloudOps Sentinel CLI.

Entry point for running scans against an AWS account.
"""

from __future__ import annotations

import time

import typer
from rich.console import Console
from rich.table import Table

from sentinel.engine.findings import ScanResult, Severity
from sentinel.engine.scoring import calculate_score
from sentinel.scanners import ec2, s3, iam, security_groups
from sentinel.utils.aws_session import get_region, verify_credentials
from sentinel.reports.json_report import write_json_report

app = typer.Typer(help="CloudOps Sentinel — AWS security & compliance scanner")
@app.callback()
def main():
    """CloudOps Sentinel CLI."""
    pass
console = Console()

# Registry of available scanners: name -> scan function
SCANNERS = {
    "ec2": ec2.scan,
    "s3": s3.scan,
    "iam": iam.scan,
    "security-groups": security_groups.scan,
}


@app.command()
def scan(
    service: str = typer.Option(None, help="Scan only one service (ec2, s3, iam, security-groups)"),
    region: str = typer.Option(None, help="AWS region to scan. Defaults to configured region."),
    output: str = typer.Option(None, "--output", "-o", help="Write JSON report to this file path."),
):
    """Run a security scan against your AWS account."""
    region = region or get_region()

    console.print("\n[bold cyan]CLOUDOPS SENTINEL[/bold cyan]")
    console.print("[dim]AWS Security & Compliance Scanner[/dim]\n")

    # Verify credentials before doing anything else.
    try:
        identity = verify_credentials()
        console.print(f"[green]✓[/green] Authenticated as: {identity['arn']}")
        console.print(f"[green]✓[/green] Region: {region}\n")
    except RuntimeError as e:
        console.print(f"[bold red]✗ AWS authentication failed:[/bold red] {e}")
        raise typer.Exit(code=1)

    # Decide which scanners to run.
    if service:
        if service not in SCANNERS:
            console.print(f"[bold red]Unknown service:[/bold red] {service}")
            console.print(f"Available: {', '.join(SCANNERS.keys())}")
            raise typer.Exit(code=1)
        scanners_to_run = {service: SCANNERS[service]}
    else:
        scanners_to_run = SCANNERS

    result = ScanResult(region=region)
    start_time = time.time()

    for name, scan_fn in scanners_to_run.items():
        console.print(f"Scanning [bold]{name}[/bold]...", end=" ")
        try:
            findings = scan_fn(region=region)
            for f in findings:
                result.add(f)
            result.services_scanned.append(name)
            console.print("[green]✓[/green]")
        except Exception as e:
            console.print(f"[bold red]✗ ({e})[/bold red]")

        result.scan_duration_seconds = round(time.time() - start_time, 2)
            # NOTE: resources_scanned is currently a proxy (findings count), not a true
    # count of resources inspected. Scanners would need to report resource
    # counts directly for full accuracy — noted as a known limitation.
    result.resources_scanned = len(result.findings)

    score_result = calculate_score(result)
    _print_summary(result, score_result)

    if output:
        path = write_json_report(result, score_result, output)
        console.print(f"[dim]Report written to: {path}[/dim]\n")


def _print_summary(result: ScanResult, score_result) -> None:
    """Print the severity breakdown table and risk score."""
    counts = result.severity_counts()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }

    for severity in Severity:
        count = counts[severity.value]
        color = severity_colors.get(severity.value, "white")
        table.add_row(f"[{color}]{severity.value}[/{color}]", str(count))

    console.print()
    console.print(table)

    status_colors = {"PASS": "bold green", "WARNING": "bold yellow", "FAIL": "bold red"}
    status_color = status_colors.get(score_result.status, "white")

    console.print(f"\n[bold]Sentinel Risk Score:[/bold] {score_result.score}/100")
    console.print(f"[bold]Status:[/bold] [{status_color}]{score_result.status}[/{status_color}]")
    console.print(f"\n[dim]Scanned {len(result.findings)} findings across {len(result.services_scanned)} services in {result.scan_duration_seconds}s[/dim]\n")


if __name__ == "__main__":
    app()