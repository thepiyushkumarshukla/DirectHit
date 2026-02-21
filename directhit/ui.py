"""UI helpers for DirectHit."""

from __future__ import annotations

from pathlib import Path

try:
    from pyfiglet import Figlet
except Exception:  # noqa: BLE001
    Figlet = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
except Exception:  # noqa: BLE001
    Console = None
    Panel = None
    Progress = None
    SpinnerColumn = None
    TextColumn = None
    BarColumn = None
    TimeElapsedColumn = None
    Table = None

from .analyzer import Finding


class _FallbackConsole:
    def print(self, message):
        print(message)


console = Console() if Console else _FallbackConsole()


def print_banner() -> None:
    title = "DirectHit"
    if Figlet:
        title = Figlet(font="slant").renderText("DirectHit")
    subtitle = "Open-Redirect Hunter — Piyush Shukla"
    if Panel:
        panel = Panel.fit(
            f"[bold cyan]{title}[/bold cyan]\n[white]{subtitle}[/white]\n[dim]Dark mode optimized terminal output[/dim]",
            border_style="cyan",
        )
        console.print(panel)
    else:
        console.print(title)
        console.print(subtitle)


def print_legal_notice() -> None:
    text = (
        "[bold yellow]Legal Notice:[/bold yellow] Scan only targets where you have explicit permission. "
        "DirectHit is for authorized security testing only."
    )
    if Panel:
        console.print(Panel(text, border_style="yellow"))
    else:
        console.print(text)


def build_progress(total: int):
    if not Progress:
        return None, None
    progress = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        transient=True,
    )
    task_id = progress.add_task("Analyzing promising redirect URLs", total=total)
    return progress, task_id


def render_findings(findings: list[Finding]) -> None:
    if not Table:
        if not findings:
            console.print("No confirmed findings.")
            return
        for finding in findings:
            console.print(f"VULNERABLE {finding.vulnerable_url} param={finding.param} via {finding.verification}")
        return

    table = Table(title="DirectHit Findings", header_style="bold cyan")
    table.add_column("URL", style="cyan", overflow="fold")
    table.add_column("Param", style="white")
    table.add_column("Payload", style="magenta", overflow="fold")
    table.add_column("Verification", style="green")
    table.add_column("Status", style="bold")

    if not findings:
        table.add_row("-", "-", "-", "-", "SAFE")
    else:
        for finding in findings:
            table.add_row(
                finding.vulnerable_url,
                finding.param,
                finding.payload,
                finding.verification,
                "VULNERABLE",
            )
    console.print(table)


def render_summary(total_urls: int, findings: int) -> None:
    summary = f"Processed URLs: [cyan]{total_urls}[/cyan]\nConfirmed findings: [red]{findings}[/red]"
    if Panel:
        console.print(Panel(summary, title="Run Summary", border_style="cyan"))
    else:
        console.print(f"Processed URLs: {total_urls} | Confirmed findings: {findings}")


def export_csv(findings: list[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = ["target,vulnerable_url,param,payload,verification,final_url,timestamp"]
    for f in findings:
        rows.append(
            ",".join(
                [
                    f.target,
                    f.vulnerable_url,
                    f.param,
                    f.payload.replace(",", "%2C"),
                    f.verification,
                    f.final_url,
                    f.timestamp,
                ]
            )
        )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
