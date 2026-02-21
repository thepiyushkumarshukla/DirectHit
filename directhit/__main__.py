"""DirectHit CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from urllib.parse import urlparse

import click

try:
    import ujson as fast_json
except Exception:  # noqa: BLE001
    fast_json = None

from .analyzer import RedirectAnalyzer
from .net import AsyncRequester
from .runner import load_urls_from_file, run_katana_gf
from .ui import build_progress, console, export_csv, print_banner, print_legal_notice, render_findings, render_summary


@click.group()
def cli() -> None:
    """DirectHit - Open redirect hunter."""


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        filename="directhit.log",
        filemode="a",
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )


def _validate_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise click.ClickException(f"Invalid target URL: {value}")


def _write_json(path: Path, payload: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fast_json:
        path.write_text(fast_json.dumps(payload, indent=2), encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


async def _analyze(target: str, urls: list[str], concurrency: int, timeout: float, user_agent: str | None) -> list[dict]:
    requester = AsyncRequester(timeout=timeout, concurrency=concurrency, user_agent=user_agent)
    try:
        analyzer = RedirectAnalyzer(
            requester=requester,
            timeout=timeout,
            deterministic_check=False,
            fast_mode=True,
            methods=("GET",),
        )
        progress, task_id = build_progress(len(urls))

        async def _progress_update(done: int, total: int) -> None:
            if progress and task_id is not None:
                progress.update(task_id, completed=done, total=total)

        if progress:
            with progress:
                findings = await analyzer.analyze_urls(target=target, urls=urls, progress_callback=_progress_update)
        else:
            findings = await analyzer.analyze_urls(target=target, urls=urls)

        return [f.to_dict() for f in findings]
    finally:
        await requester.aclose()


@cli.command()
@click.argument("target")
@click.option("--concurrency", default=20, show_default=True, type=int)
@click.option("--timeout", default=8.0, show_default=True, type=float)
@click.option("--user-agent", default=None)
@click.option("--output", default="findings.json", show_default=True)
@click.option("--export-csv", default=None)
@click.option("--output-dir", default=".", show_default=True)
@click.option("--quiet", is_flag=True)
@click.option("--banner-off", is_flag=True)
def scan(
    target: str,
    concurrency: int,
    timeout: float,
    user_agent: str | None,
    output: str,
    export_csv: str | None,
    output_dir: str,
    quiet: bool,
    banner_off: bool,
) -> None:
    """Run katana|gf redirect then analyze URLs."""
    _setup_logging(verbose=not quiet)
    _validate_url(target)
    if not quiet:
        print_legal_notice()
    if not banner_off and not quiet:
        print_banner()

    out_dir = Path(output_dir)
    candidates_file = out_dir / "promising_redirect_urls"
    urls = run_katana_gf(target, candidates_file)
    if not urls:
        console.print("[yellow]No promising URLs returned by katana|gf.[/yellow]")
        _write_json(out_dir / output, [])
        raise SystemExit(0)

    findings = asyncio.run(_analyze(target, urls, concurrency, timeout, user_agent))
    _write_json(out_dir / output, findings)
    render_findings([] if not findings else [_dict_to_finding(f) for f in findings])
    render_summary(total_urls=len(urls), findings=len(findings))

    if export_csv:
        export_csv_path = out_dir / export_csv
        export_csv([_dict_to_finding(f) for f in findings], export_csv_path)

    if findings:
        raise SystemExit(10)


@cli.command()
@click.option("--file", "file_path", default="promising_redirect_urls", show_default=True)
@click.option("--target", default="unknown-target")
@click.option("--concurrency", default=20, show_default=True, type=int)
@click.option("--timeout", default=8.0, show_default=True, type=float)
@click.option("--user-agent", default=None)
@click.option("--output", default="findings.json", show_default=True)
@click.option("--export-csv", default=None)
@click.option("--output-dir", default=".", show_default=True)
@click.option("--quiet", is_flag=True)
@click.option("--banner-off", is_flag=True)
def analyze(
    file_path: str,
    target: str,
    concurrency: int,
    timeout: float,
    user_agent: str | None,
    output: str,
    export_csv: str | None,
    output_dir: str,
    quiet: bool,
    banner_off: bool,
) -> None:
    """Analyze an existing file of URLs."""
    _setup_logging(verbose=not quiet)
    if not quiet:
        print_legal_notice()
    if target != "unknown-target":
        _validate_url(target)
    if not banner_off and not quiet:
        print_banner()

    out_dir = Path(output_dir)
    urls = load_urls_from_file(Path(file_path))
    findings = asyncio.run(_analyze(target, urls, concurrency, timeout, user_agent)) if urls else []
    _write_json(out_dir / output, findings)
    render_findings([] if not findings else [_dict_to_finding(f) for f in findings])
    render_summary(total_urls=len(urls), findings=len(findings))

    if export_csv:
        export_csv_path = out_dir / export_csv
        export_csv([_dict_to_finding(f) for f in findings], export_csv_path)

    if findings:
        raise SystemExit(10)


@cli.command("install-deps")
def install_deps() -> None:
    """Print dependency installation commands."""
    commands = [
        "export PATH=$PATH:$HOME/go/bin",
        "CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "go install github.com/tomnomnom/gf@latest",
        "cp $(go env GOPATH)/pkg/mod/github.com/tomnomnom/gf@*/examples/* ~/.gf || true",
        "git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf_patterns",
        "mkdir -p ~/.gf",
        "cp ~/.gf_patterns/*.json ~/.gf",
        "pip install -r requirements.txt",
    ]
    console.print("\n".join(commands))


def _dict_to_finding(item: dict):
    from .analyzer import Finding

    return Finding(**item)


if __name__ == "__main__":
    cli()
