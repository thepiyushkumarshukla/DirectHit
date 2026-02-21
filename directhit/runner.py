"""Recon runners for DirectHit."""

from __future__ import annotations

import logging
import shlex
import subprocess
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def _dedupe_lines(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for line in lines:
        url = line.strip()
        if url and url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered


def run_katana_gf(target: str, output_file: Path) -> list[str]:
    """Run katana + gf redirect pipeline and de-duplicate promising URLs."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    # Required pipeline form from project spec.
    cmd = f"echo {shlex.quote(target)} | katana | gf redirect >> {shlex.quote(str(output_file))}"
    proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, check=False)

    if proc.returncode != 0:
        LOGGER.warning("katana/gf exited with status %s", proc.returncode)
    if proc.stderr.strip():
        LOGGER.warning("katana/gf stderr: %s", proc.stderr.strip())

    if not output_file.exists():
        return []

    file_urls = _dedupe_lines(output_file.read_text(encoding="utf-8", errors="ignore").splitlines())
    return file_urls


def load_urls_from_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    return _dedupe_lines(path.read_text(encoding="utf-8", errors="ignore").splitlines())
