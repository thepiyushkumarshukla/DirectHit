"""Open-redirect analyzer for DirectHit."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Iterable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from .net import AsyncRequester

REDIRECT_HINTS = {
    "url",
    "redirect",
    "next",
    "dest",
    "return",
    "rurl",
    "callback",
    "continue",
    "redir",
    "goto",
}

LOGGER = logging.getLogger(__name__)
ProgressCallback = Callable[[int, int], Awaitable[None] | None]


@dataclass(slots=True)
class Finding:
    target: str
    vulnerable_url: str
    param: str
    payload: str
    verification: str
    final_url: str
    timestamp: str
    request_sample: dict

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Candidate:
    url: str
    param: str


def _norm_host(host: str | None) -> str:
    return (host or "").lower().strip(".")


def _is_google_https(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and _norm_host(parsed.hostname) in {"google.com", "www.google.com"}


def _contains_redirect_signal(value: str) -> bool:
    low = value.lower()
    return any(token in low for token in ("http", "%2f", "google.com", "//", "www."))


def _looks_like_urlish_param(name: str, values: list[str]) -> bool:
    if name.lower() in REDIRECT_HINTS:
        return True
    return any(_contains_redirect_signal(v) for v in values)


def extract_candidates(url: str) -> list[Candidate]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    candidates: list[Candidate] = []
    for name, values in params.items():
        if _looks_like_urlish_param(name, values):
            candidates.append(Candidate(url=url, param=name))
    return candidates


def dedupe_urls_for_scan(urls: list[str]) -> list[str]:
    """Reduce duplicate heavy URLs (e.g. image width variants) for faster scans."""
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()
    output: list[str] = []
    for raw in urls:
        p = urlparse(raw)
        params = tuple(sorted(parse_qs(p.query, keep_blank_values=True).keys()))
        sig = (p.scheme, p.netloc, p.path, params)
        if sig in seen:
            continue
        seen.add(sig)
        output.append(raw)
    return output


def build_payloads(fast: bool = True) -> list[str]:
    unique = uuid.uuid4().hex[:8]
    core = [
        "https://www.google.com/",
        "https://google.com/",
        "//www.google.com/",
        "https%3A%2F%2Fwww.google.com%2F",
        "https://www.google.com/%2F",
        f"https://www.google.com/?q=directhit-{unique}&dh_token={uuid.uuid4().hex}",
    ]
    if fast:
        return core
    return core + [
        "https:%2F%2Fwww.google.com%2F",
        "https%253A%252F%252Fwww.google.com%252F",
        "/https://www.google.com",
        "/\\/\\/www.google.com",
        "../../https://www.google.com/",
        "#https://www.google.com",
        "http://www.google.com/",
    ]


def inject_payload(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [payload]
    encoded = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded, parsed.fragment))


def _extract_meta_refresh(body: str) -> str | None:
    match = re.search(
        r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"'][^\"']*url\s*=\s*([^\"'>]+)",
        body,
        flags=re.IGNORECASE,
    )
    return match.group(1).strip() if match else None


def _extract_js_redirect(body: str) -> str | None:
    for pattern in (
        r"window\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]",
        r"location\.replace\(['\"]([^'\"]+)['\"]\)",
    ):
        match = re.search(pattern, body, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def verify_redirect(base_url: str, initial_status: int, location: str | None, final_url: str, body: str) -> tuple[bool, str]:
    if _is_google_https(final_url):
        return True, "final_url_match"

    if initial_status in {301, 302, 303, 307, 308} and location:
        resolved = urljoin(base_url, location)
        if _is_google_https(resolved):
            return True, "location_header"

    meta_url = _extract_meta_refresh(body)
    if meta_url and _is_google_https(urljoin(base_url, meta_url)):
        return True, "meta_refresh"

    js_url = _extract_js_redirect(body)
    if js_url and _is_google_https(urljoin(base_url, js_url)) and _is_google_https(final_url):
        return True, "js_redirect"

    return False, "none"


class RedirectAnalyzer:
    """Analyze URLs for open redirect flaws."""

    def __init__(
        self,
        requester: AsyncRequester,
        timeout: float = 8.0,
        methods: Iterable[str] = ("GET",),
        deterministic_check: bool = False,
        fast_mode: bool = True,
    ) -> None:
        self.requester = requester
        self.timeout = timeout
        self.methods = tuple(methods)
        self.deterministic_check = deterministic_check
        self.fast_mode = fast_mode

    async def analyze_urls(self, target: str, urls: list[str], progress_callback: ProgressCallback | None = None) -> list[Finding]:
        urls = dedupe_urls_for_scan(urls)
        findings: list[Finding] = []
        tasks = [asyncio.create_task(self._analyze_single(target, url)) for url in urls]
        total = len(tasks)
        completed = 0
        for task in asyncio.as_completed(tasks):
            result = await task
            completed += 1
            if progress_callback:
                ret = progress_callback(completed, total)
                if asyncio.iscoroutine(ret):
                    await ret
            if result:
                findings.append(result)
        return findings

    async def _analyze_single(self, target: str, url: str) -> Finding | None:
        candidates = extract_candidates(url)
        if not candidates:
            return None

        for candidate in candidates:
            for payload in build_payloads(fast=self.fast_mode):
                injected = inject_payload(candidate.url, candidate.param, payload)
                for method in self.methods:
                    headers = {
                        "Referer": target,
                        "X-Forwarded-Host": "www.google.com",
                    }
                    try:
                        bundle = await self.requester.fetch(injected, method=method, headers=headers)
                    except Exception as exc:  # noqa: BLE001
                        LOGGER.debug("request error for %s: %s", injected, exc)
                        continue

                    ok, verification = verify_redirect(
                        base_url=injected,
                        initial_status=bundle.initial_response.status_code,
                        location=bundle.initial_response.headers.get("Location"),
                        final_url=str(bundle.final_response.url),
                        body=bundle.final_response.text,
                    )
                    if ok and self.deterministic_check and not await self._double_check(injected, method):
                        continue

                    if ok:
                        return Finding(
                            target=target,
                            vulnerable_url=url,
                            param=candidate.param,
                            payload=payload,
                            verification=verification,
                            final_url=str(bundle.final_response.url),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            request_sample={
                                "method": method,
                                "headers": headers,
                                "raw_request": f"{method} {injected}",
                            },
                        )
        return None

    async def _double_check(self, url: str, method: str) -> bool:
        try:
            bundle = await self.requester.fetch(
                url,
                method=method,
                headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/121.0"},
            )
        except Exception:  # noqa: BLE001
            return False

        ok, _ = verify_redirect(
            base_url=url,
            initial_status=bundle.initial_response.status_code,
            location=bundle.initial_response.headers.get("Location"),
            final_url=str(bundle.final_response.url),
            body=bundle.final_response.text,
        )
        return ok
