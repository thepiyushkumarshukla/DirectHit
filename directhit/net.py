"""Networking primitives for DirectHit."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from types import SimpleNamespace
from urllib.parse import urlparse
import urllib.error
import urllib.request

try:
    import httpx  # type: ignore
except Exception:  # noqa: BLE001
    httpx = None


@dataclass(slots=True)
class HttpResponseBundle:
    """Container for probe responses."""

    method: str
    initial_response: object
    final_response: object


class DomainRateLimiter:
    """Simple per-domain request rate limiter."""

    def __init__(self, requests_per_second: float = 5.0) -> None:
        self.requests_per_second = max(0.1, requests_per_second)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def wait(self, url: str) -> None:
        domain = (urlparse(url).hostname or "").lower()
        if not domain:
            return

        window = 1.0
        async with self._lock:
            now = time.monotonic()
            events = self._events[domain]
            while events and now - events[0] > window:
                events.popleft()

            if len(events) >= self.requests_per_second:
                sleep_for = window - (now - events[0])
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                    now = time.monotonic()
                    while events and now - events[0] > window:
                        events.popleft()
            events.append(time.monotonic())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _FallbackClient:
    def __init__(self, timeout: float, follow_redirects: bool) -> None:
        self.timeout = timeout
        self.follow_redirects = follow_redirects

    async def request(self, method: str, url: str, headers: dict[str, str] | None = None):
        def _sync_request():
            req = urllib.request.Request(url=url, method=method, headers=headers or {})
            opener = urllib.request.build_opener() if self.follow_redirects else urllib.request.build_opener(_NoRedirect)
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    return SimpleNamespace(
                        status_code=resp.getcode(),
                        headers=dict(resp.headers.items()),
                        text=body,
                        url=resp.geturl(),
                    )
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
                return SimpleNamespace(
                    status_code=exc.code,
                    headers=dict(exc.headers.items()) if exc.headers else {},
                    text=body,
                    url=url,
                )
            except Exception:
                return SimpleNamespace(status_code=0, headers={}, text="", url=url)

        return await asyncio.to_thread(_sync_request)

    async def aclose(self) -> None:
        return


class AsyncRequester:
    """HTTP wrapper with concurrency and per-domain throttling."""

    def __init__(
        self,
        timeout: float = 10.0,
        concurrency: int = 10,
        user_agent: str | None = None,
        requests_per_second: float = 5.0,
    ) -> None:
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max(1, concurrency))
        self.rate_limiter = DomainRateLimiter(requests_per_second=requests_per_second)
        ua = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self._headers = {"User-Agent": ua}
        if httpx:
            self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=False, http2=True)
            self._follow_client = httpx.AsyncClient(timeout=timeout, follow_redirects=True, http2=True)
        else:
            self._client = _FallbackClient(timeout=timeout, follow_redirects=False)
            self._follow_client = _FallbackClient(timeout=timeout, follow_redirects=True)

    async def aclose(self) -> None:
        await self._client.aclose()
        await self._follow_client.aclose()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HttpResponseBundle:
        merged_headers = dict(self._headers)
        if headers:
            merged_headers.update(headers)

        async with self.semaphore:
            await self.rate_limiter.wait(url)
            initial = await self._client.request(method, url, headers=merged_headers)
            await self.rate_limiter.wait(url)
            final = await self._follow_client.request(method, url, headers=merged_headers)
            return HttpResponseBundle(method=method, initial_response=initial, final_response=final)
