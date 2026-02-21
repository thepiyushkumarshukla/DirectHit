from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from directhit.analyzer import RedirectAnalyzer, build_payloads, dedupe_urls_for_scan, verify_redirect
from directhit.net import AsyncRequester


def test_payloads_include_core_variants() -> None:
    payloads = build_payloads()
    assert "https://www.google.com/" in payloads
    assert "//www.google.com/" in payloads
    assert "https%3A%2F%2Fwww.google.com%2F" in payloads


def test_dedupe_urls_for_scan_reduces_noisy_variants() -> None:
    urls = [
        "https://t.com/_next/image?url=%2Fa.jpg&w=16&q=75",
        "https://t.com/_next/image?url=%2Fa.jpg&w=32&q=75",
        "https://t.com/_next/image?url=%2Fa.jpg&w=64&q=75",
    ]
    out = dedupe_urls_for_scan(urls)
    assert len(out) == 1


def test_verify_redirect_location_header_accepts_google() -> None:
    ok, method = verify_redirect(
        base_url="https://example.com/login?next=abc",
        initial_status=302,
        location="https://www.google.com/",
        final_url="https://www.google.com/",
        body="",
    )
    assert ok is True
    assert method in {"location_header", "final_url_match"}


def test_verify_redirect_rejects_reflection_only() -> None:
    body = "you asked for https://www.google.com/ but no redirect"
    ok, method = verify_redirect(
        base_url="https://example.com/path",
        initial_status=200,
        location=None,
        final_url="https://example.com/path",
        body=body,
    )
    assert ok is False
    assert method == "none"


class RedirectTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/redirect":
            nxt = params.get("url", [""])[0]
            if "google.com" in nxt:
                self.send_response(302)
                self.send_header("Location", "https://www.google.com/")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"echo only")
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        return


def test_integration_redirect_vs_echo() -> None:
    async def run_case() -> list:
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectTestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        base = f"http://127.0.0.1:{server.server_port}"
        urls = [
            f"{base}/redirect?url=/dashboard&w=16&q=75",
            f"{base}/echo?next=http://example.com",
        ]

        requester = AsyncRequester(timeout=3, concurrency=4)
        analyzer = RedirectAnalyzer(requester)
        findings = await analyzer.analyze_urls(base, urls)

        await requester.aclose()
        server.shutdown()
        server.server_close()
        return findings

    findings = asyncio.run(run_case())
    assert len(findings) == 1
    assert findings[0].param == "url"
