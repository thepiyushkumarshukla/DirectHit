# DirectHit

DirectHit is a production-ready Python CLI for ethically hunting open-redirect vulnerabilities. It chains reconnaissance (`katana | gf redirect`) with async payload testing and strict verification to minimize false positives.

## Legal & Ethics

DirectHit must only be used against targets you are explicitly authorized to test.

You **must** pass:

```bash
--ethics-confirm I_own_or_have_permission
```

Without this flag/value, DirectHit exits immediately.

## Features

- `directhit scan <target>` runs:
  - `echo '<target>' | katana | gf redirect`
  - Captures stdout, appends to `promising_redirect_urls`, de-duplicates, then analyzes.
- `directhit analyze --file promising_redirect_urls` analyzes existing URLs.
- Async concurrency (`asyncio` + `httpx`) and per-domain rate-limiting.
- Better terminal rendering:
  - dark banner style
  - progress bar while analyzing URLs
  - summary panel with processed count and confirmed findings
- False-positive protection:
  - Confirms only if final URL is `https://google.com` or `https://www.google.com`.
  - Accepts only verified redirect behaviors (3xx `Location`, final URL resolution, meta-refresh).
  - Includes deterministic double-check with alternate UA.
- Human-readable rich table + machine-readable `findings.json`.
- Audit log written to `directhit.log`.
- CSV export support.

> Note: no scanner can guarantee 100% coverage of all redirect paths. DirectHit is optimized to reduce false positives and provide high-confidence findings.

## Install

### 1) Ensure Go and PATH

```bash
export PATH=$PATH:$HOME/go/bin
```

### 2) Install Katana

```bash
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
```

### 3) Install gf

```bash
go install github.com/tomnomnom/gf@latest
cp $(go env GOPATH)/pkg/mod/github.com/tomnomnom/gf@*/examples/* ~/.gf || true
```

### 4) Install GF redirect patterns

```bash
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf_patterns
mkdir -p ~/.gf
cp ~/.gf_patterns/*.json ~/.gf
```

### 5) Python dependencies

```bash
pip install -r requirements.txt
```

### Optional one-shot installer

```bash
./install_deps.sh
```

## Usage

```bash
python -m directhit scan https://getmarlee.com/ \
  --ethics-confirm I_own_or_have_permission \
  --concurrency 8 \
  --timeout 10
```

```bash
python -m directhit analyze \
  --file promising_redirect_urls \
  --target https://getmarlee.com/ \
  --ethics-confirm I_own_or_have_permission \
  --output findings.json
```

```bash
python -m directhit install-deps
```

## Exit codes

- `0`: completed, no confirmed findings.
- `10`: one or more confirmed vulnerabilities.
- non-zero Click errors: invalid usage, invalid target URL, missing ethics confirmation.

## Output format (`findings.json`)

```json
[
  {
    "target": "https://getmarlee.com/",
    "vulnerable_url": "https://target/path?redirect=...",
    "param": "redirect",
    "payload": "https://www.google.com/",
    "verification": "final_url_match",
    "final_url": "https://www.google.com/",
    "timestamp": "2026-01-01T00:00:00+00:00",
    "request_sample": {
      "method": "GET",
      "headers": {},
      "raw_request": "GET https://target/..."
    }
  }
]
```

## Tests

```bash
pytest -q
```

## Notes

- DirectHit does **not** perform destructive actions.
- It does not attempt authenticated workflow chaining.
- It only performs safe redirect validation requests and logs results for reproducibility.
