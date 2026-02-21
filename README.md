# DirectHit

DirectHit is a Python CLI for hunting open-redirect vulnerabilities with strict verification and faster URL analysis.

## Legal Use

Use this tool only on targets you are explicitly authorized to test.

## What changed (speed + reliability)

- Faster analysis defaults:
  - default concurrency increased to `20`
  - default timeout lowered to `8s`
  - GET-only checks by default (no slow HEAD pass)
  - dedupe noisy URL variants by endpoint signature (helps `_next/image?...w=...` style lists)
- Better candidate handling:
  - identifies likely redirect parameters (`url`, `redirect`, `next`, etc.)
  - also detects URL-ish parameter values (`http`, `//`, encoded slashes)
- Strict false-positive reduction:
  - confirms only if final redirect target is `https://google.com` or `https://www.google.com`
  - allows strong evidence from `Location`, final URL, or meta-refresh checks

## Features

- `directhit scan <target>` runs:
  - `echo '<target>' | katana | gf redirect >> promising_redirect_urls`
  - then analyzes de-duplicated promising URLs
- `directhit analyze --file promising_redirect_urls` analyzes an existing list
- progress bar + findings table + summary panel
- exports JSON (`findings.json`) and optional CSV
- writes runtime logs to `directhit.log`

## Install

```bash
export PATH=$PATH:$HOME/go/bin
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest
cp $(go env GOPATH)/pkg/mod/github.com/tomnomnom/gf@*/examples/* ~/.gf || true
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf_patterns
mkdir -p ~/.gf
cp ~/.gf_patterns/*.json ~/.gf
pip install -r requirements.txt
```

Or run:

```bash
./install_deps.sh
```

## Usage

```bash
python -m directhit scan https://getmarlee.com/ --concurrency 20 --timeout 8
```

```bash
python -m directhit analyze --file promising_redirect_urls --target https://getmarlee.com/
```

## Your example (`url=` parameter)

For URLs like:

`https://getmarlee.com/_next/image?url=%2Fpayload-api%2F...&w=16&q=75`

DirectHit automatically treats `url` as a high-priority candidate, injects Google payload variants into that parameter, and verifies whether it truly redirects to HTTPS Google host.

## Exit codes

- `0`: completed, no confirmed findings
- `10`: one or more confirmed vulnerabilities
- other non-zero: invalid usage/input errors

## Tests

```bash
pytest -q
```
