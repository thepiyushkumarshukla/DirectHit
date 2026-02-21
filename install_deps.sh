#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:$HOME/go/bin"

if ! command -v go >/dev/null 2>&1; then
  echo "[!] Go is required. Install Go first: https://go.dev/doc/install"
  exit 1
fi

CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

go install github.com/tomnomnom/gf@latest
mkdir -p ~/.gf
cp "$(go env GOPATH)"/pkg/mod/github.com/tomnomnom/gf@*/examples/* ~/.gf || true

git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf_patterns || true
mkdir -p ~/.gf
cp ~/.gf_patterns/*.json ~/.gf

pip install -r requirements.txt

echo "[+] Dependency installation complete."
