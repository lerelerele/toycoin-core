#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist/linux-amd64
GOOS=linux GOARCH=amd64 go build -o dist/linux-amd64/toycoind ./cmd/toycoind
GOOS=linux GOARCH=amd64 go build -o dist/linux-amd64/toycoin-cli ./cmd/toycoin-cli
printf 'Built dist/linux-amd64/\n'
