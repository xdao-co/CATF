#!/usr/bin/env bash
set -euo pipefail

# Guardrail: prevent new code from using deprecated signing helpers in the protocol package.
# Allowed location (compat wrapper / deprecated): src/catf/crypto.go

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Use git grep so this works consistently in CI and locally.
# Restrict to Go source files under src/, and exclude the deprecated wrapper definitions.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  matches="$(git grep -n \
    -e 'catf\.SignEd25519SHA256(' \
    -e 'catf\.SignDilithium3(' \
    -e 'catf\.GenerateDilithium3Keypair(' \
    -- 'src/**/*.go' ':(exclude)src/catf/crypto.go' || true)"
else
  echo "error: must be run inside a git work tree" >&2
  exit 2
fi

if [[ -n "$matches" ]]; then
  echo "Deprecated signing helpers from xdao.co/catf/catf are not allowed outside src/catf/crypto.go:" >&2
  echo "$matches" >&2
  echo "Use xdao.co/catf/keys instead (keys.SignEd25519SHA256 / keys.SignDilithium3 / keys.GenerateDilithium3Keypair)." >&2
  exit 1
fi

echo "OK: no deprecated catf.Sign* usages found."
