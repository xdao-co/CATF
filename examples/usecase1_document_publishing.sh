#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

XDAO_CATF_BIN="$REPO_ROOT/bin/xdao-catf"
if [[ ! -x "$XDAO_CATF_BIN" ]]; then
  echo "Missing $XDAO_CATF_BIN" >&2
  echo "Run: make build" >&2
  exit 1
fi

XDAO_CASCLI_BIN="$REPO_ROOT/bin/xdao-cascli"

IPFS_DAEMON_BIN="$REPO_ROOT/bin/xdao-casgrpcd-ipfs"
IPFS_DAEMON_LOG=""
IPFS_DAEMON_PID=""

cleanup() {
  if [[ -n "$IPFS_DAEMON_PID" ]]; then
    kill "$IPFS_DAEMON_PID" >/dev/null 2>&1 || true
    wait "$IPFS_DAEMON_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

HOME_DIR="$(mktemp -d /tmp/xdao-home.XXXXXX)"
export HOME="$HOME_DIR"

# Generate local keys (random) and derive role keys used for signing.

"$XDAO_CATF_BIN" key init --name alice >/dev/null
"$XDAO_CATF_BIN" key init --name reviewer >/dev/null
"$XDAO_CATF_BIN" key derive --from alice --role author >/dev/null
"$XDAO_CATF_BIN" key derive --from reviewer --role reviewer >/dev/null

author_key="$("$XDAO_CATF_BIN" key export --name alice --role author)"
reviewer_key="$("$XDAO_CATF_BIN" key export --name reviewer --role reviewer)"

if [[ -n "${XDAO_USE_IPFS:-}" ]]; then
  if [[ ! -x "$XDAO_CASCLI_BIN" ]]; then
    echo "Missing $XDAO_CASCLI_BIN" >&2
    echo "Run: make build" >&2
    exit 1
  fi

  if ! command -v ipfs >/dev/null 2>&1; then
    echo "ipfs not found on PATH (install Kubo 'ipfs' CLI)" >&2
    exit 1
  fi
  ipfs init >/dev/null

  "$XDAO_CASCLI_BIN" plugin install --plugin ipfs --install-dir "$REPO_ROOT/bin" --overwrite >/dev/null
  if [[ ! -x "$IPFS_DAEMON_BIN" ]]; then
    echo "Missing $IPFS_DAEMON_BIN after plugin install" >&2
    exit 1
  fi

  IPFS_DAEMON_LOG="$(mktemp -t xdao-ipfs-daemon.XXXXXX.log)"
  IPFS_CAS_CONFIG="$(mktemp -t xdao-ipfs-daemon.XXXXXX.json)"
  cat >"$IPFS_CAS_CONFIG" <<EOF
{
  "write_policy": "first",
  "backends": [
    {"name": "ipfs", "config": {"ipfs-path": "$HOME/.ipfs", "pin": "true"}}
  ]
}
EOF

  "$IPFS_DAEMON_BIN" \
    --listen 127.0.0.1:0 \
    --backend ipfs \
    --cas-config "$IPFS_CAS_CONFIG" \
    2>"$IPFS_DAEMON_LOG" &
  IPFS_DAEMON_PID=$!

  GRPC_ADDR=""
  for _ in $(seq 1 100); do
    GRPC_ADDR="$(sed -n 's/^xdao-casgrpcd listening on \(.*\) (backend=.*$/\1/p' "$IPFS_DAEMON_LOG" | head -n 1)"
    if [[ -n "$GRPC_ADDR" ]]; then
      break
    fi
    sleep 0.05
  done
  if [[ -z "$GRPC_ADDR" ]]; then
    echo "failed to start IPFS gRPC daemon" >&2
    cat "$IPFS_DAEMON_LOG" >&2 || true
    exit 1
  fi

  SUBJECT_CID="$("$XDAO_CASCLI_BIN" put --backend grpc --grpc-target "$GRPC_ADDR" "$REPO_ROOT/examples/whitepaper.txt")"
else
  SUBJECT_CID="$("$XDAO_CATF_BIN" doc-cid "$REPO_ROOT/examples/whitepaper.txt")"
fi
echo "Subject CID: $SUBJECT_CID" >&2

EFFECTIVE_DATE="2026-01-01T00:00:00Z"

# Author authorship attestation
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Example whitepaper" \
  --signer alice \
  --signer-role author \
  --type authorship \
  --role author \
  > /tmp/xdao-a1.catf) 2> /tmp/xdao-a1.meta

a1_cid="$(grep '^Attestation-CID: ' /tmp/xdao-a1.meta | sed 's/^Attestation-CID: //')"
echo "A1 CID: $a1_cid" >&2

# Reviewer approval attestation
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Example whitepaper" \
  --signer reviewer \
  --signer-role reviewer \
  --type approval \
  --role reviewer \
  --effective-date "$EFFECTIVE_DATE" \
  --claim "Comment=Reviewed and approved" \
  > /tmp/xdao-r1.catf) 2> /tmp/xdao-r1.meta

r1_cid="$(grep '^Attestation-CID: ' /tmp/xdao-r1.meta | sed 's/^Attestation-CID: //')"
echo "R1 CID: $r1_cid" >&2

# Trust policy requiring both authorship and reviewer approval.
cat > /tmp/xdao-policy.tpdl <<EOF
-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: $author_key
Role: author

Key: $reviewer_key
Role: reviewer

RULES
Require:
  Type: authorship
  Role: author

Require:
  Type: approval
  Role: reviewer
-----END XDAO TRUST POLICY-----
EOF

# Resolve

"$XDAO_CATF_BIN" resolve \
  --subject "$SUBJECT_CID" \
  --policy /tmp/xdao-policy.tpdl \
  --att /tmp/xdao-a1.catf \
  --att /tmp/xdao-r1.catf
