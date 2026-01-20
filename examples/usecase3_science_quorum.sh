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

# Generate local keys (random) and derive role keys.
"$XDAO_CATF_BIN" key init --name author >/dev/null
"$XDAO_CATF_BIN" key init --name ai-model-a >/dev/null
"$XDAO_CATF_BIN" key init --name ai-model-b >/dev/null

"$XDAO_CATF_BIN" key derive --from author --role author >/dev/null
"$XDAO_CATF_BIN" key derive --from ai-model-a --role ai-reviewer >/dev/null
"$XDAO_CATF_BIN" key derive --from ai-model-b --role ai-reviewer >/dev/null

author_key="$("$XDAO_CATF_BIN" key export --name author --role author)"
ai_a_key="$("$XDAO_CATF_BIN" key export --name ai-model-a --role ai-reviewer)"
ai_b_key="$("$XDAO_CATF_BIN" key export --name ai-model-b --role ai-reviewer)"

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
    GRPC_ADDR="$(sed -n 's/^.* listening on \(.*\) (backend=.*$/\1/p' "$IPFS_DAEMON_LOG" | head -n 1)"
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

("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Scientific paper" \
  --signer author \
  --signer-role author \
  --type authorship \
  --role author \
  > /tmp/xdao-sci-author.catf) 2> /tmp/xdao-sci-author.meta

("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Scientific paper" \
  --signer ai-model-a \
  --signer-role ai-reviewer \
  --type approval \
  --role ai-reviewer \
  --effective-date "$EFFECTIVE_DATE" \
  --claim "Comment=Methodology sound; reproducible" \
  > /tmp/xdao-sci-ai-a.catf) 2> /tmp/xdao-sci-ai-a.meta

("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Scientific paper" \
  --signer ai-model-b \
  --signer-role ai-reviewer \
  --type approval \
  --role ai-reviewer \
  --effective-date "$EFFECTIVE_DATE" \
  --claim "Comment=Statistical analysis valid" \
  > /tmp/xdao-sci-ai-b.catf) 2> /tmp/xdao-sci-ai-b.meta

cat > /tmp/xdao-sci-policy.tpdl <<EOF
-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: $author_key
Role: author

Key: $ai_a_key
Role: ai-reviewer

Key: $ai_b_key
Role: ai-reviewer

RULES
Require:
  Type: authorship
  Role: author

Require:
  Type: approval
  Role: ai-reviewer
  Quorum: 2
-----END XDAO TRUST POLICY-----
EOF

"$XDAO_CATF_BIN" resolve \
  --subject "$SUBJECT_CID" \
  --policy /tmp/xdao-sci-policy.tpdl \
  --att /tmp/xdao-sci-author.catf \
  --att /tmp/xdao-sci-ai-a.catf \
  --att /tmp/xdao-sci-ai-b.catf
