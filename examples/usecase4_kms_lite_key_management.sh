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

# Create root identity key and derive a signing role key.
"$XDAO_CATF_BIN" key init --name alice >/dev/null
"$XDAO_CATF_BIN" key derive --from alice --role signing >/dev/null

ALICE_ROOT_KEY="$("$XDAO_CATF_BIN" key export --name alice)"
ALICE_SIGNING_KEY="$("$XDAO_CATF_BIN" key export --name alice --role signing)"

echo "Alice root key: $ALICE_ROOT_KEY" >&2
echo "Alice signing key: $ALICE_SIGNING_KEY" >&2

# Export the signing public key to a file and treat it as a subject.
"$XDAO_CATF_BIN" key export --name alice --role signing > /tmp/alice-signing.pub
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

  KEY_SUBJECT_CID="$("$XDAO_CASCLI_BIN" put --backend grpc --grpc-target "$GRPC_ADDR" /tmp/alice-signing.pub)"
else
  KEY_SUBJECT_CID="$("$XDAO_CATF_BIN" doc-cid /tmp/alice-signing.pub)"
fi
echo "Key subject CID: $KEY_SUBJECT_CID" >&2

EFFECTIVE_DATE="2026-01-01T00:00:00Z"

# Attest provenance (root key) and authorization (signing key).
("$XDAO_CATF_BIN" attest \
  --subject "$KEY_SUBJECT_CID" \
  --description "Alice signing key (public)" \
  --signer alice \
  --type authorship \
  --role identity \
  --claim "Comment=Public signing key for Alice" \
  > /tmp/xdao-key-provenance.catf) 2> /tmp/xdao-key-provenance.meta

("$XDAO_CATF_BIN" attest \
  --subject "$KEY_SUBJECT_CID" \
  --description "Alice signing key (public)" \
  --signer alice \
  --signer-role signing \
  --type approval \
  --role signing \
  --effective-date "$EFFECTIVE_DATE" \
  --claim "Comment=Authorized for document signing" \
  > /tmp/xdao-key-authorization.catf) 2> /tmp/xdao-key-authorization.meta

# Trust policy requiring both attestations.
cat > /tmp/xdao-key-policy.tpdl <<EOF
-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1
Description: Trust policy for Alice signing keys

TRUST
Key: $ALICE_ROOT_KEY
Role: identity

Key: $ALICE_SIGNING_KEY
Role: signing

RULES
Require:
  Type: authorship
  Role: identity

Require:
  Type: approval
  Role: signing
-----END XDAO TRUST POLICY-----
EOF

echo "--- Resolve (expected: Resolved)" >&2
"$XDAO_CATF_BIN" resolve \
  --subject "$KEY_SUBJECT_CID" \
  --policy /tmp/xdao-key-policy.tpdl \
  --att /tmp/xdao-key-provenance.catf \
  --att /tmp/xdao-key-authorization.catf
