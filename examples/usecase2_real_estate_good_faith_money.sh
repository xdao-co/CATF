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

# Subject CID (purchase agreement)
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

  SUBJECT_CID="$("$XDAO_CASCLI_BIN" put --backend grpc --grpc-target "$GRPC_ADDR" "$REPO_ROOT/examples/purchase-agreement.txt")"
else
  SUBJECT_CID="$("$XDAO_CATF_BIN" doc-cid "$REPO_ROOT/examples/purchase-agreement.txt")"
fi
echo "Subject CID: $SUBJECT_CID" >&2

EFFECTIVE_DATE="2026-01-01T00:00:00Z"

# Create local keys (random) and role keys matching the policy roles.
"$XDAO_CATF_BIN" key init --name buyer >/dev/null
"$XDAO_CATF_BIN" key init --name seller >/dev/null
"$XDAO_CATF_BIN" key init --name escrow >/dev/null

"$XDAO_CATF_BIN" key derive --from buyer --role buyer >/dev/null
"$XDAO_CATF_BIN" key derive --from seller --role seller >/dev/null
"$XDAO_CATF_BIN" key derive --from escrow --role escrow-agent >/dev/null

BUYER_KEY="$("$XDAO_CATF_BIN" key export --name buyer --role buyer)"
SELLER_KEY="$("$XDAO_CATF_BIN" key export --name seller --role seller)"
ESCROW_KEY="$("$XDAO_CATF_BIN" key export --name escrow --role escrow-agent)"

# Buyer deposits good faith money (approval)
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Purchase agreement" \
  --signer buyer \
  --signer-role buyer \
  --type approval \
  --role buyer \
  --effective-date "$EFFECTIVE_DATE" \
  --claim 'Good-Faith-Money=$10,000 deposited' \
  > /tmp/xdao-rea-buyer.catf) 2> /tmp/xdao-rea-buyer.meta

B1_CID="$(grep '^Attestation-CID: ' /tmp/xdao-rea-buyer.meta | sed 's/^Attestation-CID: //')"
echo "Buyer approval CID: $B1_CID" >&2

# Seller acknowledges receipt (approval)
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Purchase agreement" \
  --signer seller \
  --signer-role seller \
  --type approval \
  --role seller \
  --effective-date "$EFFECTIVE_DATE" \
  > /tmp/xdao-rea-seller.catf) 2> /tmp/xdao-rea-seller.meta

S1_CID="$(grep '^Attestation-CID: ' /tmp/xdao-rea-seller.meta | sed 's/^Attestation-CID: //')"
echo "Seller approval CID: $S1_CID" >&2

# Escrow agent attests holding funds (approval)
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Purchase agreement" \
  --signer escrow \
  --signer-role escrow-agent \
  --type approval \
  --role escrow-agent \
  --effective-date "$EFFECTIVE_DATE" \
  --claim "Funds=Held in escrow account #XYZ" \
  > /tmp/xdao-rea-escrow.catf) 2> /tmp/xdao-rea-escrow.meta

E1_CID="$(grep '^Attestation-CID: ' /tmp/xdao-rea-escrow.meta | sed 's/^Attestation-CID: //')"
echo "Escrow approval CID: $E1_CID" >&2

# Trust policy requires all three approvals.
cat > /tmp/xdao-rea-policy.tpdl <<EOF
-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: $BUYER_KEY
Role: buyer

Key: $SELLER_KEY
Role: seller

Key: $ESCROW_KEY
Role: escrow-agent

RULES
Require:
  Type: approval
  Role: buyer

Require:
  Type: approval
  Role: seller

Require:
  Type: approval
  Role: escrow-agent
-----END XDAO TRUST POLICY-----
EOF

echo "--- Resolve (expected: Resolved)" >&2
"$XDAO_CATF_BIN" resolve \
  --subject "$SUBJECT_CID" \
  --policy /tmp/xdao-rea-policy.tpdl \
  --att /tmp/xdao-rea-buyer.catf \
  --att /tmp/xdao-rea-seller.catf \
  --att /tmp/xdao-rea-escrow.catf

# Failure case: buyer withdraws (revocation targets buyer approval attestation CID)
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Purchase agreement" \
  --signer buyer \
  --signer-role buyer \
  --target-attestation "$B1_CID" \
  > /tmp/xdao-rea-revoke.catf) 2> /tmp/xdao-rea-revoke.meta

R1_CID="$(grep '^Attestation-CID: ' /tmp/xdao-rea-revoke.meta | sed 's/^Attestation-CID: //')"
echo "Buyer revocation CID: $R1_CID" >&2

echo "--- Resolve after revocation (expected: Revoked)" >&2
"$XDAO_CATF_BIN" resolve \
  --subject "$SUBJECT_CID" \
  --policy /tmp/xdao-rea-policy.tpdl \
  --att /tmp/xdao-rea-buyer.catf \
  --att /tmp/xdao-rea-seller.catf \
  --att /tmp/xdao-rea-escrow.catf \
  --att /tmp/xdao-rea-revoke.catf
