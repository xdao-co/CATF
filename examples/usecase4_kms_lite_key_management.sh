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

  KEY_SUBJECT_CID="$("$XDAO_CASCLI_BIN" put --backend ipfs --ipfs-path "$HOME/.ipfs" /tmp/alice-signing.pub)"
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
