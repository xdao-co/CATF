#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

XDAO_CATF_BIN="$REPO_ROOT/bin/xdao-catf"
if [[ ! -x "$XDAO_CATF_BIN" ]]; then
  echo "Missing $XDAO_CATF_BIN" >&2
  echo "Run: make build" >&2
  exit 1
fi

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
  SUBJECT_CID="$("$XDAO_CATF_BIN" ipfs put --init "$REPO_ROOT/examples/whitepaper.txt")"
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
