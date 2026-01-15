#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

XDAO_CATF_BIN="$REPO_ROOT/bin/xdao-catf"
XDAO_CASCLI_BIN="$REPO_ROOT/bin/xdao-cascli"

if [[ ! -x "$XDAO_CATF_BIN" ]]; then
  echo "Missing $XDAO_CATF_BIN" >&2
  echo "Run: make build" >&2
  exit 1
fi

if [[ ! -x "$XDAO_CASCLI_BIN" ]]; then
  echo "Missing $XDAO_CASCLI_BIN" >&2
  echo "Run: make build-cascli" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/xdao-walk-localfs.XXXXXX)"
CAS_DIR="$WORK_DIR/cas"
HOME_DIR="$WORK_DIR/home"
mkdir -p "$CAS_DIR" "$HOME_DIR"

cleanup() {
  status=$?
  if [[ -n "${XDAO_KEEP_WORKDIR:-}" || $status -ne 0 ]]; then
    echo "Keeping work dir: $WORK_DIR" >&2
    return
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

export HOME="$HOME_DIR"

DOC_PATH="$REPO_ROOT/examples/whitepaper.txt"

echo "Work dir: $WORK_DIR" >&2
echo "LocalFS CAS dir: $CAS_DIR" >&2

# 1) Store the subject bytes in localfs CAS.
SUBJECT_CID="$($XDAO_CASCLI_BIN put --backend localfs --localfs-dir "$CAS_DIR" "$DOC_PATH")"
echo "Subject CID: $SUBJECT_CID" >&2

# 2) Generate local keys (random) and derive role keys used for signing.
"$XDAO_CATF_BIN" key init --name alice >/dev/null
"$XDAO_CATF_BIN" key init --name reviewer >/dev/null
"$XDAO_CATF_BIN" key derive --from alice --role author >/dev/null
"$XDAO_CATF_BIN" key derive --from reviewer --role reviewer >/dev/null

author_key="$("$XDAO_CATF_BIN" key export --name alice --role author)"
reviewer_key="$("$XDAO_CATF_BIN" key export --name reviewer --role reviewer)"

EFFECTIVE_DATE="2026-01-01T00:00:00Z"

# 3) Produce attestations as CATF bytes (files), then store those bytes in CAS.
A1_CATF="$WORK_DIR/a1.catf"
A1_META="$WORK_DIR/a1.meta"
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Example whitepaper" \
  --signer alice \
  --signer-role author \
  --type authorship \
  --role author \
  > "$A1_CATF") 2> "$A1_META"
A1_CID_EXPECTED="$(grep '^Attestation-CID: ' "$A1_META" | sed 's/^Attestation-CID: //')"
A1_CID="$($XDAO_CASCLI_BIN put --backend localfs --localfs-dir "$CAS_DIR" "$A1_CATF")"
if [[ "$A1_CID" != "$A1_CID_EXPECTED" ]]; then
  echo "Attestation CID mismatch (A1): expected $A1_CID_EXPECTED, got $A1_CID" >&2
  exit 1
fi

echo "A1 CID: $A1_CID" >&2

R1_CATF="$WORK_DIR/r1.catf"
R1_META="$WORK_DIR/r1.meta"
("$XDAO_CATF_BIN" attest \
  --subject "$SUBJECT_CID" \
  --description "Example whitepaper" \
  --signer reviewer \
  --signer-role reviewer \
  --type approval \
  --role reviewer \
  --effective-date "$EFFECTIVE_DATE" \
  --claim "Comment=Reviewed and approved" \
  > "$R1_CATF") 2> "$R1_META"
R1_CID_EXPECTED="$(grep '^Attestation-CID: ' "$R1_META" | sed 's/^Attestation-CID: //')"
R1_CID="$($XDAO_CASCLI_BIN put --backend localfs --localfs-dir "$CAS_DIR" "$R1_CATF")"
if [[ "$R1_CID" != "$R1_CID_EXPECTED" ]]; then
  echo "Attestation CID mismatch (R1): expected $R1_CID_EXPECTED, got $R1_CID" >&2
  exit 1
fi

echo "R1 CID: $R1_CID" >&2

# 4) Write trust policy, store it in CAS.
POLICY_PATH="$WORK_DIR/policy.tpdl"
cat > "$POLICY_PATH" <<EOF
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
  Quorum: 1

Require:
  Type: approval
  Role: reviewer
  Quorum: 1
-----END XDAO TRUST POLICY-----
EOF

POLICY_CID="$($XDAO_CASCLI_BIN put --backend localfs --localfs-dir "$CAS_DIR" "$POLICY_PATH")"
echo "Policy CID: $POLICY_CID" >&2

# 5) Resolve purely from CIDs via CAS, render CROF bytes, store CROF bytes in CAS.
CROF_PATH="$WORK_DIR/out.crof"
CROF_META="$WORK_DIR/out.meta"
if ! "$XDAO_CASCLI_BIN" resolve \
  --backend localfs --localfs-dir "$CAS_DIR" \
  --subject "$SUBJECT_CID" \
  --policy "$POLICY_CID" \
  --att "$A1_CID" \
  --att "$R1_CID" \
  > "$CROF_PATH" 2> "$CROF_META"; then
  echo "Resolve failed:" >&2
  cat "$CROF_META" >&2 || true
  exit 1
fi

CROF_CID_RENDERED="$(grep '^CROF-CID: ' "$CROF_META" | sed 's/^CROF-CID: //')"
CROF_CID_STORED="$($XDAO_CASCLI_BIN put --backend localfs --localfs-dir "$CAS_DIR" "$CROF_PATH")"

if [[ "$CROF_CID_RENDERED" != "$CROF_CID_STORED" ]]; then
  echo "CROF CID mismatch: rendered $CROF_CID_RENDERED, stored $CROF_CID_STORED" >&2
  exit 1
fi

echo "CROF CID: $CROF_CID_STORED" >&2

echo "OK: subject + policy + attestations + CROF stored in localfs CAS" >&2
