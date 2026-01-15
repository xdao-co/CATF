#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC_DIR="$ROOT_DIR/src"
GO_BIN="${GO:-go}"

cd "$SRC_DIR"

# Regenerate CATF conformance vectors.
CATF_DIR="testdata/conformance/catf/xdao-catf-1"
mkdir -p "$CATF_DIR"

"$GO_BIN" run ./internal/tools/catf_attestation_gen \
  -seed 0xA0 \
  -subject bafy-catf-1 \
  -desc "CATF conformance" \
  -type authorship \
  -role author \
  -out "$CATF_DIR/authorship_1.catf"

"$GO_BIN" run ./internal/tools/catf_cid "$CATF_DIR/authorship_1.catf" > "$CATF_DIR/authorship_1.cid"

# Non-canonical variants should be rejected by Parse.
perl -pe 's/\n/\r\n/g' < "$CATF_DIR/authorship_1.catf" > "$CATF_DIR/authorship_1.noncanonical_crlf.catf"
perl -pe 's/: /:  /g' < "$CATF_DIR/authorship_1.catf" > "$CATF_DIR/authorship_1.noncanonical_double_space.catf"

# Helper: write a minimal, canonical TPDL policy with a TRUST list and a single Require rule.
write_policy() {
  local out_path="$1"; shift
  local require_role="$1"; shift
  local require_type="$1"; shift
  local -a issuer_keys=("$@")

  {
    printf -- "-----BEGIN XDAO TRUST POLICY-----\n"
    printf "META\n"
    printf "Spec: xdao-tpdl-1\n"
    printf "Version: 1\n\n"

    printf "TRUST\n"
    printf "%s\n" "${issuer_keys[@]}" | LC_ALL=C sort | while IFS= read -r k; do
      printf "Key: %s\n" "$k"
      printf "Role: %s\n\n" "$require_role"
    done

    printf "RULES\n"
    printf "Require:\n"
    printf "  Role: %s\n" "$require_role"
    printf "  Type: %s\n\n" "$require_type"

    printf -- "-----END XDAO TRUST POLICY-----\n"
  } > "$out_path"
}

# Regenerate resolver conformance vectors.
RESOLVER_ROOT="testdata/conformance/resolver"

# 1) Single attestation resolved.
R1_DIR="$RESOLVER_ROOT/xdao-resolver-1"
mkdir -p "$R1_DIR"
find "$R1_DIR" -maxdepth 1 -type f -delete

"$GO_BIN" run ./internal/tools/catf_attestation_gen \
  -seed 0xA1 \
  -subject bafy-resolver-1 \
  -desc "Resolver conformance" \
  -type authorship \
  -role author \
  -out "$R1_DIR/attestation_1.catf"

ISSUER_1="$(grep '^Issuer-Key: ' "$R1_DIR/attestation_1.catf" | head -n 1 | sed 's/^Issuer-Key: //')"
write_policy "$R1_DIR/policy.tpdl" author authorship "$ISSUER_1"
printf "bafy-resolver-1\n" > "$R1_DIR/subject.cid"

"$GO_BIN" run ./internal/tools/resolver_vector_gen \
  -att "$R1_DIR/attestation_1.catf" \
  -policy "$R1_DIR/policy.tpdl" \
  -subject "bafy-resolver-1" \
  -out "$R1_DIR"

# 2) Fork scenario (two competing heads).
RF_DIR="$RESOLVER_ROOT/xdao-resolver-fork-1"
mkdir -p "$RF_DIR"
find "$RF_DIR" -maxdepth 1 -type f -delete

"$GO_BIN" run ./internal/tools/catf_attestation_gen \
  -seed 0xA1 \
  -subject bafy-fork-1 \
  -desc "Fork conformance" \
  -type authorship \
  -role author \
  -out "$RF_DIR/attestation_1.catf"

"$GO_BIN" run ./internal/tools/catf_attestation_gen \
  -seed 0xA2 \
  -subject bafy-fork-1 \
  -desc "Fork conformance" \
  -type authorship \
  -role author \
  -out "$RF_DIR/attestation_2.catf"

ISSUER_F1="$(grep '^Issuer-Key: ' "$RF_DIR/attestation_1.catf" | head -n 1 | sed 's/^Issuer-Key: //')"
ISSUER_F2="$(grep '^Issuer-Key: ' "$RF_DIR/attestation_2.catf" | head -n 1 | sed 's/^Issuer-Key: //')"
write_policy "$RF_DIR/policy.tpdl" author authorship "$ISSUER_F1" "$ISSUER_F2"
printf "bafy-fork-1\n" > "$RF_DIR/subject.cid"

"$GO_BIN" run ./internal/tools/resolver_vector_gen \
  -att "$RF_DIR/attestation_1.catf" \
  -att "$RF_DIR/attestation_2.catf" \
  -policy "$RF_DIR/policy.tpdl" \
  -subject "bafy-fork-1" \
  -out "$RF_DIR"

# 3) Supersedes chain scenario.
RS_DIR="$RESOLVER_ROOT/xdao-resolver-supersedes-1"
mkdir -p "$RS_DIR"
find "$RS_DIR" -maxdepth 1 -type f -delete

SUBJ="bafy-supersedes-1"
"$GO_BIN" run ./internal/tools/catf_attestation_gen \
  -seed 0xB1 \
  -subject "$SUBJ" \
  -desc "Supersedes conformance" \
  -type authorship \
  -role author \
  -out "$RS_DIR/attestation_1.catf"

A1_CID="$($GO_BIN run ./internal/tools/catf_cid "$RS_DIR/attestation_1.catf")"

"$GO_BIN" run ./internal/tools/catf_attestation_gen \
  -seed 0xB1 \
  -subject "$SUBJ" \
  -desc "Supersedes conformance" \
  -type supersedes \
  -role author \
  -claim "Supersedes=$A1_CID" \
  -out "$RS_DIR/attestation_2.catf"

A2_CID="$($GO_BIN run ./internal/tools/catf_cid "$RS_DIR/attestation_2.catf")"

"$GO_BIN" run ./internal/tools/catf_attestation_gen \
  -seed 0xB1 \
  -subject "$SUBJ" \
  -desc "Supersedes conformance" \
  -type supersedes \
  -role author \
  -claim "Supersedes=$A2_CID" \
  -out "$RS_DIR/attestation_3.catf"

ISSUER_S="$(grep '^Issuer-Key: ' "$RS_DIR/attestation_1.catf" | head -n 1 | sed 's/^Issuer-Key: //')"
write_policy "$RS_DIR/policy.tpdl" author authorship "$ISSUER_S"
printf "%s\n" "$SUBJ" > "$RS_DIR/subject.cid"

"$GO_BIN" run ./internal/tools/resolver_vector_gen \
  -att "$RS_DIR/attestation_1.catf" \
  -att "$RS_DIR/attestation_2.catf" \
  -att "$RS_DIR/attestation_3.catf" \
  -policy "$RS_DIR/policy.tpdl" \
  -subject "$SUBJ" \
  -out "$RS_DIR"

echo "Regenerated conformance fixtures under: $SRC_DIR/testdata/conformance"
