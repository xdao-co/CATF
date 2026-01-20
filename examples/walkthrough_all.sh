#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

XDAO_CATF_BIN="$REPO_ROOT/bin/xdao-catf"
XDAO_CASCLI_BIN="$REPO_ROOT/bin/xdao-cascli"
XDAO_CASGRPCD_LOCALFS_BIN="$REPO_ROOT/bin/xdao-casgrpcd-localfs"
XDAO_CASGRPCD_IPFS_BIN="$REPO_ROOT/bin/xdao-casgrpcd-ipfs"

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

if ! command -v ipfs >/dev/null 2>&1; then
  echo "Missing 'ipfs' CLI (Kubo) on PATH" >&2
  echo "Install Kubo, then rerun: make walkthrough-all" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d /tmp/xdao-walk-all.XXXXXX)"
CAS_DIR="$WORK_DIR/cas"
IPFS_REPO="$WORK_DIR/ipfsrepo"
HOME_DIR="$WORK_DIR/home"
mkdir -p "$CAS_DIR" "$IPFS_REPO" "$HOME_DIR"

GRPC_LOG_LOCALFS="$WORK_DIR/casgrpcd-localfs.log"
GRPC_LOG_IPFS="$WORK_DIR/casgrpcd-ipfs.log"
GRPC_PID_LOCALFS=""
GRPC_PID_IPFS=""
GRPC_ADDR_LOCALFS=""
GRPC_ADDR_IPFS=""

cleanup() {
  status=$?

  if [[ -n "$GRPC_PID_LOCALFS" ]]; then
    kill "$GRPC_PID_LOCALFS" >/dev/null 2>&1 || true
    wait "$GRPC_PID_LOCALFS" >/dev/null 2>&1 || true
  fi
  if [[ -n "$GRPC_PID_IPFS" ]]; then
    kill "$GRPC_PID_IPFS" >/dev/null 2>&1 || true
    wait "$GRPC_PID_IPFS" >/dev/null 2>&1 || true
  fi

  if [[ -n "${XDAO_KEEP_WORKDIR:-}" || $status -ne 0 ]]; then
    echo "Keeping work dir: $WORK_DIR" >&2
    if [[ -s "$GRPC_LOG_LOCALFS" ]]; then
      echo "LocalFS gRPC server log: $GRPC_LOG_LOCALFS" >&2
    fi
    if [[ -s "$GRPC_LOG_IPFS" ]]; then
      echo "IPFS gRPC server log: $GRPC_LOG_IPFS" >&2
    fi
    return
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

export HOME="$HOME_DIR"

DOC_PATH="$REPO_ROOT/examples/whitepaper.txt"

echo "Work dir: $WORK_DIR" >&2
echo "LocalFS CAS dir: $CAS_DIR" >&2
echo "IPFS repo dir: $IPFS_REPO" >&2

# Initialize an offline local repo.
if [[ ! -f "$IPFS_REPO/config" ]]; then
  IPFS_PATH="$IPFS_REPO" ipfs init >/dev/null
fi

# Install plugin daemons (downloaded from GitHub Releases) into ./bin.
"$XDAO_CASCLI_BIN" plugin install --plugin localfs --install-dir "$REPO_ROOT/bin" --overwrite >/dev/null
"$XDAO_CASCLI_BIN" plugin install --plugin ipfs --install-dir "$REPO_ROOT/bin" --overwrite >/dev/null
if [[ ! -x "$XDAO_CASGRPCD_LOCALFS_BIN" ]]; then
  echo "Missing $XDAO_CASGRPCD_LOCALFS_BIN after plugin install" >&2
  exit 1
fi
if [[ ! -x "$XDAO_CASGRPCD_IPFS_BIN" ]]; then
  echo "Missing $XDAO_CASGRPCD_IPFS_BIN after plugin install" >&2
  exit 1
fi

# Start both daemons on ephemeral ports.

CAS_CONFIG_LOCALFS="$WORK_DIR/cas.localfs.daemon.json"
cat >"$CAS_CONFIG_LOCALFS" <<EOF
{
  "write_policy": "first",
  "backends": [
    {"name": "localfs", "config": {"localfs-dir": "$CAS_DIR"}}
  ]
}
EOF

CAS_CONFIG_IPFS="$WORK_DIR/cas.ipfs.daemon.json"
cat >"$CAS_CONFIG_IPFS" <<EOF
{
  "write_policy": "first",
  "backends": [
    {"name": "ipfs", "config": {"ipfs-path": "$IPFS_REPO", "pin": "true"}}
  ]
}
EOF

"$XDAO_CASGRPCD_LOCALFS_BIN" \
  --listen 127.0.0.1:0 \
  --backend localfs \
  --cas-config "$CAS_CONFIG_LOCALFS" \
  2>"$GRPC_LOG_LOCALFS" &
GRPC_PID_LOCALFS=$!

"$XDAO_CASGRPCD_IPFS_BIN" \
  --listen 127.0.0.1:0 \
  --backend ipfs \
  --cas-config "$CAS_CONFIG_IPFS" \
  2>"$GRPC_LOG_IPFS" &
GRPC_PID_IPFS=$!

for _ in $(seq 1 100); do
  GRPC_ADDR_LOCALFS="$(sed -n 's/^.* listening on \(.*\) (backend=.*$/\1/p' "$GRPC_LOG_LOCALFS" | head -n 1)"
  if [[ -n "$GRPC_ADDR_LOCALFS" ]]; then
    break
  fi
  sleep 0.05
done

for _ in $(seq 1 100); do
  GRPC_ADDR_IPFS="$(sed -n 's/^.* listening on \(.*\) (backend=.*$/\1/p' "$GRPC_LOG_IPFS" | head -n 1)"
  if [[ -n "$GRPC_ADDR_IPFS" ]]; then
    break
  fi
  sleep 0.05
done

if [[ -z "$GRPC_ADDR_LOCALFS" || -z "$GRPC_ADDR_IPFS" ]]; then
  echo "failed to start one or more gRPC servers" >&2
  cat "$GRPC_LOG_LOCALFS" >&2 || true
  cat "$GRPC_LOG_IPFS" >&2 || true
  exit 1
fi

echo "gRPC target (localfs): $GRPC_ADDR_LOCALFS" >&2
echo "gRPC target (ipfs):   $GRPC_ADDR_IPFS" >&2

CAS_CONFIG="$WORK_DIR/cas.all.json"
cat >"$CAS_CONFIG" <<EOF
{
  "write_policy": "all",
  "backends": [
    {"name": "grpc", "id": "localfs", "config": {"grpc-target": "$GRPC_ADDR_LOCALFS"}},
    {"name": "grpc", "id": "ipfs", "config": {"grpc-target": "$GRPC_ADDR_IPFS"}}
  ]
}
EOF

echo "CAS config: $CAS_CONFIG" >&2

# 1) Store the subject bytes, emitting CID multiples.
SUBJECT_JSON="$($XDAO_CASCLI_BIN put --cas-config "$CAS_CONFIG" --backend grpc --emit-backend-cids "$DOC_PATH")"
SUBJECT_CID="$(printf '%s' "$SUBJECT_JSON" | sed -n 's/^[[:space:]]*"canonical"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' | head -n 1)"
if [[ -z "$SUBJECT_CID" ]]; then
  echo "failed to parse canonical CID from put JSON" >&2
  printf '%s\n' "$SUBJECT_JSON" >&2
  exit 1
fi

echo "Subject CID: $SUBJECT_CID" >&2
echo "Subject CID multiples:" >&2
printf '%s\n' "$SUBJECT_JSON" >&2

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
A1_CID="$($XDAO_CASCLI_BIN put --cas-config "$CAS_CONFIG" --backend grpc "$A1_CATF")"
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
R1_CID="$($XDAO_CASCLI_BIN put --cas-config "$CAS_CONFIG" --backend grpc "$R1_CATF")"
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

POLICY_CID="$($XDAO_CASCLI_BIN put --cas-config "$CAS_CONFIG" --backend grpc "$POLICY_PATH")"
echo "Policy CID: $POLICY_CID" >&2

# 5) Resolve purely from CIDs via CAS, render CROF bytes, store CROF bytes in CAS.
CROF_PATH="$WORK_DIR/out.crof"
CROF_META="$WORK_DIR/out.meta"
if ! "$XDAO_CASCLI_BIN" resolve \
  --cas-config "$CAS_CONFIG" --backend grpc \
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
CROF_JSON="$($XDAO_CASCLI_BIN put --cas-config "$CAS_CONFIG" --backend grpc --emit-backend-cids "$CROF_PATH")"
CROF_CID_STORED="$(printf '%s' "$CROF_JSON" | sed -n 's/^[[:space:]]*"canonical"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' | head -n 1)"

if [[ -z "$CROF_CID_STORED" ]]; then
  echo "failed to parse CROF canonical CID from put JSON" >&2
  printf '%s\n' "$CROF_JSON" >&2
  exit 1
fi

if [[ "$CROF_CID_RENDERED" != "$CROF_CID_STORED" ]]; then
  echo "CROF CID mismatch: rendered $CROF_CID_RENDERED, stored $CROF_CID_STORED" >&2
  exit 1
fi

echo "CROF CID: $CROF_CID_STORED" >&2
echo "CROF CID multiples:" >&2
printf '%s\n' "$CROF_JSON" >&2

echo "OK: subject + policy + attestations + CROF stored in localfs + ipfs (write_policy=all)" >&2
