# xdao-catf CLI How-To (Minimum Reference CLI)

This repository includes a small CLI (`xdao-catf`) to exercise the system end-to-end:

- Generate/store Ed25519 keys locally (KMS-lite)
- Produce canonical CATF attestations
- Evaluate attestations under a TPDL trust policy
- Output canonical CROF resolutions

Note: the Go library supports additional algorithms (e.g. `Signature-Alg=dilithium3`, `Hash-Alg=sha3-256`), but the minimal CLI currently emits `ed25519` + `sha256`.

## Where the CLI lives

Build the CLI binary from the repo root:

```sh
make build
./bin/xdao-catf --help
```

For development, you can also run it from the Go module folder (`./src`) using `go run`:

```sh
cd ./src
go run ./cmd/xdao-catf --help
```

## End-to-end demonstration (recommended)

If your goal is to demonstrate the entire lifecycle (subject → attestations → policy → resolve → CROF) **and** store all artifacts in a content-addressable store, use the walkthrough Makefile targets:

```sh
make walkthrough-localfs
```

Optional (requires Kubo `ipfs` on PATH):

```sh
make walkthrough-ipfs
```

You can also run the same “store everything” demo through the **CAS gRPC interface** (a reference way to prove a backend is “CAS-compliant” over the network boundary). This starts a local gRPC server and then runs the same flow through a gRPC client:

```sh
make walkthrough-grpc-localfs
```

Optional (requires Kubo `ipfs` on PATH):

```sh
make walkthrough-grpc-ipfs
```

Details: `docs/Walkthrough_Storage.md`.

## Commands

### `crof`

Helpers for working with CROF bytes.

Compute a CROF CID from a CROF text file:

```sh
./bin/xdao-catf crof cid /path/to/out.crof
```

Validate CROF supersession semantics (new supersedes old):

```sh
./bin/xdao-catf crof validate-supersession --new /path/to/new.crof --old /path/to/old.crof
```

#### CROF supersession workflow

Supersession is how you publish an updated CROF while keeping the prior CROF immutable and auditable.

1) Resolve once and save the “old” CROF:

```sh
./bin/xdao-catf resolve --subject "$SUBJECT_CID" --policy ./policy.tpdl --att /tmp/a1.catf > /tmp/old.crof
```

1) Compute the CID of the old CROF (this requires canonical CROF bytes):

```sh
OLD_CROF_CID="$(./bin/xdao-catf crof cid /tmp/old.crof)"
```

1) Re-resolve (for example: with additional attestations) and declare supersession:

```sh
./bin/xdao-catf resolve \
  --subject "$SUBJECT_CID" \
  --policy ./policy.tpdl \
  --att /tmp/a1.catf \
  --att /tmp/a2.catf \
  --supersedes-crof "$OLD_CROF_CID" \
  > /tmp/new.crof
```

1) Validate the relationship:

```sh
./bin/xdao-catf crof validate-supersession --new /tmp/new.crof --old /tmp/old.crof
```

### `doc-cid`

Computes a stable subject CID for a file (CIDv1 `raw` + sha2-256 multihash):

```sh
SUBJECT_CID="$(./bin/xdao-catf doc-cid ./examples/whitepaper.txt)"
```

For development via `go run`:

```sh
cd ./src
SUBJECT_CID="$(go run ./cmd/xdao-catf doc-cid ../examples/whitepaper.txt)"
```

### `ipfs put` (local publish, no daemon required)

`doc-cid` only computes the CID; it does not store bytes anywhere.

IPFS usage is optional. CATF/CROF workflows work fully offline without IPFS; IPFS is one possible transport/pinning layer.

If you have the Kubo `ipfs` CLI installed, you can store the file bytes into your **local IPFS repo** (even if `ipfs daemon` is not running) as a **raw block** so the returned CID matches `doc-cid`:

```sh
SUBJECT_CID="$(./bin/xdao-catf ipfs put --init ./examples/whitepaper.txt)"
```

Notes:

- This uses `ipfs block put` under the hood (raw block, sha2-256). It is meant for “content-address the exact bytes” workflows.
- If you want “normal IPFS files” (UnixFS DAG with chunking), that’s `ipfs add`, which will usually produce a different CID than `doc-cid`.
- To actually serve the content to other peers, you’ll later run `ipfs daemon` (or have your XDAO Node serve/pin content).

#### How to test IPFS from the CLI

This is a quick smoke test that proves:

1) the CID matches `doc-cid`, and
2) the bytes are actually stored in your local IPFS repo.

From the repo root (after `make build`):

```sh
CID="$(./bin/xdao-catf ipfs put --init ./examples/whitepaper.txt)"
echo "CID=$CID"

./bin/xdao-catf doc-cid ./examples/whitepaper.txt  # should match

ipfs block stat "$CID"
ipfs block get "$CID" > /tmp/xdao-ipfs.out
cmp ./examples/whitepaper.txt /tmp/xdao-ipfs.out
echo "OK: local IPFS repo contains the exact bytes"
```

If you want to publish to the IPFS network (peers can fetch), run your node in daemon mode:

```sh
ipfs daemon
```

Then ensure the content is pinned/served by that node (or by your XDAO Node’s pinning layer).

### `key` (KMS-lite)

Keys are stored under `~/.xdao/keys/<name>/` as seed files (hex) with `0600` permissions.

Create a root key:

```sh
./bin/xdao-catf key init --name alice
```

Create a deterministic root key (useful for reproducible demos):

```sh
./bin/xdao-catf key init --name alice --seed-hex 000102...1e1f
```

Derive a role key:

```sh
./bin/xdao-catf key derive --from alice --role author
```

List keys:

```sh
./bin/xdao-catf key list
```

Export a public key (for TPDL `TRUST` entries):

```sh
./bin/xdao-catf key export --name alice --role author
```

Dev note: all of the above can also be run via `go run` from `./src`.

### `attest`

Generates a canonical CATF attestation and prints it to stdout (no trailing newline).

Sign with a stored key:

```sh
./bin/xdao-catf attest \
  --subject "$SUBJECT_CID" \
  --description "Example" \
  --signer alice \
  --signer-role author \
  --type authorship \
  --role author \
  > /tmp/a1.catf
```

Sign with an explicit seed (demo-only fallback):

```sh
./bin/xdao-catf attest \
  --subject "$SUBJECT_CID" \
  --description "Example" \
  --seed-hex 000102...1e1f \
  --type authorship \
  --role author \
  > /tmp/a1.catf
```

Notes:

- `Type=approval` requires `Effective-Date`; provide `--effective-date` or `--claim Effective-Date=...`.
- `Type=revocation` targets a prior attestation CID via `--target-attestation <AttestationCID>`.
- `Type=supersedes` links to a prior attestation CID via `--supersedes <AttestationCID>`.
- The CLI currently sets `Signature-Alg: ed25519` and `Hash-Alg: sha256`.

### `resolve`

Resolves a subject CID under a policy and prints canonical CROF:

```sh
./bin/xdao-catf resolve --subject "$SUBJECT_CID" --policy ./policy.tpdl --att /tmp/a1.catf
```

Notes:

- Inputs are not required to be valid CATF bytes.
- If an input attestation is non-canonical (e.g. CRLF, BOM, trailing newline) or otherwise fails CATF parsing, it is surfaced deterministically in CROF evidence (`EXCLUSIONS` / `VERDICTS`) with an empty CID, an `Input-Hash: sha256:<hex>`, and a deterministic reason.
- When the CID is empty, CROF omits the `Attestation-CID: ...` line for that entry, but still renders `Input-Hash:` (when available) plus `Reason:` / `Excluded-Reason:`.
- CROF `INPUTS` binds all input identifiers and may include both `Attestation-CID:` and `Input-Hash:` lines.

Compliance mode:

```sh
./bin/xdao-catf resolve --mode strict --subject "$SUBJECT_CID" --policy ./policy.tpdl --att /tmp/a1.catf
```

If you are publishing a revised CROF and want to declare supersession of a prior CROF, pass its CID:

```sh
./bin/xdao-catf resolve \
  --subject "$SUBJECT_CID" \
  --policy ./policy.tpdl \
  --att /tmp/a1.catf \
  --supersedes-crof <PriorCROFCID>
```

### `resolve-name`

Resolves name-bindings under policy:

```sh
./bin/xdao-catf resolve-name --name example.com --version v1 --policy ./policy.tpdl --att /tmp/n1.catf
```

Compliance mode:

```sh
./bin/xdao-catf resolve-name --mode strict --name example.com --version v1 --policy ./policy.tpdl --att /tmp/n1.catf
```

You can also declare CROF supersession for name resolution outputs:

```sh
./bin/xdao-catf resolve-name \
  --name example.com \
  --version v1 \
  --policy ./policy.tpdl \
  --att /tmp/n1.catf \
  --supersedes-crof <PriorCROFCID>
```

## End-to-end examples

Run the provided scripts from the repo root:

```sh
./examples/usecase1_document_publishing.sh
./examples/usecase3_science_quorum.sh
```

To run the examples with subjects stored in a local IPFS repo (no daemon required):

```sh
make examples-ipfs
```

See `UseCases.md` for the higher-level workflows these scripts correspond to.
