# CATF Examples

These scripts exercise the repo end-to-end (CATF → TPDL → Resolver → CROF) using the minimal CLI.

## Full process walkthrough

If you want a single, reproducible demo of the entire lifecycle (subject → attestations → policy → resolve → CROF) **and** you want all artifacts stored in a CAS, start here:

- [docs/Walkthrough_Storage.md](docs/Walkthrough_Storage.md)

## Walkthrough: store everything in a CAS

These walkthroughs explicitly store **all artifacts** (subject bytes, trust policy, attestations, and CROF output) into a content-addressable store, then resolve using only CIDs.

Under the hood they use `./bin/xdao-catf` (to generate attestations) plus a small helper binary `./bin/xdao-cascli` (to put/get/resolve via a chosen CAS backend).

- Local filesystem CAS:

```sh
make walkthrough-localfs
```

- Local IPFS repo (optional; requires Kubo `ipfs` on PATH):

```sh
make walkthrough-ipfs
```

### Optional: CAS gRPC transport demos

These variants run the same “store everything in a CAS” lifecycle, but route all CAS operations through the CAS gRPC protocol.

This is a reference way to demonstrate “CAS compliant storage” over a network boundary:

- A backend CAS implementation is exposed via `./bin/xdao-casgrpcd` (or via the downloadable plugin daemons `xdao-casgrpcd-localfs` / `xdao-casgrpcd-ipfs`)
- The client side uses `./bin/xdao-cascli --backend grpc --grpc-target ...`

LocalFS backend via gRPC:

```sh
make walkthrough-grpc-localfs
```

IPFS backend via gRPC (optional; requires Kubo `ipfs` on PATH):

```sh
make walkthrough-grpc-ipfs
```

To run both:

```sh
make walkthrough
```

## Prereqs

- Go 1.22+
- Run from the repo root
- Build the CLI binary: `make build`

## Use Case 1: Document publishing (authorship + optional approval)

```sh
./examples/usecase1_document_publishing.sh
```

## Use Case 3: Scientific paper with quorum AI peer review

```sh
./examples/usecase3_science_quorum.sh
```

## Use Case 2: Real estate good faith money

```sh
./examples/usecase2_real_estate_good_faith_money.sh
```

## Use Case 4: KMS-lite key management

```sh
./examples/usecase4_kms_lite_key_management.sh
```

Notes:

- The scripts use the local built binary at `./bin/xdao-catf`.
- The scripts use KMS-lite (`xdao-catf key ...`) and run with a temporary `HOME`.

### Optional: store subjects in local IPFS

By default, the scripts use `xdao-catf doc-cid` (CID computation only).

IPFS is optional: the scripts work fully offline without IPFS.

If you want the scripts to also store the subject bytes into a local IPFS repo (no daemon required), set:

```sh
XDAO_USE_IPFS=1 ./examples/usecase1_document_publishing.sh
```

This switches subject CID creation to:

- `ipfs init` (under the script’s temporary `HOME`), then
- `xdao-cascli put --backend ipfs --ipfs-path "$HOME/.ipfs" ...`
