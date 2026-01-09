# CATF Examples

These scripts exercise the repo end-to-end (CATF → TPDL → Resolver → CROF) using the minimal CLI.

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

If you want the scripts to also store the subject bytes into a local IPFS repo (no daemon required), set:

```sh
XDAO_USE_IPFS=1 ./examples/usecase1_document_publishing.sh
```

This switches subject CID creation to `xdao-catf ipfs put --init ...`.
