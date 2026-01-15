# Walkthrough: Demonstrate the Full Process (Store Everything in a CAS)

This walkthrough demonstrates the complete CATF lifecycle:

1) Take a document (subject bytes)
2) Content-address it (subject CID)
3) Create signed attestations (CATF)
4) Define a trust policy (TPDL)
5) Resolve deterministically (CROF)
6) Store **all artifacts** (subject, policy, attestations, CROF) in a **content-addressable store (CAS)**

Two backends are demonstrated:

- **Local filesystem CAS** (fully offline, no external tools)
- **Local IPFS repo CAS** (optional; requires Kubo `ipfs`)

The runnable entrypoints are Makefile targets.

---

## Prerequisites

- Go 1.22+
- Run from the repo root

Optional (for the IPFS walkthrough):

- Kubo `ipfs` CLI installed and on `PATH`

---

## Quick start (recommended)

Build and run the local filesystem walkthrough:

```sh
make walkthrough-localfs
```

Run the IPFS walkthrough (optional):

```sh
make walkthrough-ipfs
```

Run both:

```sh
make walkthrough
```

---

## What “store everything” means

For this demo, **everything needed to reproduce the resolution** is stored as immutable blocks in a CAS:

- **Subject bytes** (the document itself)
- **Trust policy bytes** (TPDL)
- **Attestation bytes** (CATF)
- **Resolver output bytes** (CROF)

The resolver step is performed by referencing **only CIDs**, and hydration is done via the chosen CAS backend.

---

## What you should see

Both walkthroughs print a sequence of CIDs:

- `Subject CID: ...`
- `A1 CID: ...` (authorship attestation)
- `R1 CID: ...` (approval attestation)
- `Policy CID: ...`
- `CROF CID: ...`

If everything worked, the script ends with:

- `OK: subject + policy + attestations + CROF stored in ...`

---

## Implementation notes (so the demo stays deterministic)

- The subject CID is `CIDv1 raw + sha2-256` over the exact file bytes.
- The IPFS walkthrough writes **raw blocks** (`ipfs block put`), not UnixFS (`ipfs add`).
- The policy in the walkthrough includes explicit `Quorum: 1` in each `Require:` block so it is valid under strict parsing rules.

---

## Where the scripts live

- LocalFS walkthrough script: `examples/walkthrough_localfs.sh`
- IPFS walkthrough script: `examples/walkthrough_ipfs.sh`

They use:

- `./bin/xdao-catf` to generate keys and attestations
- `./bin/xdao-cascli` to put/get/resolve against a selected CAS backend

---

## Troubleshooting

### IPFS: “ipfs not found on PATH”

Install Kubo and ensure `ipfs` is on your `PATH`:

```sh
ipfs --version
```

### Inspecting the temp directory after failures

Both walkthrough scripts keep the temporary work directory on failure.

To force keeping it even on success:

```sh
XDAO_KEEP_WORKDIR=1 make walkthrough-localfs
```

This is helpful for inspecting the generated CATF/TPDL/CROF files.
