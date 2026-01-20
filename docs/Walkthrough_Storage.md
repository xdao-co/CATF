# Walkthrough: Demonstrate the Full Process (Store Everything in a CAS)

This walkthrough demonstrates the complete CATF lifecycle:

1) Take a document (subject bytes)
2) Content-address it (subject CID)
3) Create signed attestations (CATF)
4) Define a trust policy (TPDL)
5) Resolve deterministically (CROF)
6) Store **all artifacts** (subject, policy, attestations, CROF) in a **content-addressable store (CAS)**

All walkthroughs route CAS operations through the **CAS gRPC interface** using **downloaded plugin daemons**.

This avoids in-process/local CAS implementations during demos.

The runnable entrypoints are Makefile targets.

---

## Prerequisites

- Go 1.22+
- Run from the repo root

Required (for plugin installation):

- Network access to GitHub Releases (or set `GITHUB_TOKEN` / use `--github-token`)

Optional (for the IPFS walkthrough):

- Kubo `ipfs` CLI installed and on `PATH`

---

## Quick start (recommended)

Build and run the LocalFS plugin-daemon walkthrough:

```sh
make walkthrough-localfs
```

Run the combined LocalFS+IPFS walkthrough using a single config (replicate writes to both plugin daemons; optional; requires Kubo `ipfs`):

```sh
make walkthrough-all
```

Run the IPFS walkthrough (optional):

```sh
make walkthrough-ipfs
```

Aliases (same behavior; retained for compatibility):

```sh
make walkthrough-grpc-localfs
```

Run both:

```sh
make walkthrough
```

Run both gRPC variants:

```sh
make walkthrough-grpc
```

---

## Runtime backend injection via config (plugins)

CATF uses a lightweight CAS plugin registry (`storage/casregistry`).
Backends are linked into the binaries (blank imports), then selected/composed at runtime.

Both `xdao-cascli` and the plugin daemons accept `--cas-config` to open backends from a JSON file.

In this repo’s walkthroughs, the **daemon** uses a backend config (localfs or ipfs), and the **client** (`xdao-cascli`) uses `--backend grpc` to talk to that daemon.

### Config: localfs daemon (plugin)

```json
{
  "write_policy": "first",
  "backends": [
    {"name": "localfs", "config": {"localfs-dir": "/tmp/xdao-cas"}}
  ]
}
```

### Config: ipfs daemon (plugin)

```json
{
  "write_policy": "first",
  "backends": [
    {"name": "ipfs", "config": {"ipfs-path": "/tmp/xdao-ipfs", "pin": "true"}}
  ]
}
```

### Config: all backends (replicate writes)

Example config (replicate writes to *both* gRPC backends).

This requires unique backend IDs so the per-backend CID map is stable:

```json
{
  "write_policy": "all",
  "backends": [
    {"name": "grpc", "id": "localfs", "config": {"grpc-target": "127.0.0.1:7777"}},
    {"name": "grpc", "id": "ipfs", "config": {"grpc-target": "127.0.0.1:7778"}}
  ]
}
```

Write a file and print "CID multiples" (per-backend CID map) as JSON:

```sh
./bin/xdao-cascli put --cas-config ./cas.json --backend grpc --emit-backend-cids ./examples/whitepaper.txt
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
- LocalFS+IPFS (replicating) walkthrough script: `examples/walkthrough_all.sh`
- LocalFS-via-gRPC walkthrough script: `examples/walkthrough_grpccas_localfs.sh`
- IPFS-via-gRPC walkthrough script: `examples/walkthrough_grpccas_ipfs.sh`

They use:

- `./bin/xdao-catf` to generate keys and attestations
- `./bin/xdao-cascli` to put/get/resolve against a selected CAS backend

The gRPC variants additionally use:

- Downloadable plugin daemons (`xdao-casgrpcd-localfs`, `xdao-casgrpcd-ipfs`) installed via `./bin/xdao-cascli plugin install ...`
- `xdao-cascli --backend grpc --grpc-target <host:port>` to exercise the exact same flow through the network boundary

Internally, `xdao-cascli` performs the “resolve from CIDs” step via the public Go API:

- `model.ResolveAndRenderCROF(...)` (JSON-ish DTO)
- `model.ResolveResult(...)` (compact Go type: `model.ResolutionResult`)

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
