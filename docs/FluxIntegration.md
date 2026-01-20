# Flux Integration (Library-Only)

This document describes how to integrate **Flux** (or any workflow/orchestration layer) with the **CATF core library** without introducing non-determinism, network assumptions, or implicit defaults.

Scope:

- Go library integration only (no servers/HTTP)
- Deterministic resolution and CROF generation
- CAS-based hydration for CID-addressed inputs

---

## Integration contract (deterministic)

A Flux step that “runs the resolver” MUST be a pure function of explicit inputs:

- `subjectCID` (string)
- `policy` (bytes or CID)
- `attestations[]` (bytes or CID)
- `compliance` (must be explicitly set)

Output:

- `resolution` (deterministic structured output)
- `crof.bytes` + `crof.cid`

Prohibited in a resolver step:

- Fetching over the network
- Reading wall-clock time
- Falling back to implicit defaults for compliance or storage
- Accepting bytes that do not match their claimed CID

---

## Storage & hydration (CAS is mandatory)

If Flux passes policy/attestation inputs by CID (common for large artifacts), you MUST provide a **CAS** implementation capable of hydrating bytes by CID.

The core library expresses this as `xdao.co/catf/storage.CAS`.

For Flux-style deployments, the recommended approach is to run a CAS as a **sidecar daemon** (downloaded plugin binaries from GitHub Releases) and connect to it over gRPC.

Design notes:

- Transport is not authority: even if bytes were obtained from IPFS or an object store, they MUST be validated against the CID.
- If you use multiple adapters, the adapter order MUST be deterministic (slice order).

### Plugging in your own CAS

Any CAS provider can integrate by implementing `xdao.co/catf/storage.CAS`.
If you need multiple backends (e.g. local filesystem + an optional transport), compose them deterministically with `storage.MultiCAS`.

Sketch (single backend via gRPC):

```go
cas, err := grpccas.Dial("127.0.0.1:7777", grpccas.DialOptions{})
if err != nil { /* handle */ }
defer cas.Close()
```

If you need multiple backends, you can dial multiple daemons and compose them deterministically with `storage.MultiCAS` (slice order).

---

## Recommended call pattern

Use the stable boundary DTOs in `xdao.co/catf/model` for API/Flux integrations.

- They provide JSON-ready request/response types.
- Errors can be surfaced as stable codes (`model.ErrorCode`).

Go example (sketch):

```go
cas, err := grpccas.Dial("127.0.0.1:7777", grpccas.DialOptions{})
if err != nil { /* handle */ }
defer cas.Close()

req := model.ResolverRequest{
  SubjectCID: "bafy...",
  Policy: model.BlobRef{CID: "bafy..."},
  Attestations: []model.BlobRef{
    {CID: "bafy..."},
    {CID: "bafy..."},
  },
  Compliance: model.ComplianceStrict,
}

resp, err := model.ResolveAndRenderCROF(req, model.ResolveOptions{
  CAS: cas,
  CROFOptions: crof.RenderOptions{},
})
if err != nil {
  // err may be a *model.CodedError with a stable Code
}

_ = resp.CROF.CID
_ = resp.CROF.Bytes
```

Notes:

- `Compliance` MUST be explicitly set; missing/empty compliance is rejected.
- Prefer `CAS` (single authoritative store) unless you have a strict reason to use multiple adapters.
- If you do use multiple adapters, always put your authoritative local CAS first, followed by optional transports.

---

## Error handling guidance

Flux should treat these as hard failures:

- `MISSING_CAS` (a CID was provided but no CAS was configured)
- `NOT_FOUND` (required CID missing)
- `CID_MISMATCH` (bytes do not hash to CID; indicates corruption/attack/misrouting)
- `INVALID_REQUEST` / `INVALID_CID`

Flux may decide policy for retries:

- `NOT_FOUND`: retry only if the upstream step is expected to publish the CID later.
- `INTERNAL`: treat as a bug or operational fault; do not silently degrade.
