# xDAO CATF — Concrete Code Audit (main/HEAD)

**Audit date:** 2026-01-15
**Source:** Repository snapshot provided as `CATF.zip` (current main/HEAD)
**Goal:** Identify what is **missing** / **should be improved** to make this a **complete, civilization‑grade core library** that is ready to be wrapped by an API and integrated into automation/orchestration systems (e.g., Flux).

> This audit is **code‑anchored**: each item references concrete packages/files in the repo.

---

## 0. What’s already strong (Implemented & Verified in Code)

### Canonicalization & determinism are actively enforced

Evidence in repo:

- `src/catf/canonicalize.go` + `src/catf/canonicalization_enforcement_test.go`
- `src/crof/canonicalize.go` + `src/crof/canonicalization_enforcement_test.go`
- `src/resolver/determinism_test.go`
- Conformance fixtures under `src/testdata/conformance/...`

### Trust policy & verdict evidence are materialized (not just implied)

Evidence in repo:

- `src/tpdl/tpdl.go`
- `src/resolver/verdict_evidence.go` (includes `PolicyVerdict` and reasons; enforces strict mode in name resolution)

### CROF exists as a real, testable artifact

Evidence in repo:

- `src/crof/document.go`, `src/crof/crof.go`, `src/crof/verify.go`
- `src/crof/cid.go` (+ tests), supersession support:
  - `src/crof/supersession.go`
  - adversarial tests: `src/crof/supersession_adversarial_test.go`

### Stability policy is documented (API tiering)

Evidence in repo:

- `docs/STABILITY.md`
- `docs/CONFORMANCE.md`
- `docs/spec/*`

---

## 1. GAPS (Missing to be “complete library”)

### GAP-01 — Storage is not a first‑class subsystem (CAS interface + adapters)

**Problem:** The repo uses CIDs and talks about IPFS compatibility, but without a CAS subsystem the integration story becomes ad-hoc.
**Impact:** Any API layer or Flux/controller integration has to invent storage semantics (risking non‑portable behavior).

**Status update (2026-01-15):** Implemented in core library.

**Evidence:** Storage is now a first-class subsystem:

- `src/storage/cas.go` (core CAS interface)
- `src/storage/errors.go` (stable storage errors)
- `src/storage/multi.go` (deterministic adapter composition)
- `src/storage/localfs/localfs.go` (offline, write-once filesystem CAS)
- `src/storage/ipfs/ipfs.go` (optional IPFS adapter; shells out to local `ipfs` CLI)
- `src/storage/testkit/cas.go` (conformance harness)

**Required fixes:**

- Add a **core CAS interface** (library‑only, no network assumptions):
  - `Put(bytes) -> cid`
  - `Get(cid) -> bytes | NotFound`
  - `Has(cid) -> bool` (recommended)
- Add **mandatory Local CAS** reference impl:
  - filesystem object store keyed by CID
- Add **optional adapters** (as separate packages; still library-only):
  - IPFS adapter (best‑effort transport; never authoritative)
  - HTTP mirror adapter (best‑effort; verify bytes against CID)
  - “bundle”/archive adapter (offline civilization-grade distribution)

**Status:**

- Core CAS interface: Implemented
- Local filesystem CAS: Implemented
- Optional adapters:
  - IPFS: Implemented (`src/storage/ipfs`)
  - HTTP mirror: Not implemented (optional)
  - Bundle/archive: Not implemented (optional)

**Concrete deliverables (suggested paths):**

- `src/storage/cas.go`
- `src/storage/localfs/localfs.go`
- `src/storage/ipfs/ipfs.go` (optional)
- `src/storage/httpmirror/httpmirror.go` (optional)
- `src/storage/bundle/bundle.go` (optional)

**Tests to add:**

- Deterministic CAS conformance tests: `Put/Get` roundtrip and hash mismatch detection
- LocalFS immutability test (write-once semantics)
- Optional: IPFS adapter conformance test (skipped by default; runnable when `ipfs` is available)

---

### GAP-02 — Resolver does not yet accept a pluggable storage source for byte hydration

**Problem:** Resolver tests and conformance vectors exist, but there is not yet a clear, stable way to supply a storage backend to:

- fetch attestation bytes by CID
- fetch subject/document bytes by CID (when needed)
- support multi-source retrieval order

**Status update (2026-01-15):** Implemented.

**Evidence:**

- `src/resolver/hydrate.go` implements CID hydration via injected `storage.CAS` and/or an explicitly ordered adapter list.
- Determinism is pinned with tests under `src/resolver/hydrate_test.go`.

**Required fixes:**

- Define resolver inputs so that resolution can be run:
  1) fully in-memory (current tests), **or**
  2) by CID with CAS hydration (needed for API/Flux integrations)
- Add a `ResolverInput` model supporting:
  - `AttestationBytes []byte` or `AttestationCID string`
  - `PolicyBytes []byte` or `PolicyCID string`
- Provide a deterministic hydration strategy:
  - local CAS first; then optional adapters in fixed order

**Concrete deliverables (suggested paths):**

- `src/resolver/input.go` (or integrate into existing `resolver.go`)
- `src/resolver/hydrate.go` (uses `storage.CAS`)

**Tests to add:**

- Hydration determinism: shuffled adapter list must still produce deterministic selection (explicit ordering)

---

### GAP-03 — “Ready for API” boundary types are not fully explicit

**Problem:** There is good work on determinism and stability docs, but API-ready libraries benefit from explicit boundary types so an API layer never needs to interpret internal structs.

**Status update (2026-01-15):** Implemented.

**Evidence:**

- Stable boundary DTOs exist in `src/model/*` and are intended for direct JSON serialization.
- Snapshot tests pin JSON field names/shapes: `src/model/snapshot_test.go`.

**Required fixes:**

- Define canonical, stable boundary DTOs for:
  - resolver request
  - resolver response (including verdict evidence and CROF bytes/CID)
  - errors (stable error codes in addition to human strings)

**Concrete deliverables (suggested paths):**

- Implemented as `src/model/`:
  - `src/model/types.go`
  - `src/model/errors.go`
  - `src/model/resolve.go`

**Tests to add:**

- Round-trip JSON/YAML projections MUST NOT affect canonical bytes (projection is non-authoritative)
- Stable field names (snapshot tests)

---

## 2. ENHANCEMENTS (Recommended Improvements)

### ENH-01 — Make “storage reachability is advisory” explicit in docs and code

**Problem:** `docs/Integration.md` references IPFS workflows, which can accidentally imply IPFS is required.
**Fix:** Update docs to make the stance explicit:

- CATF guarantees identity & integrity, not availability
- CAS local is mandatory; IPFS is optional transport

**Files to update:**

- `docs/Integration.md`
- `docs/ReferenceDesign.md` (storage section)

**Status update (2026-01-15):** Done.

---

### ENH-02 — Provide a tiny “Flux/controller integration pattern” doc (library-only)

**Problem:** Flux integration will likely be a controller/operator calling the resolver deterministically. A short pattern doc prevents misuse.

**Deliverable:**

- `docs/FluxIntegration.md` (or extend `docs/Integration.md`) covering:
  - deterministic resolver invocation
  - strict mode usage
  - CAS hydration approach
  - “do not use wall-clock time” guidance

**Status update (2026-01-15):** Done (`docs/FluxIntegration.md`).

---

### ENH-03 — Conformance harness for adapters

Add a reusable harness so any adapter must pass the same behavior:

- `storage/testkit` with table-driven tests for CAS semantics.

**Status update (2026-01-15):** Done (`src/storage/testkit`).

---

### ENH-04 — Bundle/export format for offline civilization-grade transport

Create an archive format that can carry:

- objects by CID
- a small index (optional)
- optional CROF snapshots

This becomes your “Library of Alexandria” mechanism.

Deliverable (suggested):

- `src/storage/bundle/format.md` (spec)
- `src/storage/bundle/*` implementation (export/import + determinism tests)

---

## 3. Proposed Storage Decision (Recommendation)

To keep the CATF/CID contract intact **and** eliminate reliance on a non-self-contained network, implement this **required baseline**:

### Required baseline (MUST)

1. **Local filesystem CAS** (write-once, immutable, CID-keyed)
2. Resolver can hydrate from local CAS

### Optional transports (MAY)

1. IPFS adapter (best-effort publish/fetch; verify bytes) — implemented (`src/storage/ipfs`)
2. HTTP mirror adapter (best-effort; verify bytes)
3. Offline bundle adapter

> This keeps the protocol honest: **truth is verifiable without being retrievable**.

---

## 4. “Done” definition for API/Flux readiness

You are “library complete” for the next step when:

- [x] `storage.CAS` exists and passes conformance tests
- [x] `storage.localfs` exists and is mandatory baseline
- [x] resolver supports CID-hydration using CAS deterministically
- [x] API boundary models are explicit (request/response/errors)
- [x] documentation states IPFS is optional transport, not dependency
- [x] intent tests (determinism, canonicalization, forks, strict mode) remain passing

---

## 5. Actionable Work Order (Suggested)

1. Implement **Local CAS** + conformance tests
2. Wire resolver hydration to CAS (CID-based inputs)
3. Add adapter scaffolding (IPFS/HTTP/bundle) as optional packages
4. Add API boundary models (wire types + error codes)
5. Update docs to reflect storage truth/availability separation
6. Add Flux integration pattern doc

---
