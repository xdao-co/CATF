# xDAO CATF

- Reference design: [ReferenceDesign.md](ReferenceDesign.md)
- Structural contract (normative): [spec/CATF-STRUCT-1.md](spec/CATF-STRUCT-1.md)
- Conformance vectors: [CONFORMANCE.md](CONFORMANCE.md)
- Stability & versioning: [STABILITY.md](STABILITY.md)
- CLI how-to: [CLI.md](CLI.md)
- Integration guide: [Integration.md](Integration.md)
- End-to-end workflows: [UseCases.md](UseCases.md)
- Runnable scripts: [examples/README.md](examples/README.md)

## Glossary

This glossary defines normative terms used throughout the xDAO CATF specification. Terms are written to be durable, implementation-agnostic, and unambiguous.

---

### Attestation

A signed, immutable statement asserting something about a subject (such as a document, another attestation, or a name binding). Attestations are expressed in **CATF** and are content-addressed.

---

### CATF (Canonical Attestation Text Format)

A human-legible, canonically serializable text format for recording attestations. CATF is the authoritative representation of an attestation; all hashes, signatures, and identifiers are derived from its canonical byte form.

---

### Canonicalization

The deterministic process of transforming a CATF or CROF document into a unique, byte-for-byte representation. Canonicalization ensures that independent implementations derive identical bytes from identical semantic content.

---

### CID (Content Identifier)

A content-addressed identifier derived from cryptographic hashing of canonical bytes. CIDs provide immutable, location-independent reference to documents, attestations, and resolver outputs.

---

### CROF (Canonical Resolver Output Format)

A canonical, text-first representation of a resolver’s output. CROF records the result of applying attestations, trust policy, and context to produce a resolved view. CROF is itself evidence and may be stored, signed, superseded, and re-evaluated.

---

### Deterministic Resolver

A resolver that behaves as a pure function: given identical inputs (attestations, trust policy, context), it produces identical outputs. Deterministic resolvers MUST not depend on time, network state, or implementation-specific behavior.

---

### Deterministic Resolver Contract (DRC)

The normative specification defining how resolvers MUST process attestations, apply trust policy, detect forks, and produce CROF output deterministically.

---

### Document

An immutable artifact (e.g., text, PDF, image, dataset) addressed by a CID. Documents are stored via content-addressed storage and are not modified in place.

---

### Fork

The existence of multiple valid, conflicting attestations or resolution paths that cannot be deterministically reconciled under a given trust policy. Forks are first-class outcomes and MUST be preserved and surfaced.

---

### Name Binding

An attestation that associates a symbolic name (and optional version) with a CID. Name bindings are advisory and do not supersede the authority of CIDs.

---

### Supersession

An explicit, content-addressed “this replaces that” relationship.

Supersession never mutates or deletes older evidence. Instead, it creates a new immutable object (a new attestation or a new CROF) that *references* the prior object by CID.

There are two common uses:

- **Attestation supersession (CATF)**: an attestation with `Type=supersedes` points at a prior attestation CID (a revision chain).
- **Resolution supersession (CROF)**: a newer CROF includes `META: Supersedes-CROF-CID: <PriorCROFCID>`.

Why use supersession?

- To publish an updated resolution after new attestations arrive, policy changes, or a resolver bugfix/upgrade.
- To keep history: consumers can audit what changed and when.

Minimal CROF supersession validity rules enforced by the reference implementation:

- New CROF `B` must declare `Supersedes-CROF-CID` equal to `CID(A)`.
- `A` and `B` must bind the same `RESULT: Subject-CID`.
- `A` and `B` must use the same `META: Resolver-ID`.
- `A` and `B` must use the same `INPUTS: Trust-Policy-CID`.

For normative details, see ReferenceDesign.md §17.13 (“CROF Supersession Semantics”).

---

### Resolution

The process of evaluating attestations under a trust policy to produce a resolved view. Resolution does not enforce real-world action and may result in resolved, forked, unresolved, or revoked states.

---

### Trust Policy

An external, declarative set of rules defining which issuers, roles, and conditions are trusted for specific claims. Trust policy is not encoded in CATF and is evaluated by the resolver.

---

### TPDL (Trust Policy Domain Language)

A minimal, text-first language used to express trust policies deterministically. TPDL is intentionally non-Turing-complete and free of external dependencies.

---

### xDAO (Extended Distributed Autonomous Organization)

A platform for decentralized coordination based on evidence, policy, and deterministic resolution. xDAO extends the DAO concept beyond on-chain execution by separating attestation, trust, resolution, and enforcement.

## Library notes

- Spec compliance: the ReferenceDesign.md §19 test vectors run under `go test ./...`.
- Crypto agility: CATF verification supports `Signature-Alg: ed25519 | dilithium3` and `Hash-Alg: sha256 | sha512 | sha3-256`.

## Documentation sync policy

When changing behavior or formats in the reference implementation:

- CLI flags/outputs: update [CLI.md](CLI.md)
- Integration-facing behavior/APIs: update [Integration.md](Integration.md)
- Normative format rules and examples: update [ReferenceDesign.md](ReferenceDesign.md)

## IPFS note (local vs network publishing)

- The reference workflows assume your local node (e.g. an XDAO Node) has the Kubo `ipfs` CLI installed.
- `doc-cid` only computes a CID (content-addressing); it does not publish bytes.
- `ipfs put` stores bytes into the local IPFS repo without requiring a daemon.
- If you intend to publish to the IPFS network “for real” (so other peers can fetch it), your node must be running in daemon mode (`ipfs daemon`) and the content must be provided/pinned by that node.
