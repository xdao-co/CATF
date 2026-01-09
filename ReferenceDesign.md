# xDAO CATF – Reference Design

This document defines the **reference design** for the Canonical Attestation Text Format (CATF) and its supporting system within xDAO. It is written to be implementable, forkable, and survivable.

---

## 1. Design Goals

CATF and xDAO together MUST:

* Preserve evidence across centuries
* Support arbitrary documents and attestations
* Operate without global roots or required networks
* Allow independent implementations to converge
* Make disagreement visible, not destructive

Non-goals:

* Currency, tokens, or gas
* Anonymous adversarial consensus
* Automatic enforcement of truth

---

## 2. Core Objects

### 2.1 Document

A **Document** is any immutable artifact addressed by a CID.

Examples:

* PDF (real estate contract)
* Text manuscript (scientific paper)
* Image, scan, dataset, archive

Properties:

* Immutable
* Content-addressed
* Stored via IPFS or equivalent CAS

---

### 2.2 Attestation (CATF)

An **Attestation** is a signed statement about a document or another attestation.

Canonical form: CATF
Authoritative bytes: CATF canonicalization
Storage: IPFS (CID derived from CATF bytes)

Attestations are append-only and never overwritten.

---

### 2.3 Name Record

A **Name Record** is a special attestation that binds a symbolic name and optional version to a CID.

Names are:

* Advisory
* Mutable via supersession
* Signed
* Forkable

Names never replace CIDs as authority.

---

## 3. Attestation Types (v1 Core)

All types are expressed in CATF `CLAIMS`.

### 3.1 authorship

Asserts creation or authorship.

Required claims:

* Type: authorship
* Role

---

### 3.2 approval

Asserts approval or consent.

Required claims:

* Type: approval
* Role
* Effective-Date

---

### 3.3 supersedes

Asserts replacement of prior CID.

Required claims:

* Type: supersedes
* Supersedes: <CID>

---

### 3.4 revocation

Withdraws trust from a prior attestation.

Required claims:

* Type: revocation
* Target-Attestation: <CID>

---

### 3.5 name-binding

Binds symbolic name + version to CID.

Required claims:

* Type: name-binding
* Name
* Version
* Points-To: <CID>

---

## 4. Identity Model

* Identity = public key
* Recommended: Ed25519
* Encoding: self-describing key prefix

No usernames. No accounts. No passwords.

Key rotation is handled via attestations.

---

## 5. Trust Policy (External)

CATF does **not** encode trust.

Trust is expressed by resolvers as policy:

* Trusted keys
* Required roles
* Quorum thresholds
* Jurisdictional rules

Trust policy input + attestation graph → resolved view.

---

## 6. Resolver Algorithm (Deterministic)

Given:

* Set of CATF attestations
* Trust policy

Steps:

1. Parse and canonicalize CATF
2. Verify signatures
3. Build attestation DAG
4. Apply revocations
5. Apply trust policy
6. Identify forks
7. Produce resolved state + confidence

Resolvers MUST surface forks explicitly.

---

## 7. Versioning Model

Three independent layers:

1. **Content version** – CID (immutable)
2. **Attestation version** – DAG ordering
3. **Name version** – human semantics

Resolvers MUST NOT conflate these.

---

## 8. Storage Model

Minimum requirements:

* Content-addressed storage (IPFS-compatible)
* Optional pinning
* Offline archives supported

No dependency on continuous availability.

---

## 9. Failure & Degradation Modes

Designed outcomes:

* Missing attestations → reduced confidence
* Conflicting attestations → visible forks
* Lost names → CID resolution still valid
* Crypto breakage → semantic meaning preserved

---

## 10. Real Estate Workflow (Example)

1. Contract drafted → CID
2. Buyer approval attestation
3. Seller approval attestation
4. Notary attestation
5. Name-binding: `contracts.realestate.123-main-st@final`

Disputes produce forks, not erasure.

---

## 11. Implementation Guidance

Reference implementations SHOULD:

* Be readable over fast
* Prefer correctness over optimization
* Emit CATF by default
* Never hide forks

---

## 12. Locked Principles

* CATF is canonical
* CIDs are authority
* Names are convenience
* Forks are truth
* Resolution is policy

---

## 13. Deterministic Resolver Contract (DRC)

This section defines the **Deterministic Resolver Contract (DRC)**. The DRC specifies how an xDAO resolver MUST process attestations to produce a resolved view. Given the same inputs and policy, all compliant resolvers MUST produce identical results.

---

## 13.1 Resolver Inputs

A resolver operates over the following explicit inputs:

1. **Attestation Set**

   * A finite set of CATF attestations
   * Each attestation independently verifiable

2. **Trust Policy**

   * A policy definition external to CATF
   * Specifies trusted issuers, roles, quorum rules, and jurisdictional constraints

3. **Resolution Context (Optional)**

   * Time of evaluation
   * Jurisdiction
   * Application-specific role expectations

Resolvers MUST treat missing optional context as undefined, not defaulted.

---

## 13.2 Normalization Phase

Resolvers MUST:

1. Parse CATF documents
2. Apply canonicalization rules
3. Reject attestations that fail canonicalization
4. Verify cryptographic signatures

Invalid attestations MUST be excluded from further processing but MUST be reported.

---

## 13.3 Graph Construction Phase

Resolvers MUST construct a directed acyclic graph (DAG):

* Nodes: attestations
* Edges: `Supersedes`, `Parents`, or equivalent causal references

Multiple roots and branches are expected and valid.

---

## 13.4 Revocation Processing

Resolvers MUST:

1. Identify all revocation attestations
2. Determine revocation validity via trust policy
3. Mark revoked attestations as inactive

Revocation affects trust, not historical existence.

---

## 13.5 Trust Evaluation Phase

Resolvers MUST evaluate attestations against the trust policy:

* Issuer authorization
* Required roles present
* Quorum or multi-signature conditions
* Jurisdictional validity

Attestations failing trust evaluation are retained but marked **untrusted**.

---

## 13.6 Fork Detection

A **fork** exists when:

* Two or more trusted attestations make incompatible claims
* Neither supersedes the other

Resolvers MUST:

* Preserve all forks
* Never auto-resolve forks without explicit policy

---

## 13.7 Resolution Output States

Resolvers MUST produce one of the following states per subject:

* **Resolved** – Single trusted attestation path
* **Forked** – Multiple trusted conflicting paths
* **Unresolved** – Insufficient trusted attestations
* **Revoked** – All trusted attestations revoked

---

## 13.8 Deterministic Selection Rules

Where policy allows selection, resolvers MAY use deterministic tie-breakers such as:

* Explicit supersession
* Quorum weight
* Monotonic counters

Resolvers MUST document any such rules.

---

## 13.9 Resolver Output Contract

Resolver output MUST include:

* Resolved state
* List of supporting attestations (CIDs)
* List of forks (if any)
* Confidence indicators (optional)
* Excluded or invalid attestations

---

## 13.10 Determinism Guarantee

Given:

* Identical attestation sets
* Identical trust policies
* Identical resolution context

All compliant resolvers MUST produce identical outputs.

---

## 13.11 Non-Goals of the Resolver

Resolvers MUST NOT:

* Enforce real-world actions
* Hide forks
* Mutate attestations
* Assume global time

---

## 14. Locked Principles (Reaffirmed)

* CATF is canonical
* CIDs are authority
* Names are convenience
* Forks are truth
* Resolution is policy

---

## 15. Formal Verification of Resolver Determinism

This section defines the **Formal Determinism Guarantee** for xDAO resolvers. It specifies the conditions, invariants, and proof obligations required to ensure that independent resolver implementations always converge on identical outputs.

---

## 15.1 Determinism Statement

**Given**:

* An identical finite set of valid CATF attestations `A`
* An identical trust policy `P`
* An identical resolution context `C`

**Then**:
All compliant resolvers MUST produce an identical resolved output `R`.

Formally:

```
∀ r1, r2 ∈ Resolvers,
Resolve(r1, A, P, C) = Resolve(r2, A, P, C)
```

---

## 15.2 Resolver as a Pure Function

A resolver MUST behave as a **pure function**:

```
Resolve : (A, P, C) → R
```

Where:

* `A` is unordered
* `P` is immutable for the resolution
* `C` is explicitly supplied

Resolvers MUST NOT:

* Depend on wall-clock time
* Depend on network state
* Depend on iteration order of inputs
* Depend on implementation-specific defaults

---

## 15.3 Input Normalization Invariants

Resolvers MUST enforce the following normalization invariants:

1. All CATF documents are canonicalized before processing
2. Invalid or unverifiable attestations are deterministically excluded
3. Attestation identity is defined solely by its CID

These steps guarantee a stable, ordered input domain.

---

## 15.4 Graph Construction Determinism

The attestation DAG MUST be constructed deterministically:

* Nodes sorted lexicographically by CID
* Edges derived only from explicit references (`Supersedes`, `Parents`)
* No inferred or implicit edges allowed

Graph construction MUST yield an identical structure across implementations.

---

## 15.5 Revocation Evaluation Determinism

Revocation processing MUST satisfy:

* Revocation targets identified by CID
* Revocation validity evaluated strictly by trust policy `P`
* No ordering dependence between revocations

Revocation outcome for each attestation MUST be binary and deterministic.

---

## 15.6 Trust Evaluation Determinism

Trust evaluation MUST be:

* Rule-based
* Explicit
* Side-effect free

For any attestation `a ∈ A`:

```
Trusted(a) ∈ {true, false}
```

Trust evaluation MUST NOT:

* Use probabilistic rules
* Use heuristics
* Depend on resolution order

---

## 15.7 Fork Detection Invariants

Fork detection MUST be deterministic:

* Conflict defined only by incompatible trusted claims
* Fork membership determined solely by DAG topology and claim semantics

Resolvers MUST produce identical fork sets for identical inputs.

---

## 15.8 Resolution Selection Rules

Where policy permits selection, resolvers MAY apply deterministic tie-breakers:

* Explicit supersession edges
* Fixed quorum weights
* Lexicographic ordering of CIDs

All such rules MUST be:

* Fully specified
* Deterministic
* Documented

---

## 15.9 Output Canonicalization

Resolver outputs MUST be canonicalized:

* Fixed field ordering
* Stable data structures
* Explicit representation of forks and exclusions

Two compliant resolvers MUST produce byte-identical output representations when serialized canonically.

---

## 15.10 Proof Obligations for Implementations

Each resolver implementation MUST demonstrate:

1. Pure-function behavior
2. Deterministic input handling
3. Deterministic graph construction
4. Deterministic trust evaluation
5. Deterministic output generation

Formal methods MAY include:

* Property-based testing
* Model checking
* Reference test vectors
* Cross-implementation comparison

---

## 15.11 Non-Determinism Prohibitions

Resolvers MUST NOT:

* Use randomization
* Use concurrency without deterministic reduction
* Use unordered data structures without explicit ordering
* Depend on external mutable state

Any such behavior violates compliance.

---

## 15.12 Determinism as a Compliance Requirement

Resolver determinism is a **hard compliance requirement**.

Non-deterministic resolvers:

* Are non-compliant
* Must not claim xDAO compatibility

---

## 16. Trust Policy DSL (TPDL)

This section defines the **Trust Policy Domain Language (TPDL)**. TPDL is a minimal, text-first language used by resolvers to express trust assumptions deterministically.

TPDL is intentionally small, boring, and explicit. It is not expressive by default; it is extensible by layering.

---

## 16.1 Design Goals

TPDL MUST:

* Be human-readable without tooling
* Be deterministic and side-effect free
* Be archivable as plain text
* Avoid Turing-completeness
* Allow independent implementations to converge

TPDL MUST NOT:

* Execute code
* Fetch network resources
* Depend on external state

---

## 16.2 Core Model

A Trust Policy evaluates attestations by answering two questions:

1. **Is the issuer trusted for this claim?**
2. **Are sufficient trusted claims present?**

TPDL expresses these rules declaratively.

---

## 16.3 Policy Document Structure

A TPDL document is plain text with fixed sections:

```
-----BEGIN XDAO TRUST POLICY-----
META
TRUST
RULES
-----END XDAO TRUST POLICY-----
```

---

## 16.4 META Section

Describes the policy itself.

```
META
Version: 1
Spec: xdao-tpdl-1
Description: Iowa real estate purchase agreement policy
```

---

## 16.5 TRUST Section

Defines trusted identities and roles.

```
TRUST
Key: ed25519:BUYER_KEY
Role: buyer

Key: ed25519:SELLER_KEY
Role: seller

Key: ed25519:NOTARY_KEY
Role: notary
```

Rules:

* Keys may appear multiple times with different roles
* Roles are symbolic strings
* No implicit trust exists outside this section

---

## 16.6 RULES Section

Defines evaluation rules.

### 16.6.1 Require Rules

```
RULES
Require:
  Type: approval
  Role: buyer

Require:
  Type: approval
  Role: seller

Require:
  Type: notarization
  Role: notary
```

Semantics:

* Each `Require` block must be satisfied
* Order is irrelevant

---

### 16.6.2 Quorum Rules (Optional)

```
Require:
  Type: approval
  Role: board-member
  Quorum: 3
```

Semantics:

* At least `Quorum` distinct trusted issuers must satisfy the rule

---

### 16.6.3 Supersession Rules

```
Supersedes:
  Allowed-By: buyer, seller
```

Semantics:

* Supersession attestations are trusted only if signed by allowed roles

---

## 16.7 Deterministic Evaluation Rules

Resolvers MUST:

* Evaluate TRUST bindings first
* Evaluate RULES independently
* Treat missing rules as unmet
* Treat unmet rules as unresolved state

No rule short-circuiting is permitted.

---

## 16.8 Prohibited Features

TPDL MUST NOT include:

* Conditionals (`if`, `else`)
* Loops
* Arithmetic beyond quorum counts
* Time-based logic
* External references

---

## 16.9 Policy Resolution Output

Policy evaluation yields:

* `Satisfied`
* `Unsatisfied`
* `Insufficient Evidence`

These results feed into the Deterministic Resolver Contract.

---

## 16.10 Policy Versioning

Policies are immutable documents.

Updates require:

* New policy document
* Explicit supersession via CATF attestation

---

## 16.11 Compliance Requirement

Resolvers claiming xDAO compatibility MUST:

* Parse TPDL exactly as specified
* Reject non-conforming policies
* Apply policies deterministically

---

## 17. Final Statement (Extended)

> **Trust policies declare assumptions.**
> **Resolvers apply them mechanically.**
> **Truth emerges from evidence plus policy — never from code alone.**
