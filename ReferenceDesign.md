# xDAO CATF – Reference Design

**Specification Status:** Stable

**Version:** 1.0

**Release Intent:** Civilization-grade baseline. This version defines the minimum complete, deterministic, and interoperable core of the xDAO CATF protocol.

**Change Policy:**

* Version 1.x MAY receive clarifications and non-semantic editorial fixes.
* Any semantic change that affects determinism, canonicalization, or resolution MUST increment the major version.

---

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

## 1.1 What Is CATF (Canonical Attestation Text Format)

**CATF (Canonical Attestation Text Format)** is a human-readable, cryptographically verifiable, and canonically serializable text format for recording attestations.

CATF is designed to act as a **civilization-grade evidence substrate**. It preserves *what was asserted*, *by whom*, and *about what*, in a form that can be:

* Verified offline
* Archived on paper or digital media
* Reimplemented without reference code
* Interpreted by humans without schemas

CATF binds **meaning first** and **cryptographic proof second**. Cryptography provides evidence of authorship and integrity; it does not create meaning.

CATF is not a database format or execution layer. It is a durable affidavit format designed to survive institutional collapse, cryptographic migration, and technological discontinuity.

---

## 1.2 What Is xDAO (Extended Distributed Autonomous Organization)

**xDAO** is an **Extended Distributed Autonomous Organization platform**.

Unlike conventional DAOs, which focus on token governance, on-chain execution, and economic coordination, xDAO is designed as a **civilization-grade coordination and memory substrate**.

xDAO extends the DAO concept beyond blockchain execution by separating:

* **Evidence** (what was asserted)
* **Authority** (who is trusted, under what policy)
* **Resolution** (how conclusions are derived)
* **Enforcement** (explicitly external)

xDAO is built on CATF and related protocols to enable organizations to:

* Record durable, cryptographically verifiable statements
* Preserve disagreement without forced consensus
* Apply policy-driven trust without global authorities
* Operate offline, independently, and forkably

xDAO is **not** a blockchain, smart contract platform, or token system.

xDAO **is**:

* A distributed institutional memory
* A coordination substrate for law, science, and governance
* A framework for autonomous yet interoperable organizations

xDAO provides autonomy at the organizational layer while remaining **compatible with multiple storage, networking, and execution environments**.

Autonomy in xDAO means:

* No required central operator
* No mandatory global state
* No irreversible consensus

xDAO systems coordinate through **evidence, policy, and resolution**, not force or finality.

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

## 2.4 CATF Canonical Serialization Rules (Normative)

This section defines the **byte-level canonicalization rules** for CATF. These rules are mandatory to ensure deterministic hashing and signing across independent implementations.

### Canonical Encoding Rules

CATF documents MUST adhere to the following:

1. Encoding MUST be UTF-8
2. Line endings MUST be LF (`
   `)
3. No BOM is permitted
4. Trailing whitespace on any line is forbidden

### Structural Rules

1. Sections MUST appear in the following order:
   `META`, `SUBJECT`, `CLAIMS`, `CRYPTO`
2. Section headers MUST appear alone on a single line
3. A single blank line MUST separate sections

### Key–Value Rules

1. Keys MUST be ASCII
2. Keys are case-sensitive
3. Keys within a section MUST be sorted lexicographically (byte order)
4. Each key MUST appear only once per section
5. Key–value pairs MUST be formatted as:
   `Key: <single-space><Value>`

### Signature Scope

The cryptographic signature MUST cover all bytes from:

`-----BEGIN XDAO ATTESTATION-----`

through the end of the `CLAIMS` section, inclusive.

The `Signature:` line itself MUST NOT be included in the signed material.

---

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

## 5.1 Name Resolution Rules (Normative)

Resolvers MUST resolve symbolic names deterministically according to the following rules:

1. Collect all `name-binding` attestations for the requested name
2. Exclude invalid or revoked name-binding attestations
3. Construct a supersession DAG among name-bindings
4. If a single non-superseded binding exists, it is selected
5. If multiple non-superseded bindings exist, a **name fork** is declared
6. Name forks MUST be surfaced explicitly to the caller

Version strings have no intrinsic ordering semantics and are advisory only.

Resolvers MUST NOT:

* Implicitly choose a name binding without policy
* Infer time-based precedence
* Hide name forks

---

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

## 12. CATF Guardrails (Normative)

This section defines the **non-negotiable guardrails** for CATF.
These are **normative requirements** (`MUST / MUST NOT`) that ensure CATF remains verifiable, intelligible, and reconstructable across centuries, technological collapse, and institutional failure.

If any of these guardrails are violated, CATF **ceases to be civilization-grade**.

---

### I. Canonical Authority Guardrails

#### G1 — CATF Is the Canonical Truth

**MUST**

* CATF is the authoritative, canonical representation of an attestation.
* Any other representation (JSON, CBOR, YAML, database rows, APIs) is a *projection*.

**MUST NOT**

* No system may claim validity that cannot be derived from CATF.
* No signature may apply only to a non-CATF representation.

**Rationale:**
Truth must not depend on tooling.

---

#### G2 — Hashes and Signatures Bind CATF, Not Projections

**MUST**

* Cryptographic hashes and signatures MUST be computed over the canonical CATF byte sequence.
* CATF canonicalization rules MUST produce identical bytes across independent implementations.

**MUST NOT**

* No signing of “equivalent JSON”
* No signing of internal object models

**Rationale:**
Independent civilizations must converge on the same bytes.

---

### II. Human Survivability Guardrails

#### G3 — Human-Legible Without External References

**MUST**

* Every CATF document MUST be semantically understandable by a literate human without schemas, URLs, or software.

**MUST NOT**

* No required external schema
* No required network access
* No opaque binary blobs in semantic sections

**Rationale:**
Meaning must survive machine loss.

---

#### G4 — Print-Safe and Transcribable

**MUST**

* CATF MUST be representable entirely as plain text.
* Errors MUST degrade locally (line-level), not globally.

**MUST NOT**

* No indentation-sensitive meaning
* No whitespace-depth semantics
* No escaping rules that conceal content

**Rationale:**
CATF must survive paper, OCR, and manual transcription.

---

### III. Structural Guardrails

#### G5 — Explicitness Over Convenience

**MUST**

* All semantics MUST be explicit key–value pairs.
* No implicit defaults.
* No inferred meaning from omission.

**MUST NOT**

* No positional semantics
* No schema-defined hidden behavior

**Rationale:**
Implicit meaning is the first casualty of civilizational decay.

---

#### G6 — Deterministic Ordering Is Mandatory

**MUST**

* Section order is fixed.
* Key ordering within sections is fixed and specified.
* Canonical spacing and line endings are fixed.

**MUST NOT**

* No implementation-defined ordering
* No locale-dependent formatting

**Rationale:**
Canonical truth requires canonical bytes.

---

### IV. Cryptographic Guardrails

#### G7 — Cryptography Is Evidence, Not Meaning

**MUST**

* Cryptographic material MUST be isolated in a `CRYPTO` section.
* Loss or deprecation of cryptography MUST NOT erase semantic meaning.

**MUST NOT**

* No semantic claims encoded only in cryptographic structures
* No “magic meaning” derived from algorithms

**Rationale:**
Crypto ages. Meaning must not.

---

#### G8 — Cryptographic Agility Is Mandatory

**MUST**

* CATF MUST support re-attestation and cross-signing.
* CATF MUST allow multiple attestations over the same subject.

**MUST NOT**

* No assumption of permanent algorithms
* No single-signature finality model

**Rationale:**
Civilizations outlive cryptosystems.

---

### V. Identity & Authority Guardrails

#### G9 — No Global Root of Authority

**MUST**

* CATF MUST NOT depend on any global registry, root key, or centralized authority.

**MUST NOT**

* No ICANN-like root
* No hardcoded trust anchors

**Rationale:**
Global roots are political failure points.

---

#### G10 — Authority Is Always Explicit

**MUST**

* Every attestation MUST explicitly state its issuer identity.
* Trust decisions MUST be external to CATF (policy-based).

**MUST NOT**

* No implied authority
* No default trust assumptions

**Rationale:**
Authority is contextual, not universal.

---

### VI. Fork & Conflict Guardrails

#### G11 — Forks Are First-Class and Preserved

**MUST**

* CATF MUST allow multiple valid, conflicting attestations to coexist.

**MUST NOT**

* No silent overwrites
* No forced convergence

**Rationale:**
Civilizations disagree. Systems must remember that.

---

#### G12 — Resolution Is External and Recomputable

**MUST**

* CATF MUST NOT encode final resolution logic.
* Resolution MUST be a deterministic function of:

  * attestations
  * trust policy
  * optional context (time, jurisdiction, role)

**MUST NOT**

* No embedded consensus outcomes
* No irreversible “final state”

**Rationale:**
Truth evolves as evidence accumulates.

---

### VII. Naming & Discovery Guardrails

#### G13 — Names Are Advisory, Never Authoritative

**MUST**

* Symbolic names MUST resolve to CIDs via attestations.
* CIDs remain the ultimate authority.

**MUST NOT**

* No name-only references
* No name-based truth claims

**Rationale:**
Names rot. Hashes endure.

---

#### G14 — Name Records Are Attestations

**MUST**

* All name bindings MUST themselves be CATF attestations.
* Name supersession MUST be explicit.

**MUST NOT**

* No implicit TTL
* No mutable registries without attestations

**Rationale:**
Discovery must be auditable.

---

### VIII. Dependency Guardrails

#### G15 — CATF Is Self-Describing

**MUST**

* The CATF specification itself MUST be archivable as plain text.
* A future implementer MUST be able to reconstruct the system from the spec alone.

**MUST NOT**

* No reliance on living websites
* No “see online documentation” dependencies

**Rationale:**
Specifications must survive their creators.

---

### IX. Foundational Principle

> **CATF is designed to preserve evidence, not enforce truth.**
> **Enforcement belongs to people, institutions, and policy.**

If CATF ever attempts to *decide*, it will fail to *survive*.

---

### Summary

CATF is **not**:

* A database format
* A blockchain clone
* A SaaS schema

CATF **is**:

* A durable truth substrate
* A cryptographic affidavit system
* A civilization-grade memory primitive

These guardrails are locked. All future design must comply with them.

---

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

## 17. Canonical Resolver Output Format (CROF)

This section defines the **Canonical Resolver Output Format (CROF)**. CROF is the canonical, text-first, archivable representation of a resolver’s resolved view at a specific point in time.

CROF answers the question:

> *“Given these attestations, this trust policy, and this context — what did this resolver conclude?”*

CROF is itself **evidence** and may be archived, transmitted, signed, and later re-evaluated.

---

## 17.1 Design Goals

CROF MUST:

* Be deterministic and canonical
* Be human-readable without software
* Preserve forks and uncertainty explicitly
* Bind resolution output to exact inputs
* Be archivable and printable

CROF MUST NOT:

* Hide disagreement
* Imply global or permanent truth
* Depend on network access

---

## 17.2 CROF Document Structure

A CROF document is plain text with fixed sections:

```text
-----BEGIN XDAO RESOLUTION-----
META
INPUTS
RESULT
PATHS
FORKS
EXCLUSIONS
VERDICTS
CRYPTO
-----END XDAO RESOLUTION-----
```

All sections MUST appear, even if empty.

---

## 17.3 META Section

Describes the resolution event.

```text
META
Version: 1
Spec: xdao-crof-1
Resolver-ID: xdao-resolver-reference
Resolved-At: 2026-01-10T03:12:00Z
Supersedes-CROF-CID: bafybeipriorcrof...
```

`Resolved-At` is informational only.

`Supersedes-CROF-CID` is optional. If present, it declares that this CROF supersedes a prior CROF by CID.

---

## 17.4 INPUTS Section

Binds the resolution output to its inputs.

```text
INPUTS
Trust-Policy-CID: bafybeipolicy...
Attestation-CID: bafybeiatta1...
Attestation-CID: bafybeiatta2...
```

Rules:

* All input attestations MUST be listed
* Ordering MUST be lexicographic by CID

---

## 17.5 RESULT Section

Defines the resolver’s high-level conclusion.

```text
RESULT
Subject-CID: bafy-doc-1
State: Resolved | Forked | Unresolved | Revoked
Confidence: High | Medium | Low | Undefined
```

Confidence is advisory and policy-dependent.

---

## 17.6 PATHS Section

Enumerates trusted resolution paths.

```text
PATHS
Path-ID: primary
Attestation-CID: bafybeiatta1...
Attestation-CID: bafybeiatta3...
```

Rules:

* Each path is ordered causally
* Multiple paths MAY exist

---

## 17.7 FORKS Section

Explicitly lists conflicting trusted paths.

```text
FORKS
Fork-ID: fork-1
Conflicting-Path: primary
Conflicting-Path: alternative
```

Fork absence MUST be explicit.

---

## 17.8 EXCLUSIONS Section

Lists attestations excluded from trust.

```text
EXCLUSIONS
Attestation-CID: bafybeibad...
Reason: Signature invalid
```

Reasons MUST be explicit and textual.

---

## 17.9 VERDICTS Section

Lists per-attestation evidence that explains how each attestation was handled (trusted, revoked, excluded).

This section is intended for auditability: it allows downstream consumers to preserve a deterministic explanation alongside the final result.

Example:

```text
VERDICTS
Attestation-CID: bafybeiatta1...
Issuer-Key: ed25519:BASE64...
Claim-Type: authorship
Trusted: true
Revoked: false
Trust-Role: author

Attestation-CID: bafybeibad...
Trusted: false
Revoked: false
Excluded-Reason: signature invalid
```

Rules:

* If present, `Attestation-CID` identifies the attestation being described.
* `Trusted` and `Revoked` MUST be explicit (`true`/`false`).
* `Excluded-Reason` is optional; if present it MUST be human-readable text.

---

## 17.10 CRYPTO Section

Binds the resolution output cryptographically.

```text
CRYPTO
Resolver-Key: ed25519:RESOLVERKEY...
Signature-Alg: ed25519
Hash-Alg: sha256
Signature: MEUCIQDv...
```

The signature covers the entire CROF document excluding the `Signature:` line.

---

## 17.11 Determinism Requirements

Resolvers MUST:

* Canonicalize CROF output deterministically
* Produce identical CROF bytes for identical inputs
* Include all forks and exclusions
* If `VERDICTS` are emitted, their ordering MUST be deterministic

---

## 17.12 CROF as Evidence

CROF documents:

* MAY be stored on IPFS
* MAY be CID-addressed
* MAY be cross-signed
* MAY be superseded by later CROFs

CROF does not replace attestations; it records interpretation.

---

## 17.13 Non-Goals of CROF

CROF MUST NOT:

* Enforce real-world actions
* Resolve forks automatically
* Assert global truth

---

## 18. Final Statement (Extended)

> **Attestations record what was said.**
> **Policies record what was trusted.**
> **CROF records what was believed — and why.**

CROF is the memory of interpretation, preserved honestly for the future.

## 19. Reference Test Vectors

This section defines **normative reference test vectors**. These vectors are authoritative examples that resolver implementations MUST pass to claim xDAO compatibility.

Each vector consists of:

* Input CATF attestations
* A Trust Policy (TPDL)
* Expected CROF output (canonical summary)

Test vectors are intentionally small, explicit, and boring.

---

### 19.1 Test Vector 1 — Single-Author Document (No Forks)

**Scenario**: A single author publishes a document. No conflicts exist.

#### Document

* CID: `bafy-doc-1`

#### CATF Attestation A1 (Authorship)

```
-----BEGIN XDAO ATTESTATION-----
META
Version: 1
Spec: xdao-catf-1

SUBJECT
CID: bafy-doc-1
Description: Scientific paper draft

CLAIMS
Type: authorship
Role: author

CRYPTO
Issuer-Key: ed25519:AUTHOR_KEY
Signature-Alg: ed25519
Hash-Alg: sha256
Signature: SIG_A1
-----END XDAO ATTESTATION-----
```

#### Trust Policy

```
-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:AUTHOR_KEY
Role: author

RULES
Require:
  Type: authorship
  Role: author
-----END XDAO TRUST POLICY-----
```

#### Expected CROF Summary

* State: `Resolved`
* Paths: 1
* Forks: 0
* Exclusions: 0

---

### 19.2 Test Vector 2 — Competing Revisions (Forked)

**Scenario**: Two trusted authors publish competing revisions without supersession.

#### CATF Attestations

* A1: Authorship by AUTHOR_A
* A2: Authorship by AUTHOR_B

Both reference the same parent document.

#### Trust Policy

* AUTHOR_A and AUTHOR_B trusted as authors

#### Expected CROF Summary

* State: `Forked`
* Paths: 2
* Forks: 1

Resolvers MUST NOT auto-select a winner.

---

### 19.3 Test Vector 3 — Explicit Supersession

**Scenario**: A later revision explicitly supersedes an earlier one.

#### CATF Attestations

* A1: Authorship (v1)
* A2: Supersedes A1 (v2)

#### Trust Policy

* Author trusted

#### Expected CROF Summary

* State: `Resolved`
* Primary Path: A2 → A1
* Forks: 0

---

### 19.4 Test Vector 4 — Real Estate Multi-Party Approval

**Scenario**: Buyer and Seller must both approve a contract.

#### CATF Attestations

* A1: Approval by Buyer
* A2: Approval by Seller

#### Trust Policy

```
Require:
  Type: approval
  Role: buyer
Require:
  Type: approval
  Role: seller
```

#### Expected CROF Summary

* State: `Resolved`
* Confidence: High

---

### 19.5 Test Vector 5 — Missing Required Party

**Scenario**: Buyer approves, Seller does not.

#### Expected CROF Summary

* State: `Unresolved`
* Reason: Insufficient trusted attestations

---

### 19.6 Test Vector 6 — Revocation

**Scenario**: An approval is later revoked.

#### CATF Attestations

* A1: Approval by Buyer
* A2: Revocation of A1 by Buyer

#### Expected CROF Summary

* State: `Revoked`
* Active Paths: 0

---

### 19.7 Compliance Requirement

Resolver implementations MUST:

* Reproduce the expected CROF state for each test vector
* Preserve forks exactly where specified
* Fail deterministically on deviation

Additional test vectors MAY be added over time. Existing vectors MUST remain valid.

---

> **Reference test vectors are the living constitution of the protocol.**
> They ensure the future cannot quietly rewrite the past.
