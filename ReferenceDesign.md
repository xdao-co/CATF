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

## 13. Next Design Stages

Planned extensions:

* Trust Policy DSL
* Jurisdiction modules
* Schema registries (CID-addressed)
* Resolver UX standards
* Long-term archive profiles

This document defines the **foundation**. All extensions MUST comply.
