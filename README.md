# CATF Guardrails  
**Canonical Attestation Text Format (xDAO)**  
**Civilization-Grade Normative Constraints**

This section defines the **non-negotiable guardrails** for CATF.  
These are **normative requirements** (`MUST / MUST NOT`) that ensure CATF remains verifiable, intelligible, and reconstructable across centuries, technological collapse, and institutional failure.

If any of these guardrails are violated, CATF **ceases to be civilization-grade**.

---

## I. Canonical Authority Guardrails

### G1 — CATF Is the Canonical Truth
**MUST**
- CATF is the authoritative, canonical representation of an attestation.
- Any other representation (JSON, CBOR, YAML, database rows, APIs) is a *projection*.

**MUST NOT**
- No system may claim validity that cannot be derived from CATF.
- No signature may apply only to a non-CATF representation.

**Rationale:**  
Truth must not depend on tooling.

---

### G2 — Hashes and Signatures Bind CATF, Not Projections
**MUST**
- Cryptographic hashes and signatures MUST be computed over the canonical CATF byte sequence.
- CATF canonicalization rules MUST produce identical bytes across independent implementations.

**MUST NOT**
- No signing of “equivalent JSON”
- No signing of internal object models

**Rationale:**  
Independent civilizations must converge on the same bytes.

---

## II. Human Survivability Guardrails

### G3 — Human-Legible Without External References
**MUST**
- Every CATF document MUST be semantically understandable by a literate human without schemas, URLs, or software.

**MUST NOT**
- No required external schema
- No required network access
- No opaque binary blobs in semantic sections

**Rationale:**  
Meaning must survive machine loss.

---

### G4 — Print-Safe and Transcribable
**MUST**
- CATF MUST be representable entirely as plain text.
- Errors MUST degrade locally (line-level), not globally.

**MUST NOT**
- No indentation-sensitive meaning
- No whitespace-depth semantics
- No escaping rules that conceal content

**Rationale:**  
CATF must survive paper, OCR, and manual transcription.

---

## III. Structural Guardrails

### G5 — Explicitness Over Convenience
**MUST**
- All semantics MUST be explicit key–value pairs.
- No implicit defaults.
- No inferred meaning from omission.

**MUST NOT**
- No positional semantics
- No schema-defined hidden behavior

**Rationale:**  
Implicit meaning is the first casualty of civilizational decay.

---

### G6 — Deterministic Ordering Is Mandatory
**MUST**
- Section order is fixed.
- Key ordering within sections is fixed and specified.
- Canonical spacing and line endings are fixed.

**MUST NOT**
- No implementation-defined ordering
- No locale-dependent formatting

**Rationale:**  
Canonical truth requires canonical bytes.

---

## IV. Cryptographic Guardrails

### G7 — Cryptography Is Evidence, Not Meaning
**MUST**
- Cryptographic material MUST be isolated in a `CRYPTO` section.
- Loss or deprecation of cryptography MUST NOT erase semantic meaning.

**MUST NOT**
- No semantic claims encoded only in cryptographic structures
- No “magic meaning” derived from algorithms

**Rationale:**  
Crypto ages. Meaning must not.

---

### G8 — Cryptographic Agility Is Mandatory
**MUST**
- CATF MUST support re-attestation and cross-signing.
- CATF MUST allow multiple attestations over the same subject.

**MUST NOT**
- No assumption of permanent algorithms
- No single-signature finality model

**Rationale:**  
Civilizations outlive cryptosystems.

---

## V. Identity & Authority Guardrails

### G9 — No Global Root of Authority
**MUST**
- CATF MUST NOT depend on any global registry, root key, or centralized authority.

**MUST NOT**
- No ICANN-like root
- No hardcoded trust anchors

**Rationale:**  
Global roots are political failure points.

---

### G10 — Authority Is Always Explicit
**MUST**
- Every attestation MUST explicitly state its issuer identity.
- Trust decisions MUST be external to CATF (policy-based).

**MUST NOT**
- No implied authority
- No default trust assumptions

**Rationale:**  
Authority is contextual, not universal.

---

## VI. Fork & Conflict Guardrails

### G11 — Forks Are First-Class and Preserved
**MUST**
- CATF MUST allow multiple valid, conflicting attestations to coexist.

**MUST NOT**
- No silent overwrites
- No forced convergence

**Rationale:**  
Civilizations disagree. Systems must remember that.

---

### G12 — Resolution Is External and Recomputable
**MUST**
- CATF MUST NOT encode final resolution logic.
- Resolution MUST be a deterministic function of:
  - attestations
  - trust policy
  - optional context (time, jurisdiction, role)

**MUST NOT**
- No embedded consensus outcomes
- No irreversible “final state”

**Rationale:**  
Truth evolves as evidence accumulates.

---

## VII. Naming & Discovery Guardrails

### G13 — Names Are Advisory, Never Authoritative
**MUST**
- Symbolic names MUST resolve to CIDs via attestations.
- CIDs remain the ultimate authority.

**MUST NOT**
- No name-only references
- No name-based truth claims

**Rationale:**  
Names rot. Hashes endure.

---

### G14 — Name Records Are Attestations
**MUST**
- All name bindings MUST themselves be CATF attestations.
- Name supersession MUST be explicit.

**MUST NOT**
- No implicit TTL
- No mutable registries without attestations

**Rationale:**  
Discovery must be auditable.

---

## VIII. Dependency Guardrails

### G15 — CATF Is Self-Describing
**MUST**
- The CATF specification itself MUST be archivable as plain text.
- A future implementer MUST be able to reconstruct the system from the spec alone.

**MUST NOT**
- No reliance on living websites
- No “see online documentation” dependencies

**Rationale:**  
Specifications must survive their creators.

---

## IX. Foundational Principle

> **CATF is designed to preserve evidence, not enforce truth.**  
> **Enforcement belongs to people, institutions, and policy.**

If CATF ever attempts to *decide*, it will fail to *survive*.

---

## Summary

CATF is **not**:
- A database format  
- A blockchain clone  
- A SaaS schema  

CATF **is**:
- A durable truth substrate
- A cryptographic affidavit system
- A civilization-grade memory primitive

These guardrails are locked. All future design must comply with them.
