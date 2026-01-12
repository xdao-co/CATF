# CATF-ERRORS-1 — Error Taxonomy & Rule Catalog (Normative)

Status: Normative

This document defines:

- A stable error taxonomy (`Kind`) for programmatic handling.
- A stable catalog of `RuleID` values.
- The deterministic precedence rules for which `RuleID` MUST be reported.

Non-goals:

- This does not define trust policy semantics (TPDL).
- This does not define resolver policy selection.
- This does not rely on JSON Schema, OpenAPI, or any serialization-coupled validator.

## 1. Structured Errors

Implementations MUST expose structured errors with:

- `Kind`: stable category
- `RuleID`: stable identifier of the violated rule
- `Message`: human-readable (not stable)

Callers MUST branch on (`Kind`, `RuleID`), not on `Message`.

## 2. Kinds

`Kind` values are stable and intended for coarse-grained handling:

- `Parse`: byte-level or structural parse failure
- `Canonical`: canonical form failure
- `Validation`: semantic/core-claims validation failure
- `Render`: canonical rendering/model-to-bytes failure
- `Crypto`: signature/hash algorithm handling or verification failure
- `CID`: content identifier computation failure
- `Internal`: invariant violation in the implementation itself

## 3. Precedence (Deterministic)

When multiple issues exist in the same input, implementations MUST report the first failing rule according to this deterministic pipeline:

1. Byte-level invariants (CATF-STR-001, CATF-CANON-001..003)
2. Structural parse invariants (CATF-STR-010, CATF-STR-020, CATF-CANON-010, CATF-STR-030)
3. Canonical invariants (CATF-CANON-020, CATF-CANON-030)
4. Semantic/core-claims validation rules (CATF-VAL-###)

Within a stage, rule evaluation order MUST be deterministic (and is part of conformance).

## 4. Rule Catalog

### CATF-STR-001 UTF-8

- Meaning: document bytes MUST be valid UTF-8.
- Typical `Kind`: `Parse`.

### CATF-CANON-001 Line endings

- Meaning: CR (`\r`) is forbidden; LF-only document.
- Typical `Kind`: `Canonical`.

### CATF-CANON-002 No BOM

- Meaning: UTF-8 BOM (0xEF,0xBB,0xBF) is forbidden.
- Typical `Kind`: `Canonical`.

### CATF-CANON-003 No trailing newline

- Meaning: the document MUST NOT end with a trailing `\n`.
- Typical `Kind`: `Canonical`.

### CATF-STR-010 Preamble/Postamble

- Meaning: exact preamble and postamble lines are required.
- Notes:
  - “Preamble must be on its own line” is covered by this rule.
- Typical `Kind`: `Parse`.

### CATF-STR-020 Section order and presence

- Meaning: exactly the sections `META`, `SUBJECT`, `CLAIMS`, `CRYPTO` in that order.
- Typical `Kind`: `Parse`.

### CATF-CANON-010 Section separation

- Meaning: exactly one blank line between sections; no stray blank lines.
- Typical `Kind`: `Parse`.

### CATF-STR-030 Key/value constraints

- Meaning: key/value line delimiter, ASCII keys, uniqueness, and value constraints.
- Typical `Kind`: `Parse` or `Render`.

### CATF-CANON-020 Key order

- Meaning: within each section, keys are in strict lexicographic order.
- Typical `Kind`: `Canonical`.

### CATF-CANON-030 Canonical byte identity

- Meaning: parsing + canonical rendering MUST reproduce identical bytes.
- Typical `Kind`: `Canonical`.

### CATF-STR-999 I/O/read failure

- Meaning: internal read failure while parsing.
- Typical `Kind`: `Parse`.

### CATF-RENDER-001 Render failure

- Meaning: renderer failed for a reason not covered by a structured CATF-* rule.
- Typical `Kind`: `Render`.

## 5. Validation Rules (CATF-VAL-###)

The CATF v1 core claim validation rules are stable and deterministic.

- `CATF-VAL-101`: missing `CLAIMS` section
- `CATF-VAL-102`: missing required claim `Type`
- Type-specific requirements:
  - `authorship`: `CATF-VAL-201` requires `Role`
  - `approval`: `CATF-VAL-211` requires `Role`; `CATF-VAL-212` requires `Effective-Date`
  - `supersedes`: `CATF-VAL-221` requires `Supersedes`
  - `revocation`: `CATF-VAL-231` requires `Target-Attestation`
  - `name-binding`: `CATF-VAL-241` requires `Name`; `CATF-VAL-242` requires `Version`; `CATF-VAL-243` requires `Points-To`

Unknown claim types are permitted; this rule set only validates CATF v1 core requirements.
