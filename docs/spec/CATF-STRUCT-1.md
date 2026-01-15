# CATF-STRUCT-1 — Structural Contract (Normative)

Status: Normative

This document defines a **serialization-independent structural contract** for CATF documents.
It is intended to be used as a machine-enforceable set of invariants for conformance testing and multi-language implementations.

Non-goals:

- This is not an API specification.
- This does not define trust policy semantics (TPDL) or resolver behavior.
- This does not rely on JSON Schema, OpenAPI, or any serialization-coupled validator.

## 1. Model

A CATF document is a sequence of bytes that, when interpreted as UTF-8 text, yields a document with:

- A preamble line
- Exactly four ordered sections: `META`, `SUBJECT`, `CLAIMS`, `CRYPTO`
- Each section is a set of key/value pairs

Meaning is derived from the (section, key, value) triples — **not** from the original presentation beyond canonicalization.

## 2. Invariants

### CATF-STR-001 UTF-8

The document bytes MUST be valid UTF-8.

### CATF-CANON-001 Line endings

The document MUST use LF (`\n`) line endings only. CR (`\r`) is forbidden.

### CATF-CANON-002 No BOM

A UTF-8 BOM (0xEF,0xBB,0xBF) is forbidden.

### CATF-CANON-003 No trailing newline

The document MUST NOT end with a trailing newline.

### CATF-STR-010 Preamble/Postamble

The document MUST begin with the exact preamble line:

- `-----BEGIN XDAO ATTESTATION-----`

The document MUST end with the exact postamble line:

- `-----END XDAO ATTESTATION-----`

### CATF-STR-020 Section order and presence

The document MUST contain exactly these sections, in this order:

1. `META`
2. `SUBJECT`
3. `CLAIMS`
4. `CRYPTO`

Each section header MUST appear on its own line.

### CATF-CANON-010 Section separation

There MUST be exactly one blank line between sections.
No blank line is allowed:

- Before the first section
- After the `CRYPTO` section
- Immediately before the postamble

### CATF-STR-030 Key/value lines

Within a section, each key/value line MUST use the delimiter `": "` (colon + single space).

Keys:

- MUST be non-empty
- MUST be ASCII
- MUST be unique within their section

Values:

- MUST be non-empty
- MUST NOT start with a space
- MUST NOT contain `\n` or `\r`
- MUST NOT end with a space or tab

### CATF-CANON-020 Key order

Within each section, keys MUST appear in strict lexicographic order (bytewise ASCII order).

### CATF-CANON-030 Canonical byte identity

A canonical CATF document MUST be identical (byte-for-byte) to the output of rendering its parsed (section,key,value) model under the canonical rendering rules.

## 3. Traversal Rules (for validators)

A validator MUST:

1. Validate byte-level invariants (`UTF-8`, `LF-only`, `no BOM`, `no trailing newline`).
2. Parse the document into the section model.
3. Validate structural invariants (section order/presence, separators, key/value line constraints, uniqueness).
4. Validate canonical invariants (key order, canonical byte identity).

## 4. Notes for Re-Implementers

- The reference implementation may provide additional helper APIs, but MUST NOT be treated as the sole authority.
- Conformance SHOULD be validated using published test vectors.
