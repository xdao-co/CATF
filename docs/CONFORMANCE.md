# Conformance (Normative Test Vectors)

This repository publishes **conformance vectors** intended to be usable by independent, multi-language implementations.

Constraints:

- Vectors are **serialization-independent in meaning** (i.e., they assert semantic invariants), but CATF/CROF are text formats, so vectors are published as canonical bytes.
- Vectors are intended to be stable; changes SHOULD be rare and reviewed as spec changes.

## Locations

- Structural contract (normative): [spec/CATF-STRUCT-1.md](spec/CATF-STRUCT-1.md)
- Error taxonomy & rule catalog (normative): [spec/CATF-ERRORS-1.md](spec/CATF-ERRORS-1.md)
- CATF vectors: `src/testdata/conformance/catf/`
- Resolver vectors: `src/testdata/conformance/resolver/`

## What Vectors Assert

Vectors may assert one or more of:

- Structural equivalence
- Canonical equivalence (byte-for-byte)
- Hash equivalence (CID)
- Signature verification expectations
- Resolver determinism (given explicit inputs)

Resolver vectors MUST include all resolver inputs (attestation bytes, trust policy bytes, subject CID, resolver ID/options) and publish the expected CROF bytes + CID.

## Running in Go

- `cd src && go test ./...`

The Go tests treat these vectors as first-class artifacts to prevent behavioral drift.
