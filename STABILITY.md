# Stability & Versioning Policy (Normative for This Repository)

This repository contains a reference implementation of CATF/CROF and related components.
The **specification** remains the authority; this code MUST NOT become the de facto spec.

## Semantic Versioning

The Go module follows Semantic Versioning (SemVer): `MAJOR.MINOR.PATCH`.

- **PATCH**: bugfixes; no breaking changes to Stable APIs.
- **MINOR**: new backwards-compatible features; may add new Stable APIs.
- **MAJOR**: breaking changes (including Stable API changes or conformance vector resets).

## API Tiers

### Stable

Stable APIs are intended for long-term, multi-language reimplementation and SHOULD NOT change without a MAJOR version bump.

- Package `xdao.co/catf/catf`
  - `Parse([]byte) (*CATF, error)` (parses canonical CATF; rejects non-canonical bytes)
  - `CanonicalizeCATF([]byte) ([]byte, error)`
  - `ValidateCoreClaims(*CATF) error` (rule-ID-driven)
  - `(*CATF).CanonicalBytes() []byte`
  - `(*CATF).SignedBytes() []byte`
  - `(*CATF).CID() (string, error)`
  - `(*CATF).Verify() error`
  - Structured error type: `*catf.Error` (`Kind`, `RuleID`)

- Package `xdao.co/catf/resolver`
  - `Resolve(attestations, policy, subjectCID)`
  - `ResolveStrict(attestations, policy, subjectCID)`
  - `ResolveName(attestations, policy, name, version)`

- Package `xdao.co/catf/crof`
  - `Render`, `CID`, `ValidateSupersession`
  - `RenderWithCompliance` (strict output compliance gate)

### Experimental

Experimental APIs MAY change in MINOR releases.
They should be used with pinning and explicit upgrade review.

- Package `xdao.co/catf/catf`
  - `NormalizeCATF([]byte) ([]byte, error)` (model-first canonicalization helper)

- Packages under `xdao.co/catf/internal/...`

### Internal

Internal APIs are not for external consumption and may change at any time.

## Required Processing Pipeline

Consumers SHOULD treat CATF processing as a strict, explicit pipeline:

1. Parse
2. Validate
3. Canonicalize
4. Hash (CID)
5. Resolve
6. Verify

Each step is intended to be deterministic and idempotent.

## Conformance Artifacts

Normative conformance vectors live under:

- `src/testdata/conformance/`

They are intended to prevent behavioral drift and enable multi-language validation.
