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
  - `Render`, `RenderSigned`, `CID`, `ValidateSupersession`
  - `RenderWithCompliance` (strict output compliance gate)

- Package `xdao.co/catf/tpdl`
  - `Parse([]byte) (*Policy, error)` and policy model types

- Package `xdao.co/catf/cidutil`
  - `CIDv1RawSHA256([]byte) string`

- Package `xdao.co/catf/compliance`
  - `ComplianceMode` (`Permissive`, `Strict`)

- Package `xdao.co/catf/keys` (pure primitives only)
  - `GenerateIssuerKeyFromSeed([]byte) string`
  - `DeriveRoleSeed([]byte, string) ([]byte, error)`
  - `IssuerKeyFromPublicKey(ed25519.PublicKey) (string, error)`

### Experimental

Experimental APIs MAY change in MINOR releases.
They should be used with pinning and explicit upgrade review.

- Package `xdao.co/catf/catf`
  - `NormalizeCATF([]byte) ([]byte, error)` (model-first canonicalization helper)

- Package `xdao.co/catf/keys`
  - Filesystem-backed key storage and convenience helpers (`KeyStore`, `CreateKeyStore`, etc.)
  - These are intentionally local-first utilities and may change independently of the protocol core.

- Packages under `xdao.co/catf/internal/...`

- Package `xdao.co/catf/cmd/xdao-catf` (CLI; not a library API)

### Internal

Internal APIs are not for external consumption and may change at any time.

- Package `xdao.co/catf/catf`
  - Rule-engine plumbing (`Rule`, `ValidateRules`, `ValidateRulesAll`) is UNSUPPORTED for downstream use.
    These symbols are exported for reference implementation composition and tests, but are not part of
    the stable protocol-facing library surface.

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
