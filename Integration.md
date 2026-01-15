# Integration Guide (External Projects)

This repo provides:

- **CATF** (Canonical Attestation Text Format): canonical, signed attestations over a subject CID
- **TPDL** (Trust Policy Definition Language): policies that define *who is trusted* and *what is required*
- **Resolver**: evaluates attestations under a policy and emits **CROF** (Canonical Resolution Output Format)

This document explains what an external project needs to define (roles, policies, key model, and subject CIDs) and how to integrate either via the CLI or directly via Go packages.

---

## Mental model

An integration has four core artifacts:

1) **Subject bytes**: your document/data (e.g. PDF, JSON export, public key file)
2) **Subject CID**: a stable content-addressed identifier derived from those bytes
3) **Attestations (CATF)**: statements about the subject, signed by issuer keys
4) **Trust policy (TPDL)**: declares which keys are trusted for which roles, and which attestations are required

Resolution is deterministic:

- Inputs: `policy bytes` + `attestation bytes[]` + `subject CID`
- Output: CROF resolution state + paths/forks/exclusions

---

## 1) Define your subject canonicalization (what exactly is hashed)

Your project must be explicit about what bytes are hashed/published to produce the **subject CID**.

Typical choices:

- **File bytes as-is** (simple): hash the PDF/text/JSON file bytes exactly
- **Canonical export** (recommended for structured data): define a deterministic serialization (stable JSON, stable CSV, etc.) and hash that

### CID computation (hash-only)

Use `doc-cid` to compute a stable CID for bytes:

```sh
./bin/xdao-catf doc-cid ./path/to/subject.bin
```

This only computes the CID; it does not store bytes anywhere.

### Store bytes in local IPFS repo (no daemon required)

If you want to also store bytes locally in your node’s IPFS repo:

```sh
./bin/xdao-catf ipfs put --init ./path/to/subject.bin
```

This writes the raw block to the local IPFS repo (via `ipfs block put`) and prints the CID.

### Publish to the IPFS network

If you intend other peers to fetch the content, you need a network-facing node (or pinning layer). Concretely:

- Install Kubo `ipfs`
- Run the node in daemon mode: `ipfs daemon`
- Ensure content is pinned/served by that node (or an XDAO Node service)

---

## 2) Define role vocabulary (your contract with policy)

Roles are **policy-level labels** used to interpret issuer keys and attestations.

Your external project should define a small role vocabulary and use it consistently in:

- `TRUST` entries (which key can act in which role)
- `CLAIMS` (what role the attestation is asserting)
- `RULES` requirements (what roles/types are required for resolution)

Examples:

- Document workflows: `author`, `reviewer`, `publisher`
- AI workflows: `ai-reviewer`
- Real estate: `buyer`, `seller`, `escrow-agent`, `notary`
- Name registry: `registrar`

Guidelines:

- Keep role names stable (policy depends on them).
- Prefer a small set of roles; encode nuances in additional claims if needed.
- If you need scope, use conventions (e.g. `reviewer:medical`, `reviewer:legal`) and treat that as part of the role string.

---

## 3) Define claim types you will use

The resolver evaluates attestations primarily via their claims.

Common core types (v1 patterns used by the examples/CLI):

- `Type=authorship` — asserts authorship / provenance
- `Type=approval` — asserts approval / acceptance (often gated by policy)
- `Type=revocation` — invalidates a prior attestation via `Target-Attestation=<CID>`
- `Type=supersedes` — links to prior via `Supersedes=<CID>` (revision chain)
- `Type=name-binding` — binds `Name + Version -> Points-To`

Typical required claims by type:

- `authorship`: `Role`
- `approval`: `Role`, and usually `Effective-Date` (required; the reference CLI requires you to provide it)
- `revocation`: `Target-Attestation`
- `supersedes`: `Supersedes`
- `name-binding`: `Name`, `Version`, `Points-To`

Project-specific claims are allowed (e.g. `Comment=...`, `Funds=...`). They will not affect resolution unless you later add policy semantics that interpret them.

---

## 4) Choose your key model (how you issue and trust keys)

You need issuer keys to sign CATF attestations. Policies reference issuer **public keys**.

### Option A: KMS-lite (local-first)

This repo includes a minimal local key store (good for pilots and offline workflows):

```sh
./bin/xdao-catf key init --name alice
./bin/xdao-catf key derive --from alice --role author
./bin/xdao-catf key export --name alice --role author   # prints ed25519:<base64>
```

Pattern:

- Root key = identity
- Derived role keys = operational separation (rotate/revoke per role)

### Option B: Bring-your-own signing

If your project already has keys (HSM, Vault, wallet, etc.), you can:

- Publish issuer public keys in `TRUST` as `ed25519:<base64>` or `dilithium3:<base64>`
- Produce valid CATF attestations using the Go packages (or extend CLI integration)

Notes:

- `Issuer-Key` is required and is algorithm-qualified (e.g. `ed25519:...`, `dilithium3:...`).
- `Issuer-Key` must match `Signature-Alg` (mismatches are rejected).

---

## 5) Author policies (TPDL)

A TPDL policy has:

- `TRUST`: (Issuer public key → role)
- `RULES`: what must be satisfied for resolution

Minimal template:

```text
-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:BASE64PUBKEY_1
Role: author

Key: ed25519:BASE64PUBKEY_2
Role: reviewer

RULES
Require:
  Type: authorship
  Role: author

Require:
  Type: approval
  Role: reviewer
-----END XDAO TRUST POLICY-----
```

Policy parsing notes:

- `META` is required and must include `Spec: xdao-tpdl-1` and `Version: 1`.
- A single public key may appear multiple times with different `Role:` values; roles are accumulated.

Quorum example:

```text
Require:
  Type: approval
  Role: ai-reviewer
  Quorum: 2
```

Practical guidance:

- Treat policies as versioned configuration artifacts.
- In production, generate policies from your application state (users/organizations/registrars) rather than hand-editing.
- Keep the policy text canonical/stable so it can be content-addressed and audited.
- If you use `Type=supersedes`, prefer adding `Supersedes: Allowed-By` constraints so supersedes authority is explicit.

---

## 6) Produce attestations (CATF)

Your app can produce CATF using the CLI (easy) or Go packages (tight integration).

### CLI (reference)

```sh
./bin/xdao-catf attest \
  --subject "$SUBJECT_CID" \
  --description "Purchase agreement" \
  --signer buyer \
  --signer-role buyer \
  --type approval \
  --role buyer \
  --claim 'Good-Faith-Money=$10,000 deposited' \
  > /tmp/buyer.catf
```

### Go integration (recommended for applications)

At a high level:

1) Build a `catf.Document`
2) Render it canonically
3) Parse to get the canonical signing scope (`SignedBytes()`)
4) Compute the signature and render final bytes

Sketch:

```go
import (
  "xdao.co/catf/catf"
  "xdao.co/catf/keys"
)

// Pseudocode sketch: see packages in ./src for exact APIs.
doc := catf.Document{ /* Meta, Subject, Claims, Crypto */ }
pre, _ := catf.Render(doc)
parsed, _ := catf.Parse(pre)

// signature should be computed over the canonical signed scope
sig := keys.SignEd25519SHA256(parsed.SignedBytes(), priv)

doc.Crypto["Signature"] = sig
finalBytes, _ := catf.Render(doc)
```

Note: `catf.SignEd25519SHA256` (and related helpers) are deprecated; prefer the non-protocol utility helpers in `xdao.co/catf/keys`.

Crypto agility notes:

- Supported `Crypto` fields include `Signature-Alg` (`ed25519`, `dilithium3`) and `Hash-Alg` (`sha256`, `sha512`, `sha3-256`).
- For `Signature-Alg=dilithium3`, signatures are computed/verified over the digest bytes of `SignedBytes()`.

Operational guidance:

- Store the final CATF bytes exactly (they are canonical; do not add a trailing newline).
- Track the Attestation CID (`catf.Parse(finalBytes).CID()`) as the stable identifier.

Important behavior note:

- CATF is strict about canonical bytes. `catf.Parse` rejects any non-canonical input bytes (including CRLF line endings, UTF-8 BOM, or a trailing newline). Integrations should treat the exact CATF bytes as the artifact; do not “pretty print”, re-wrap, or otherwise rewrite them in transit.

---

## 7) Resolve (evaluate under policy)

Resolution can run:

- On-demand (API endpoint: “is this document resolved?”)
- As a job (index attestations, recompute resolutions)
- As part of a node (XDAO Node continuously evaluates policy state)

CLI:

```sh
./bin/xdao-catf resolve \
  --subject "$SUBJECT_CID" \
  --policy ./policy.tpdl \
  --att /tmp/a1.catf \
  --att /tmp/r1.catf
```

Resolver compliance mode (optional):

```sh
./bin/xdao-catf resolve \
  --mode strict \
  --subject "$SUBJECT_CID" \
  --policy ./policy.tpdl \
  --att /tmp/a1.catf
```

If you are producing a revised CROF and want to declare it supersedes a prior CROF, pass the prior CROF CID:

```sh
./bin/xdao-catf resolve \
  --subject "$SUBJECT_CID" \
  --policy ./policy.tpdl \
  --att /tmp/a1.catf \
  --supersedes-crof <PriorCROFCID>
```

### CROF supersession (what it is and how to use it)

CROF is evidence. A later resolver run may produce a revised CROF that is intended to supersede a prior CROF (for example: new attestations arrived, policy changed, or the resolver implementation was upgraded).

Supersession is explicit and CID-addressed:

- The new CROF includes `META: Supersedes-CROF-CID: <PriorCROFCID>`.
- The reference implementation provides `./bin/xdao-catf crof validate-supersession --new ... --old ...` to check minimal validity rules.

Go integration pattern:

```go
oldCID, err := crof.CID(oldCROFBytes)
if err != nil { /* old CROF must be canonical */ }

newCROFBytes := crof.Render(
  res,
  crof.PolicyCID(policyBytes),
  attestationCIDs,
  crof.RenderOptions{ResolverID: "your-resolver", SupersedesCROFCID: oldCID},
)

if err := crof.ValidateSupersession(newCROFBytes, oldCROFBytes); err != nil {
  /* invalid supersession relationship */
}
```

Go integration:

```go
res, err := resolver.ResolveWithOptions(attestationBytesList, policyBytes, subjectCID, resolver.Options{Mode: compliance.Permissive})
if err != nil { /* handle */ }

crofBytes := crof.Render(
  res,
  crof.PolicyCID(policyBytes),
  attestationCIDs,
  crof.RenderOptions{ResolverID: "your-resolver"},
)
```

Your application typically consumes:

- `res.State` (Resolved / Unresolved / Forked / Revoked)
- `res.Paths` (valid chains)
- `res.Forks` (competing heads)

In addition, the resolver now emits per-attestation evidence as `res.Verdicts`, which the CROF renderer records in the `VERDICTS` section. This is useful for auditing *why* an attestation was excluded (untrusted, revoked, parse-failed, etc.) without re-running the resolver.

Invalid / non-canonical attestation inputs:

- If an input attestation fails CATF parse/canonicalization, the resolver will still surface it deterministically as an `EXCLUSIONS` + `VERDICTS` entry with an empty CID, a stable `InputHash` (`sha256:<hex>`), and reason `CATF parse/canonicalization failed`.
- When rendering CROF, entries with an empty CID omit the `Attestation-CID: ...` line, but still include `Input-Hash: sha256:<hex>` (when available) plus the corresponding `Reason:` / `Excluded-Reason:` lines.
- CROF `INPUTS` may include both `Attestation-CID: ...` (valid CATF inputs) and `Input-Hash: sha256:<hex>` (invalid/non-CATF inputs). Canonical ordering is: all `Attestation-CID` lines first (sorted), then all `Input-Hash` lines (sorted).

The CROF `RESULT` section also records `Subject-CID` to bind the output to the subject being resolved.

Fork surfacing notes:

- Forks are never silently merged. If multiple trusted candidates can satisfy a `Quorum: 1` requirement for the same `(Type, Role)`, resolution will surface competing forks.

---

## 8) Naming (optional)

If you want stable human-readable identifiers (e.g. `contracts.realestate.123-main-st@final`):

- Create `Type=name-binding` attestations with `Name`, `Version`, `Points-To`
- Resolve with `resolve-name`

This is typically how a project builds a registry layer that maps names → subject CIDs.

---

## Integration checklist

An external project usually needs to ship:

- A **role registry** (constants) used by UI, policy generation, and attestation issuance
- A **policy generator** (TPDL templates + “who is trusted for what role”)
- A **subject canonicalization rule** (what bytes are hashed/published)
- A **key strategy** (KMS-lite for pilots, or existing signer infrastructure)
- A **storage layer** for:
  - subject bytes (optional IPFS)
  - attestations (object store / database / filesystem)
  - policies (versioned config)
- A **resolver runner** (on-demand, scheduled, or node service)

---

## Common pitfalls

- **CID mismatch**: if your subject serialization is not deterministic, different parties will hash different bytes.
- **Policy drift**: changing role names or trust mappings breaks resolution semantics.
- **Using `ipfs add` when you expect `doc-cid`**: `ipfs add` typically yields a different CID (UnixFS DAG), while this system’s `doc-cid` / `ipfs put` is a raw-block CID over exact bytes.
- **Shell `$` expansion**: if you embed dollar signs in claim values in bash, use single quotes (e.g. `'Good-Faith-Money=$10,000'`).
- **Assuming malformed attestations have a CID**: invalid/non-canonical CATF bytes are not assigned an “attestation CID”; they surface as deterministic exclusions/verdicts with an empty CID.
