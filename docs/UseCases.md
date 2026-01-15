xDAO CLI Use Cases – End-to-End Workflows

Runnable demos:

- For scripts you can run immediately, see `docs/examples/README.md`.
- For a full storage walkthrough that stores subject/policy/attestations/CROF in a CAS (localfs + optional IPFS), see `docs/Walkthrough_Storage.md`.

Note on Keys: These use cases assume no external PKI or wallet. xDAO provides a minimal, local Key Management Subsystem (KMS-lite) to generate, store, derive, and rotate keys deterministically for users who do not already have a mechanism.

All key material is local-first, offline-capable, and never requires a network.

This document defines four complete, end-to-end CLI use cases for exercising the xDAO CATF v1.0 system. Each use case is designed to validate canonical evidence handling, trust policy evaluation, deterministic resolution, and CROF output.

These use cases are intentionally procedural and explicit so they can later be converted into:
 • shell scripts
 • Makefile targets
 • automated compliance tests

⸻

Key Management Subsystem (KMS-lite)

xDAO includes a minimal key management subsystem intended for:
 • developers
 • CLI users
 • offline or air-gapped environments

It is not a global identity system and intentionally avoids accounts or recovery services.

Key Types
 • Root Key: primary identity key (long-lived)
 • Role Key: derived sub-key scoped to a role
 • Session Key (optional): short-lived signing key

All keys are Ed25519.

⸻

Create a Root Key

xdao-catf key init --name alice

Output:

Created root key: ed25519:ALICE_ROOT_KEY
Stored at: ~/.xdao/keys/alice/root.key

⸻

Derive a Role Key

xdao-catf key derive \
  --from alice \
  --role author

Output:

Created role key: ed25519:ALICE_AUTHOR_KEY

Role keys are deterministically derived and may be revoked or rotated independently.

⸻

List Keys

xdao-catf key list

⸻

Export Public Key

xdao-catf key export --name alice --role author

⸻

Security Notes
 • Private keys never leave local storage
 • Keys may be backed up manually
 • Loss of keys = loss of authority (by design)

⸻

Use Case 1 — Document Publishing Workflow

AUTHOR → (optional REVIEW) → READ

Goal

Demonstrate:
 • document publishing
 • optional approval workflow
 • distinction between published vs canonicalized
 • reader access without trust authority

⸻

Roles
 • AUTHOR — creates and asserts authorship
 • REVIEWER — optionally approves (gatekeeping role)
 • READER — consumes resolved output, no trust authority

⸻

Scenario A — Reviewed & Approved Document

Step 1 — Author publishes document

xdao doc add ./whitepaper.md

# returns CID: bafy-doc-001

Step 2 — Author asserts authorship

xdao attest authorship \
  --subject bafy-doc-001 \
  --role author \
  --key AUTHOR_KEY

# returns CID: bafy-attest-A1

Step 3 — Reviewer approves document

xdao attest approval \
  --subject bafy-doc-001 \
  --role reviewer \
  --key REVIEWER_KEY

# returns CID: bafy-attest-R1

Step 4 — Trust Policy (Reviewer required)

TRUST
Key: ed25519:AUTHOR_KEY
Role: author

Key: ed25519:REVIEWER_KEY
Role: reviewer

RULES
Require:
  Type: authorship
  Role: author

Require:
  Type: approval
  Role: reviewer

Step 5 — Resolve

xdao resolve \
  --policy policy.tpdl \
  --input bafy-attest-A1 bafy-attest-R1

Expected CROF
 • State: Resolved
 • Canonical: Yes
 • Paths: 1
 • Forks: 0

⸻

Scenario B — Reviewer Optional

Policy change only

RULES
Require:
  Type: authorship
  Role: author

Resolution succeeds without reviewer approval.

⸻

Scenario C — NOT_APPROVED (Rejected or Absent Review)

Reviewer explicitly revokes

xdao attest revocation \
  --target bafy-attest-A1 \
  --key REVIEWER_KEY

Expected CROF
 • State: Unresolved
 • Canonical: No
 • Reason: Insufficient trusted approvals

Key principle: Not approved ≠ erased. Not approved ≠ invalid. Not approved = not canonicalized.

⸻

Use Case 2 — Real Estate: Good Faith Money Transaction

Goal

Demonstrate:
 • multi-party approvals
 • money as evidence, not execution
 • conditional trust resolution
 • revocation and dispute handling

⸻

Roles
 • BUYER
 • SELLER
 • ESCROW_AGENT
 • NOTARY (optional, jurisdictional)

⸻

Step 1 — Purchase agreement stored

xdao doc add ./purchase-agreement.pdf

# CID: bafy-doc-REA-001

⸻

Step 2 — Buyer deposits Good Faith Money

xdao attest approval \
  --subject bafy-doc-REA-001 \
  --role buyer \
  --claim "Good-Faith-Money: $10,000 deposited" \
  --key BUYER_KEY

⸻

Step 3 — Seller acknowledges receipt

xdao attest approval \
  --subject bafy-doc-REA-001 \
  --role seller \
  --key SELLER_KEY

⸻

Step 4 — Escrow agent attests holding funds

xdao attest approval \
  --subject bafy-doc-REA-001 \
  --role escrow-agent \
  --claim "Funds held in escrow account #XYZ" \
  --key ESCROW_KEY

⸻

Step 5 — Trust Policy

TRUST
Key: ed25519:BUYER_KEY
Role: buyer

Key: ed25519:SELLER_KEY
Role: seller

Key: ed25519:ESCROW_KEY
Role: escrow-agent

RULES
Require:
  Type: approval
  Role: buyer

Require:
  Type: approval
  Role: seller

Require:
  Type: approval
  Role: escrow-agent

⸻

Step 6 — Resolve

xdao resolve \
  --policy realestate.tpdl \
  --input bafy-attest-B1 bafy-attest-S1 bafy-attest-E1

Expected CROF
 • State: Resolved
 • Confidence: High
 • Canonical: Yes

⸻

Failure Case — Buyer Withdraws

xdao attest revocation \
  --target bafy-attest-B1 \
  --key BUYER_KEY

Expected CROF
 • State: Revoked
 • Canonical: No
 • Status: Disputed

Funds never move. Evidence does.

⸻

Use Case 3 — Scientific Paper with AI Peer Review

Goal

Demonstrate:
 • non-human actors as first-class attestors
 • quorum-based peer review
 • trust without centralized authority
 • reproducibility

⸻

Roles
 • AUTHOR
 • AI_REVIEWER
 • EDITOR (optional)

⸻

Step 1 — Paper stored

xdao doc add ./paper.pdf

# CID: bafy-doc-SCI-001

⸻

Step 2 — Author asserts authorship

xdao attest authorship \
  --subject bafy-doc-SCI-001 \
  --role author \
  --key AUTHOR_KEY

⸻

Step 3 — AI peer reviews

xdao attest approval \
  --subject bafy-doc-SCI-001 \
  --role ai-reviewer \
  --claim "Methodology sound; reproducible" \
  --key AI_MODEL_A_KEY

xdao attest approval \
  --subject bafy-doc-SCI-001 \
  --role ai-reviewer \
  --claim "Statistical analysis valid" \
  --key AI_MODEL_B_KEY

⸻

Step 4 — Trust Policy (AI quorum)

TRUST
Key: ed25519:AUTHOR_KEY
Role: author

Key: ed25519:AI_MODEL_A_KEY
Role: ai-reviewer

Key: ed25519:AI_MODEL_B_KEY
Role: ai-reviewer

RULES
Require:
  Type: authorship
  Role: author

Require:
  Type: approval
  Role: ai-reviewer
  Quorum: 2

⸻

Step 5 — Resolve

xdao resolve \
  --policy science.tpdl \
  --input bafy-attest-A1 bafy-attest-AI1 bafy-attest-AI2

Expected CROF
 • State: Resolved
 • Confidence: High
 • Canonical: Yes

⸻

Fork Case — Conflicting AI Reviews

If one AI approves and another rejects:

Expected CROF
 • State: Forked
 • Canonical: No

A human editor MAY later attest supersession.

⸻

Use Case 4 — KMS-lite: Public/Private Key Management

Goal

Demonstrate:
 • local-first Ed25519 key generation and deterministic derivation
 • exporting public keys for TPDL trust policies
 • keys as first-class evidence (via attestations about key material)
 • key rotation and revocation as explicit evidence

⸻

Step 1 — Create a root identity key

xdao-catf key init --name alice

Output:

Created root key: ed25519:ALICE_ROOT_KEY
Stored at: ~/.xdao/keys/alice/root.key

⸻

Step 2 — Derive a signing role key

xdao-catf key derive --from alice --role signing

Output:

Created role key: ed25519:ALICE_SIGNING_KEY
Stored at: ~/.xdao/keys/alice/roles/signing.key

⸻

Step 3 — Export public keys (for policies)

xdao-catf key export --name alice > alice-root.pub
xdao-catf key export --name alice --role signing > alice-signing.pub

⸻

Step 4 — Treat the public key as a subject (content-addressed)

Minimum CLI note: the reference system may include `doc add`. The minimum CLI provides `doc-cid` to compute a stable subject CID.

xdao-catf doc-cid alice-signing.pub

# Subject CID: bafy-doc-key-signing

⸻

Step 5 — Attest to the key's provenance and purpose

Authorship/provenance (root key vouches for the key document):

xdao-catf attest \
  --subject bafy-doc-key-signing \
  --description "Alice signing key (public)" \
  --signer alice \
  --type authorship \
  --role identity \
  --claim "Comment=Public signing key for Alice" \
  > a1_key_provenance.catf

Purpose/authorization (signing role key asserts intent):

xdao-catf attest \
  --subject bafy-doc-key-signing \
  --description "Alice signing key (public)" \
  --signer alice \
  --signer-role signing \
  --type approval \
  --role signing \
  --claim "Comment=Authorized for document signing" \
  > a2_key_authorization.catf

⸻

Step 6 — Define trust policy for key usage

-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1
Description: Trust policy for Alice signing keys

TRUST
Key: ed25519:ALICE_ROOT_KEY
Role: identity

Key: ed25519:ALICE_SIGNING_KEY
Role: signing

RULES
Require:
  Type: authorship
  Role: identity

Require:
  Type: approval
  Role: signing
-----END XDAO TRUST POLICY-----

⸻

Step 7 — Resolve and verify canonical status

xdao-catf resolve --subject bafy-doc-key-signing --policy key-trust.tpdl --att a1_key_provenance.catf --att a2_key_authorization.catf

Expected CROF:
 • State: Resolved
 • Canonical: Yes

⸻

Rotation and revocation (evidence-based)

Rotation is modeled as creating a new key document and producing a `Type=supersedes` attestation that links to the prior key attestation CID (attestations are what the resolver chains).

Revocation is modeled with `Type=revocation` targeting an attestation CID via `Target-Attestation`.

Summary

This use case demonstrates keys as first-class evidence that can be archived, resolved, superseded, and revoked under explicit policy.

Summary

These four use cases collectively exercise:
 • optional and mandatory trust
 • multi-party coordination
 • revocation and dispute
 • forks as first-class outcomes
 • human and non-human authority
 • offline and deterministic resolution
 • key generation, derivation, and key-as-evidence

They are suitable as the basis for CLI demos, test vectors, and compliance testing for xDAO CATF v1.0.
