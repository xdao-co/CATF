# CATF Bundle Format (Draft)

**Status:** Draft specification (no implementation yet)

## 1) Purpose

A *bundle* is an offline, deterministic transport container for content-addressed bytes.
It is designed to:

- Move a complete set of required bytes between systems without relying on network availability.
- Preserve the CATF/CROF CID contract: bytes are authoritative; transports are not.
- Be reproducible: given the same set of blocks, the bundle bytes are stable.

This enables “civilization‑grade” distribution (e.g., air‑gapped transfer, archival, escrow).

## 2) Core principles (non-negotiable)

- **CID-keyed objects:** Every payload is keyed by CID. Filenames and indexes are advisory.
- **No wall-clock:** No timestamps, mtimes, random IDs, or nondeterministic ordering.
- **Verification first:** Consumers MUST validate bytes against the expected CID.
- **Immutability:** Bundles are write-once artifacts; new content produces a new bundle.

## 3) Content model

A bundle carries a set of *blocks*:

- Each block is raw bytes.
- The CID for each block MUST be computed using the CATF contract: **CIDv1 + raw codec + sha2-256**.
  - In code, this corresponds to `cidutil.CIDv1RawSHA256CID`.

Optionally, a bundle may also carry *labels* (human hints) that map names to CIDs.
Labels are not authoritative.

## 4) Wire format

A bundle is a TAR archive with strict determinism rules.

### 4.1 Archive type

- Container: `tar` (USTAR or PAX)
- Compression: **none** (optional external compression is allowed but MUST NOT be part of the canonical bundle bytes)

Rationale:

- TAR is widely supported and simple.
- Determinism is achievable with explicit rules.

### 4.2 TAR determinism rules

When writing the TAR:

- Entries MUST be emitted in lexicographic order by entry path (byte-wise).
- All entries MUST have:
  - uid/gid: `0`
  - uname/gname: empty
  - mode: `0644` for files, `0755` for directories (or fixed, but consistent)
  - mtime: `0`
- No extended attributes that encode timestamps or platform metadata.

Consumers MUST ignore TAR metadata beyond paths and file contents.

## 5) Path layout

All paths use `/` separators.

### 5.1 Blocks

Blocks live under:

- `blocks/<cid>`

Where `<cid>` is the canonical CID string.

Example:

- `blocks/bafy...`

The file content is the raw bytes of that block.

### 5.2 Optional index

A bundle MAY include an index at:

- `index.json`

The index is advisory metadata.

Suggested schema (stable, but still draft):

```json
{
  "version": 1,
  "cidCodec": "raw",
  "multihash": "sha2-256",
  "blocks": [
    {"cid": "bafy...", "size": 1234}
  ],
  "labels": {
    "subject": "bafy...",
    "policy": "bafy...",
    "attestations/0": "bafy..."
  }
}
```

If present, `index.json` MUST be UTF-8 and MUST be canonical JSON:

- No insignificant whitespace
- Object keys sorted lexicographically
- Arrays in deterministic order

(If/when we implement this, we should reuse the same canonical JSON routine used elsewhere in CATF.)

### 5.3 Optional manifests

A bundle MAY include additional manifests (e.g., a CROF snapshot) under:

- `manifests/<name>`

Manifests are also non-authoritative hints.
If a manifest references a CID, the referenced bytes MUST still be verified.

## 6) Import/export behavior

### 6.1 Export

Given a set of CIDs and a CAS:

- Resolve each CID to bytes via CAS.
- Validate bytes hash to that CID.
- Write `blocks/<cid>` entries.
- Optionally write `index.json`.

### 6.2 Import

Given a bundle and a target CAS:

- For each `blocks/<cid>` entry:
  - Read bytes
  - Validate CID matches content
  - `Put(bytes)` into CAS
  - Ensure returned CID matches expected

Import MUST fail (hard) on:

- CID mismatch
- Duplicate paths with different bytes
- Invalid CID strings

## 7) Security considerations

- Bundles do not provide confidentiality; use external encryption if needed.
- Bundles do not assert trust; they only carry bytes.
- All consumers MUST treat labels/manifests as untrusted hints.

## 8) Compatibility note

This format is intentionally simple and avoids requiring an IPFS daemon or network client.
If in the future we choose to support standardized content-addressed archives (e.g., CAR), that can be introduced as an *additional* optional bundle codec, but the verification rules remain identical.
