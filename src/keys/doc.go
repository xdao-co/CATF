// Package keys provides key-related helpers used by the CATF reference implementation.
//
// API stability (GAP-07):
//
// Stable (SemVer-protected):
//   - Pure, deterministic primitives for issuer-key formatting and role-seed derivation.
//
// Experimental:
//   - Filesystem-backed key storage and convenience helpers (KeyStore and related functions).
//     These are local-first utilities and are not part of the long-term protocol contract.
package keys
