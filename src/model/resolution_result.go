package model

import "github.com/ipfs/go-cid"

// ResolutionResult is a compact, Go-friendly view of resolver output.
//
// It is intended for integrations that want the resolved evidence (CROF) plus the
// high-signal, policy-facing outputs without consuming the full ResolverResponse DTO.
//
// Notes:
// - CROF is the canonical resolver output bytes.
// - CROFCID is the CID bound to CROF.
// - Verdicts are policy verdicts (TPDL Require blocks), not per-attestation verdicts.
// - Forks and Exclusions mirror the resolver outcomes surfaced in CROF.
//
// This type is public-facing but is not the JSON boundary DTO (see ResolverResponse).
type ResolutionResult struct {
	CROF       []byte
	CROFCID    cid.Cid
	Verdicts   []PolicyVerdict
	Forks      []Fork
	Exclusions []Exclusion
}
