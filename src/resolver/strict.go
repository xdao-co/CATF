package resolver

import "xdao.co/catf/compliance"

// ResolveStrict runs Resolve and enforces strict compliance semantics.
//
// Strict compliance mode is intentionally rejecting:
// - Any non-Resolved state (Unresolved, Revoked, Forked)
// - Any exclusions (invalid/untrusted inputs)
//
// This is a convenience entry point for callers that want "no ambiguity" behavior
// while still keeping the base resolver behavior available.
func ResolveStrict(attestationBytes [][]byte, policyBytes []byte, subjectCID string) (*Resolution, error) {
	return ResolveWithOptions(attestationBytes, policyBytes, subjectCID, Options{Mode: compliance.Strict})
}

// ResolveNameStrict runs ResolveName and enforces strict compliance semantics.
func ResolveNameStrict(attestationBytes [][]byte, policyBytes []byte, name, version string) (*NameResolution, error) {
	return ResolveNameWithOptions(attestationBytes, policyBytes, name, version, Options{Mode: compliance.Strict})
}
