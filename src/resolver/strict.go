package resolver

import "fmt"

// ResolveStrict runs Resolve and enforces strict compliance semantics.
//
// Strict compliance mode is intentionally rejecting:
// - Any non-Resolved state (Unresolved, Revoked, Forked)
// - Any exclusions (invalid/untrusted inputs)
//
// This is a convenience entry point for callers that want "no ambiguity" behavior
// while still keeping the base resolver behavior available.
func ResolveStrict(attestationBytes [][]byte, policyBytes []byte, subjectCID string) (*Resolution, error) {
	res, err := Resolve(attestationBytes, policyBytes, subjectCID)
	if err != nil {
		return nil, err
	}
	if len(res.Exclusions) > 0 {
		return nil, fmt.Errorf("strict mode: exclusions present (%d)", len(res.Exclusions))
	}
	if res.State != StateResolved {
		return nil, fmt.Errorf("strict mode: expected StateResolved, got %s", res.State)
	}
	return res, nil
}

// ResolveNameStrict runs ResolveName and enforces strict compliance semantics.
func ResolveNameStrict(attestationBytes [][]byte, policyBytes []byte, name, version string) (*NameResolution, error) {
	res, err := ResolveName(attestationBytes, policyBytes, name, version)
	if err != nil {
		return nil, err
	}
	if len(res.Exclusions) > 0 {
		return nil, fmt.Errorf("strict mode: exclusions present (%d)", len(res.Exclusions))
	}
	if res.State != StateResolved {
		return nil, fmt.Errorf("strict mode: expected StateResolved, got %s", res.State)
	}
	return res, nil
}
