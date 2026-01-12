package compliance

// ComplianceMode selects how aggressively the library rejects ambiguity.
//
// Strict mode prefers explicit failure over silent acceptance.
// Permissive mode attempts to produce a resolution while surfacing exclusions
// and forks explicitly.
//
// ReferenceDesign.md guardrails emphasize determinism and explicitness.
type ComplianceMode int

const (
	Permissive ComplianceMode = iota
	Strict
)
