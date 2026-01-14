package catf

// NormalizeCATF canonicalizes a CATF document.
//
// EXPERIMENTAL: This API may evolve.
//
// GAP-01 enforcement: CATF canonicalization is not an auto-fix mechanism.
// Non-canonical inputs MUST be rejected loudly. For the single authoritative
// canonicalization choke point, use CanonicalizeCATF.
func NormalizeCATF(input []byte) ([]byte, error) {
	return CanonicalizeCATF(input)
}
