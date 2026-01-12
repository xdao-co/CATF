package catf

// CanonicalizeCATF is the single mandatory canonicalization choke point for CATF.
//
// ReferenceDesign.md §2.4 defines byte-level canonicalization rules that are
// mandatory for deterministic hashing and signing. This function enforces those
// rules by rejecting any non-canonical input.
//
// All CATF hashing, signing, CID derivation, and resolver ingestion MUST pass
// through CanonicalizeCATF.
func CanonicalizeCATF(input []byte) ([]byte, error) {
	c, err := Parse(input)
	if err != nil {
		return nil, err
	}
	// Return a copy to prevent callers from mutating internal slices.
	return append([]byte(nil), c.Raw...), nil
}
