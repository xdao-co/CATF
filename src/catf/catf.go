// Package catf implements parsing and canonicalization for Canonical Attestation Text Format (CATF).
package catf

import (
	"bytes"
	"errors"

	"xdao.co/catf/cidutil"
)

// SectionOrder defines the canonical order of CATF sections.
var SectionOrder = []string{"META", "SUBJECT", "CLAIMS", "CRYPTO"}

// CATF represents a parsed CATF attestation.
type CATF struct {
	Sections map[string]Section
	raw      []byte // Canonical bytes (immutable via API)
	signed   []byte // Bytes covered by signature (BEGIN..end of CLAIMS, inclusive)
}

type Section struct {
	Name  string
	Pairs map[string]string // Key-value pairs, sorted lexicographically
}

const (
	Preamble  = "-----BEGIN XDAO ATTESTATION-----"
	Postamble = "-----END XDAO ATTESTATION-----"
)

// Parse parses a CATF document and enforces the v1 canonical serialization rules.
// Non-canonical inputs are rejected.
func Parse(data []byte) (*CATF, error) {
	if err := applyParseRules(data, parseRulesV1()); err != nil {
		return nil, err
	}

	parsed, err := parseSectionsV1(data)
	if err != nil {
		return nil, err
	}
	sections := parsed.sections

	// Enforce full canonical byte identity by re-rendering and comparing.
	// This makes Parse() strictly reject any non-canonical inputs.
	doc := Document{
		Meta:    sections["META"].Pairs,
		Subject: sections["SUBJECT"].Pairs,
		Claims:  sections["CLAIMS"].Pairs,
		Crypto:  sections["CRYPTO"].Pairs,
	}
	canonical, rerr := Render(doc)
	if rerr != nil {
		return nil, rerr
	}
	if !bytes.Equal(data, canonical) {
		return nil, newError(KindCanonical, "CATF-CANON-030", "non-canonical CATF")
	}

	// Compute signed bytes: BEGIN line through end of CLAIMS section, inclusive.
	// Canonical Render() emits exactly one blank line between CLAIMS and CRYPTO.
	signedScope, err := signedScopeFromCanonical(canonical)
	if err != nil {
		return nil, err
	}
	// Store independent backing arrays so callers cannot mutate raw by mutating signed.
	rawCopy := append([]byte(nil), canonical...)
	signedCopy := append([]byte(nil), signedScope...)
	return &CATF{Sections: sections, raw: rawCopy, signed: signedCopy}, nil
}

// CanonicalBytes returns a copy of the canonical CATF bytes.
// The returned slice is safe to mutate by the caller.
func (c *CATF) CanonicalBytes() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.raw...)
}

// SignedBytes returns a copy of the bytes covered by the CATF signature.
// The returned slice is safe to mutate by the caller.
func (c *CATF) SignedBytes() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.signed...)
}

// CID returns a deterministic local content identifier for the canonical CATF bytes.
// This is an IPFS-compatible CIDv1 (raw + sha2-256) derived from canonical bytes.
//
// For protocol safety, CID derivation MUST only be computed over canonical CATF.
// If the receiver does not contain canonical CATF bytes, an error is returned.
func (c *CATF) CID() (string, error) {
	if c == nil {
		return "", errors.New("nil CATF")
	}
	if _, err := Parse(c.raw); err != nil {
		return "", err
	}
	return cidutil.CIDv1RawSHA256(c.raw), nil
}

func signedScopeFromCanonical(canonical []byte) ([]byte, error) {
	marker := []byte("\nCRYPTO\n")
	idx := bytes.Index(canonical, marker)
	if idx < 0 {
		return nil, errors.New("cannot determine signature scope")
	}
	signedEnd := idx + 1
	return canonical[:signedEnd], nil
}

func (c *CATF) SubjectCID() string {
	if sec, ok := c.Sections["SUBJECT"]; ok {
		return sec.Pairs["CID"]
	}
	return ""
}

func (c *CATF) ClaimType() string {
	if sec, ok := c.Sections["CLAIMS"]; ok {
		return sec.Pairs["Type"]
	}
	return ""
}

func (c *CATF) IssuerKey() string {
	if sec, ok := c.Sections["CRYPTO"]; ok {
		return sec.Pairs["Issuer-Key"]
	}
	return ""
}

func isSectionHeader(line string) bool {
	for _, s := range SectionOrder {
		if line == s {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
