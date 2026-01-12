package catf

import (
	"bytes"
	"errors"
)

// NormalizeCATF canonicalizes a CATF document by parsing into the section model
// and re-rendering under the canonical rendering rules.
//
// EXPERIMENTAL: This API may evolve. It is intended to help build
// representation-independent tooling where canonicalization is a pure function
// over the (section,key,value) model, rather than being entangled with Parse.
//
// Unlike Parse(), NormalizeCATF tolerates some non-canonical byte-level forms
// (currently: optional UTF-8 BOM, CRLF line endings, and trailing newlines) and
// produces canonical output bytes.
func NormalizeCATF(input []byte) ([]byte, error) {
	b := input

	// Tolerate a UTF-8 BOM by removing it.
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		b = b[3:]
	}

	// Tolerate CRLF by normalizing to LF; reject bare CR.
	if bytes.Contains(b, []byte("\r")) {
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if bytes.Contains(b, []byte("\r")) {
			return nil, newError(KindCanonical, "CATF-CANON-001", "CR line endings not allowed")
		}
	}

	// Tolerate trailing newlines by trimming them.
	for len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}

	// Validate the remaining byte-level invariants that we still require.
	if err := applyParseRules(b, parseRulesV1()); err != nil {
		return nil, err
	}

	parsed, err := parseSectionsModelV1(b)
	if err != nil {
		return nil, err
	}
	sections := parsed.sections

	doc := Document{
		Meta:    sections["META"].Pairs,
		Subject: sections["SUBJECT"].Pairs,
		Claims:  sections["CLAIMS"].Pairs,
		Crypto:  sections["CRYPTO"].Pairs,
	}

	canonical, rerr := Render(doc)
	if rerr != nil {
		var e *Error
		if errors.As(rerr, &e) {
			return nil, rerr
		}
		return nil, wrapError(KindRender, "CATF-RENDER-001", "render failure", rerr)
	}

	// Defensive: ensure output is strict-canonical according to Parse.
	if _, perr := Parse(canonical); perr != nil {
		return nil, perr
	}

	return canonical, nil
}
