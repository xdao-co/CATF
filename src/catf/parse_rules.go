package catf

import (
	"bytes"
	"unicode/utf8"
)

type parseRule struct {
	id    string
	kind  Kind
	apply func([]byte) error
}

func applyParseRules(input []byte, rules []parseRule) error {
	for _, r := range rules {
		if r.apply == nil {
			return newError(KindInternal, "CATF-INTERNAL-010", "nil parse rule")
		}
		if err := r.apply(input); err != nil {
			// If the rule already returned a structured error, preserve it.
			return err
		}
	}
	return nil
}

func parseRulesV1() []parseRule {
	return []parseRule{
		{
			id:   "CATF-STR-001",
			kind: KindParse,
			apply: func(b []byte) error {
				if !utf8.Valid(b) {
					return newError(KindParse, "CATF-STR-001", "CATF must be valid UTF-8")
				}
				return nil
			},
		},
		{
			id:   "CATF-CANON-001",
			kind: KindCanonical,
			apply: func(b []byte) error {
				if bytes.Contains(b, []byte("\r")) {
					return newError(KindCanonical, "CATF-CANON-001", "CR line endings not allowed")
				}
				return nil
			},
		},
		{
			id:   "CATF-CANON-002",
			kind: KindCanonical,
			apply: func(b []byte) error {
				if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
					return newError(KindCanonical, "CATF-CANON-002", "BOM not allowed")
				}
				return nil
			},
		},
		{
			id:   "CATF-CANON-003",
			kind: KindCanonical,
			apply: func(b []byte) error {
				if len(b) > 0 && b[len(b)-1] == '\n' {
					return newError(KindCanonical, "CATF-CANON-003", "trailing newline not allowed")
				}
				return nil
			},
		},
		{
			id:   "CATF-STR-010",
			kind: KindParse,
			apply: func(b []byte) error {
				if !bytes.HasPrefix(b, []byte(Preamble)) {
					return newError(KindParse, "CATF-STR-010", "missing CATF preamble")
				}
				if !bytes.HasSuffix(b, []byte(Postamble)) {
					return newError(KindParse, "CATF-STR-010", "missing CATF postamble")
				}
				return nil
			},
		},
		{
			id:   "CATF-STR-030",
			kind: KindParse,
			apply: func(b []byte) error {
				for _, line := range bytes.Split(b, []byte("\n")) {
					if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
						return newError(KindParse, "CATF-STR-030", "trailing whitespace forbidden")
					}
				}
				return nil
			},
		},
		{
			id:   "CATF-STR-010",
			kind: KindParse,
			apply: func(b []byte) error {
				// Preamble must appear as the first full line.
				if !bytes.HasPrefix(b, []byte(Preamble+"\n")) && string(b) != Preamble {
					return newError(KindParse, "CATF-STR-010", "CATF preamble must be on its own line")
				}
				return nil
			},
		},
	}
}
