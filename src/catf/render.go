package catf

import (
	"errors"
	"sort"
	"strings"
)

// Document is a convenient in-memory representation for producing canonical CATF.
// Rendered bytes are always canonical (section order, key order, spacing, and blank lines).
//
// NOTE: This does not perform semantic validation; use ValidateCoreClaims on parsed output.
type Document struct {
	Meta    map[string]string
	Subject map[string]string
	Claims  map[string]string
	Crypto  map[string]string
}

// Render produces canonical CATF bytes from a Document.
func Render(doc Document) ([]byte, error) {
	sections := []struct {
		name  string
		pairs map[string]string
	}{
		{name: "META", pairs: doc.Meta},
		{name: "SUBJECT", pairs: doc.Subject},
		{name: "CLAIMS", pairs: doc.Claims},
		{name: "CRYPTO", pairs: doc.Crypto},
	}

	var sb strings.Builder
	sb.WriteString(Preamble)
	sb.WriteString("\n")

	for i, sec := range sections {
		sb.WriteString(sec.name)
		sb.WriteString("\n")

		keys := make([]string, 0, len(sec.pairs))
		for k := range sec.pairs {
			if k == "" {
				return nil, errors.New("empty key")
			}
			if !isASCII(k) {
				return nil, errors.New("non-ASCII key")
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := sec.pairs[k]
			if v == "" {
				return nil, errors.New("empty value")
			}
			if strings.HasPrefix(v, " ") {
				return nil, errors.New("value must not start with a space")
			}
			if strings.Contains(v, "\n") || strings.Contains(v, "\r") {
				return nil, errors.New("value must not contain newlines")
			}
			if strings.HasSuffix(v, " ") || strings.HasSuffix(v, "\t") {
				return nil, errors.New("trailing whitespace forbidden")
			}
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}

		if i != len(sections)-1 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString(Postamble)
	return []byte(sb.String()), nil
}
