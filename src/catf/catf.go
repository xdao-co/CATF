// Package catf implements parsing and canonicalization for Canonical Attestation Text Format (CATF).
package catf

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"xdao.co/catf/cidutil"
)

// SectionOrder defines the canonical order of CATF sections.
var SectionOrder = []string{"META", "SUBJECT", "CLAIMS", "CRYPTO"}

// CATF represents a parsed CATF attestation.
type CATF struct {
	Sections map[string]Section
	Raw      []byte // Canonical bytes
	Signed   []byte // Bytes covered by signature (BEGIN..end of CLAIMS, inclusive)
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
	if !utf8.Valid(data) {
		return nil, errors.New("CATF must be valid UTF-8")
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		return nil, errors.New("trailing newline not allowed")
	}
	if !bytes.HasPrefix(data, []byte("-----BEGIN XDAO ATTESTATION-----")) {
		return nil, errors.New("missing CATF preamble")
	}
	if !bytes.HasSuffix(data, []byte(Postamble)) {
		return nil, errors.New("missing CATF postamble")
	}
	// Enforce UTF-8, LF, no BOM, no trailing whitespace
	if bytes.Contains(data, []byte("\r")) {
		return nil, errors.New("CR line endings not allowed")
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("BOM not allowed")
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
			return nil, errors.New("trailing whitespace forbidden")
		}
	}
	if !bytes.HasPrefix(data, []byte(Preamble+"\n")) && string(data) != Preamble {
		return nil, errors.New("CATF preamble must be on its own line")
	}

	// Parse sections with ordering and enforce blank-line separation.
	sections := make(map[string]Section)
	reader := bufio.NewReader(bytes.NewReader(data))
	lineNo := 0
	readLine := func() (string, error) {
		l, err := reader.ReadString('\n')
		if err == io.EOF {
			lineNo++
			return strings.TrimRight(l, "\n"), io.EOF
		}
		if err != nil {
			return "", err
		}
		lineNo++
		return strings.TrimRight(l, "\n"), nil
	}

	// First line must be preamble.
	first, err := readLine()
	if err != nil && err != io.EOF {
		return nil, err
	}
	if first != Preamble {
		return nil, errors.New("CATF preamble must be exact")
	}

	sectionIndex := -1
	var currSection string
	var currPairs map[string]string
	var currKeyOrder []string
	seenSection := map[string]bool{}
	seenAnySection := false
	claimsEndLineNo := -1
	afterSeparator := false

	flushSection := func() error {
		if currSection == "" {
			return nil
		}
		// Validate key order exactly matches lexicographic sort.
		sorted := append([]string(nil), currKeyOrder...)
		sort.Strings(sorted)
		if len(sorted) != len(currKeyOrder) {
			return errors.New("duplicate keys in section")
		}
		for i := range sorted {
			if sorted[i] != currKeyOrder[i] {
				return errors.New("keys not sorted lexicographically")
			}
		}
		sections[currSection] = Section{Name: currSection, Pairs: currPairs}
		if currSection == "CLAIMS" {
			claimsEndLineNo = lineNo
		}
		currSection = ""
		currPairs = nil
		currKeyOrder = nil
		return nil
	}

	for {
		line, rerr := readLine()
		if rerr != nil && rerr != io.EOF {
			return nil, rerr
		}

		if line == Postamble {
			if afterSeparator {
				return nil, errors.New("unexpected blank line before postamble")
			}
			if err := flushSection(); err != nil {
				return nil, err
			}
			break
		}

		if isSectionHeader(line) {
			seenAnySection = true
			if currSection != "" {
				return nil, errors.New("missing blank line between sections")
			}
			if seenSection[line] {
				return nil, errors.New("duplicate section")
			}
			if err := flushSection(); err != nil {
				return nil, err
			}
			sectionIndex++
			if sectionIndex >= len(SectionOrder) || SectionOrder[sectionIndex] != line {
				return nil, errors.New("sections missing or out of order")
			}
			if sectionIndex == 0 {
				if afterSeparator {
					return nil, errors.New("blank line before first section not allowed")
				}
			} else {
				if !afterSeparator {
					return nil, errors.New("missing blank line between sections")
				}
			}
			afterSeparator = false
			seenSection[line] = true
			currSection = line
			currPairs = make(map[string]string)
			continue
		}

		if !seenAnySection {
			// Canonical CATF has META immediately after preamble.
			return nil, errors.New("unexpected content before first section")
		}

		if line == "" {
			// Canonical CATF requires exactly one blank line between sections.
			if currSection == "" {
				return nil, errors.New("blank line outside section not allowed")
			}
			if currSection == "CRYPTO" {
				return nil, errors.New("blank line after CRYPTO section not allowed")
			}
			if afterSeparator {
				return nil, errors.New("multiple blank lines between sections not allowed")
			}
			if err := flushSection(); err != nil {
				return nil, err
			}
			afterSeparator = true
			continue
		}

		if currSection == "" {
			return nil, errors.New("content outside section")
		}
		if afterSeparator {
			return nil, errors.New("expected section header after blank line")
		}
		if !strings.Contains(line, ": ") {
			return nil, errors.New("invalid key-value formatting")
		}
		kv := strings.SplitN(line, ": ", 2)
		key, val := kv[0], kv[1]
		if key == "" {
			return nil, errors.New("empty key")
		}
		if !isASCII(key) {
			return nil, errors.New("non-ASCII key")
		}
		if strings.HasPrefix(val, " ") {
			return nil, errors.New("value must not start with a space")
		}
		if _, exists := currPairs[key]; exists {
			return nil, errors.New("duplicate key in section")
		}
		currPairs[key] = val
		currKeyOrder = append(currKeyOrder, key)

		if rerr == io.EOF {
			return nil, errors.New("missing CATF postamble")
		}
	}

	// Ensure all sections exist.
	for _, s := range SectionOrder {
		if !seenSection[s] {
			return nil, errors.New("sections missing or out of order")
		}
	}
	if claimsEndLineNo < 0 {
		return nil, errors.New("missing CLAIMS section")
	}
	// Check key order and uniqueness
	for _, sec := range sections {
		var keys []string
		for k := range sec.Pairs {
			if !isASCII(k) {
				return nil, errors.New("non-ASCII key")
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		_ = keys
	}

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
		return nil, errors.New("non-canonical CATF")
	}

	// Compute signed bytes: BEGIN line through end of CLAIMS section, inclusive.
	// Canonical Render() emits exactly one blank line between CLAIMS and CRYPTO.
	marker := []byte("\nCRYPTO\n")
	idx := bytes.Index(canonical, marker)
	if idx < 0 {
		return nil, errors.New("cannot determine signature scope")
	}
	signedEnd := idx + 1
	signed := canonical[:signedEnd]
	return &CATF{Sections: sections, Raw: canonical, Signed: signed}, nil
}

// CID returns a deterministic local content identifier for the canonical CATF bytes.
// This is an IPFS-compatible CIDv1 (raw + sha2-256) derived from canonical bytes.
func (c *CATF) CID() string {
	return cidutil.CIDv1RawSHA256(c.Raw)
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
