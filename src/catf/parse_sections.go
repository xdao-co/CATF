package catf

import (
	"bufio"
	"bytes"
	"io"
	"sort"
	"strings"
)

type parsedSections struct {
	sections        map[string]Section
	claimsEndLineNo int
}

func parseSectionsV1(data []byte) (*parsedSections, error) {
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
			return "", wrapError(KindParse, "CATF-STR-999", "read failure", err)
		}
		lineNo++
		return strings.TrimRight(l, "\n"), nil
	}

	first, err := readLine()
	if err != nil && err != io.EOF {
		return nil, err
	}
	if first != Preamble {
		return nil, newError(KindParse, "CATF-STR-010", "CATF preamble must be exact")
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
		// CATF-CANON-020: keys must be sorted lexicographically.
		sorted := append([]string(nil), currKeyOrder...)
		sort.Strings(sorted)
		if len(sorted) != len(currKeyOrder) {
			return newError(KindParse, "CATF-STR-030", "duplicate keys in section")
		}
		for i := range sorted {
			if sorted[i] != currKeyOrder[i] {
				return newError(KindCanonical, "CATF-CANON-020", "keys not sorted lexicographically")
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
				return nil, newError(KindParse, "CATF-CANON-010", "unexpected blank line before postamble")
			}
			if err := flushSection(); err != nil {
				return nil, err
			}
			break
		}

		if isSectionHeader(line) {
			seenAnySection = true
			if currSection != "" {
				return nil, newError(KindParse, "CATF-CANON-010", "missing blank line between sections")
			}
			if seenSection[line] {
				return nil, newError(KindParse, "CATF-STR-020", "duplicate section")
			}
			if err := flushSection(); err != nil {
				return nil, err
			}
			sectionIndex++
			if sectionIndex >= len(SectionOrder) || SectionOrder[sectionIndex] != line {
				return nil, newError(KindParse, "CATF-STR-020", "sections missing or out of order")
			}
			if sectionIndex == 0 {
				if afterSeparator {
					return nil, newError(KindParse, "CATF-CANON-010", "blank line before first section not allowed")
				}
			} else {
				if !afterSeparator {
					return nil, newError(KindParse, "CATF-CANON-010", "missing blank line between sections")
				}
			}
			afterSeparator = false
			seenSection[line] = true
			currSection = line
			currPairs = make(map[string]string)
			continue
		}

		if !seenAnySection {
			return nil, newError(KindParse, "CATF-STR-020", "unexpected content before first section")
		}

		if line == "" {
			if currSection == "" {
				return nil, newError(KindParse, "CATF-CANON-010", "blank line outside section not allowed")
			}
			if currSection == "CRYPTO" {
				return nil, newError(KindParse, "CATF-CANON-010", "blank line after CRYPTO section not allowed")
			}
			if afterSeparator {
				return nil, newError(KindParse, "CATF-CANON-010", "multiple blank lines between sections not allowed")
			}
			if err := flushSection(); err != nil {
				return nil, err
			}
			afterSeparator = true
			continue
		}

		if currSection == "" {
			return nil, newError(KindParse, "CATF-STR-020", "content outside section")
		}
		if afterSeparator {
			return nil, newError(KindParse, "CATF-CANON-010", "expected section header after blank line")
		}
		if !strings.Contains(line, ": ") {
			return nil, newError(KindParse, "CATF-STR-030", "invalid key-value formatting")
		}
		kv := strings.SplitN(line, ": ", 2)
		key, val := kv[0], kv[1]
		if key == "" {
			return nil, newError(KindParse, "CATF-STR-030", "empty key")
		}
		if !isASCII(key) {
			return nil, newError(KindParse, "CATF-STR-030", "non-ASCII key")
		}
		if val == "" {
			return nil, newError(KindParse, "CATF-STR-030", "empty value")
		}
		if strings.HasPrefix(val, " ") {
			return nil, newError(KindParse, "CATF-STR-030", "value must not start with a space")
		}
		if strings.Contains(val, "\n") || strings.Contains(val, "\r") {
			return nil, newError(KindParse, "CATF-STR-030", "value must not contain newlines")
		}
		if strings.HasSuffix(val, " ") || strings.HasSuffix(val, "\t") {
			return nil, newError(KindParse, "CATF-STR-030", "trailing whitespace forbidden")
		}
		if _, exists := currPairs[key]; exists {
			return nil, newError(KindParse, "CATF-STR-030", "duplicate key in section")
		}
		currPairs[key] = val
		currKeyOrder = append(currKeyOrder, key)

		if rerr == io.EOF {
			return nil, newError(KindParse, "CATF-STR-010", "missing CATF postamble")
		}
	}

	for _, s := range SectionOrder {
		if !seenSection[s] {
			return nil, newError(KindParse, "CATF-STR-020", "sections missing or out of order")
		}
	}
	if claimsEndLineNo < 0 {
		return nil, newError(KindParse, "CATF-STR-020", "missing CLAIMS section")
	}

	// Defensive: validate all keys are ASCII.
	for _, sec := range sections {
		for k := range sec.Pairs {
			if !isASCII(k) {
				return nil, newError(KindParse, "CATF-STR-030", "non-ASCII key")
			}
		}
	}

	return &parsedSections{sections: sections, claimsEndLineNo: claimsEndLineNo}, nil
}
