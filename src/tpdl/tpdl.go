// Package tpdl implements parsing for the Trust Policy Domain Language (TPDL).
package tpdl

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"strings"

	"xdao.co/catf/compliance"
)

type Policy struct {
	Meta  map[string]string
	Trust []TrustEntry
	Rules []Rule

	// SupersedesAllowedBy restricts which trusted roles may issue supersession attestations.
	// When empty, supersession attestations are not additionally restricted by policy.
	SupersedesAllowedBy []string
}

type TrustEntry struct {
	Key  string
	Role string
}

type Rule struct {
	Type   string
	Role   string
	Quorum int
}

// ParseWithCompliance parses a TPDL policy and optionally enforces additional
// compliance-mode constraints.
//
// In compliance.Strict mode, this enforces "no defaults": every Require block
// must include an explicit Quorum field.
func ParseWithCompliance(data []byte, mode compliance.ComplianceMode) (*Policy, error) {
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if mode == compliance.Strict {
		if err := enforceStrictTPDL(data); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// ParseStrict is a convenience wrapper for ParseWithCompliance(..., compliance.Strict).
func ParseStrict(data []byte) (*Policy, error) {
	return ParseWithCompliance(data, compliance.Strict)
}

func enforceStrictTPDL(data []byte) error {
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	stripIndent := func(s string) string {
		return strings.TrimLeft(s, " \t")
	}

	for i := 0; i < len(lines); i++ {
		if lines[i] != "Require:" {
			continue
		}
		hasQuorum := false
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if l == "" {
				break
			}
			if l == "Require:" || l == "Supersedes:" || l == "META" || l == "TRUST" || l == "RULES" || strings.HasPrefix(l, "-----END ") {
				break
			}
			l = stripIndent(l)
			if strings.HasPrefix(l, "Quorum: ") {
				hasQuorum = true
				break
			}
		}
		if !hasQuorum {
			return errors.New("strict mode: Require block missing Quorum")
		}
	}
	return nil
}

// Parse parses a TPDL policy from bytes.
func Parse(data []byte) (*Policy, error) {
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("BOM not allowed")
	}
	if bytes.Contains(data, []byte("\r")) {
		return nil, errors.New("CR line endings not allowed")
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
			return nil, errors.New("trailing whitespace forbidden")
		}
	}

	lines := strings.Split(string(data), "\n")
	// Allow a trailing newline in the input by dropping the last empty line.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 2 {
		return nil, errors.New("TPDL too short")
	}
	if lines[0] != "-----BEGIN XDAO TRUST POLICY-----" {
		return nil, errors.New("missing TPDL preamble")
	}
	if lines[len(lines)-1] != "-----END XDAO TRUST POLICY-----" {
		return nil, errors.New("missing TPDL postamble")
	}

	meta := make(map[string]string)
	var trust []TrustEntry
	var rules []Rule
	allowedBy := make(map[string]bool)

	stripIndent := func(s string) string {
		return strings.TrimLeft(s, " \t")
	}

	sectionOrder := []string{"META", "TRUST", "RULES"}
	sectionIndex := -1
	currSection := ""

	for i := 1; i < len(lines)-1; {
		line := lines[i]
		if line == "" {
			i++
			continue
		}

		// Section headers must appear in fixed order.
		if line == "META" || line == "TRUST" || line == "RULES" {
			if currSection != "" {
				// ok
			}
			sectionIndex++
			if sectionIndex >= len(sectionOrder) || sectionOrder[sectionIndex] != line {
				return nil, errors.New("sections missing or out of order")
			}
			currSection = line
			i++
			continue
		}
		if currSection == "" {
			return nil, errors.New("unexpected content before first section")
		}

		switch currSection {
		case "META":
			if !strings.Contains(line, ": ") {
				return nil, errors.New("invalid META key-value")
			}
			kv := strings.SplitN(line, ": ", 2)
			meta[kv[0]] = kv[1]
			i++
		case "TRUST":
			if !strings.HasPrefix(line, "Key: ") {
				return nil, errors.New("expected Key in TRUST")
			}
			key := strings.TrimPrefix(line, "Key: ")
			if key == "" {
				return nil, errors.New("empty Key")
			}
			if i+1 >= len(lines)-1 {
				return nil, errors.New("expected Role after Key")
			}
			roleLine := lines[i+1]
			if !strings.HasPrefix(roleLine, "Role: ") {
				return nil, errors.New("expected Role after Key")
			}
			role := strings.TrimPrefix(roleLine, "Role: ")
			if role == "" {
				return nil, errors.New("empty Role")
			}
			trust = append(trust, TrustEntry{Key: key, Role: role})
			i += 2
		case "RULES":
			if line == "Require:" {
				var r Rule
				r.Quorum = 1
				i++
				for i < len(lines)-1 {
					l := lines[i]
					if l == "" {
						i++
						break
					}
					// New block or section header.
					if l == "Require:" || l == "Supersedes:" || l == "META" || l == "TRUST" || l == "RULES" {
						break
					}
					l = stripIndent(l)
					switch {
					case strings.HasPrefix(l, "Type: "):
						r.Type = strings.TrimPrefix(l, "Type: ")
					case strings.HasPrefix(l, "Role: "):
						r.Role = strings.TrimPrefix(l, "Role: ")
					case strings.HasPrefix(l, "Quorum: "):
						qStr := strings.TrimPrefix(l, "Quorum: ")
						q, qErr := strconv.Atoi(qStr)
						if qErr != nil || q < 1 {
							return nil, errors.New("invalid Quorum")
						}
						r.Quorum = q
					default:
						return nil, errors.New("unknown field in Require block")
					}
					i++
				}
				if r.Type == "" || r.Role == "" {
					return nil, errors.New("Require block missing Type or Role")
				}
				rules = append(rules, r)
				continue
			}
			if line == "Supersedes:" {
				i++
				for i < len(lines)-1 {
					l := lines[i]
					if l == "" {
						i++
						break
					}
					if l == "Require:" || l == "Supersedes:" || l == "META" || l == "TRUST" || l == "RULES" {
						break
					}
					l = stripIndent(l)
					if strings.HasPrefix(l, "Allowed-By: ") {
						list := strings.TrimPrefix(l, "Allowed-By: ")
						for _, part := range strings.Split(list, ",") {
							role := strings.TrimSpace(part)
							if role == "" {
								continue
							}
							allowedBy[role] = true
						}
						if len(list) == 0 {
							return nil, errors.New("Allowed-By must not be empty")
						}
					} else {
						return nil, errors.New("unknown field in Supersedes block")
					}
					i++
				}
				continue
			}
			return nil, errors.New("unexpected content in RULES")
		default:
			return nil, errors.New("unknown section")
		}
	}

	if sectionIndex != len(sectionOrder)-1 {
		return nil, errors.New("sections missing or out of order")
	}

	allowedList := make([]string, 0, len(allowedBy))
	for r := range allowedBy {
		allowedList = append(allowedList, r)
	}
	sort.Strings(allowedList)

	// Spec-strict META validation (ReferenceDesign.md §16.4).
	if meta["Spec"] == "" {
		return nil, errors.New("missing META Spec")
	}
	if meta["Spec"] != "xdao-tpdl-1" {
		return nil, errors.New("unsupported policy Spec")
	}
	if meta["Version"] == "" {
		return nil, errors.New("missing META Version")
	}
	if meta["Version"] != "1" {
		return nil, errors.New("unsupported policy Version")
	}

	return &Policy{Meta: meta, Trust: trust, Rules: rules, SupersedesAllowedBy: allowedList}, nil
}
