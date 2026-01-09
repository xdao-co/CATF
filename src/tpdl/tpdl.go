// Package tpdl implements parsing for the Trust Policy Domain Language (TPDL).
package tpdl

import (
	"bufio"
	"bytes"
	"errors"
	"strconv"
	"strings"
)

type Policy struct {
	Meta  map[string]string
	Trust []TrustEntry
	Rules []Rule
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

	if !bytes.HasPrefix(data, []byte("-----BEGIN XDAO TRUST POLICY-----")) {
		return nil, errors.New("missing TPDL preamble")
	}
	if !bytes.HasSuffix(bytes.TrimSpace(data), []byte("-----END XDAO TRUST POLICY-----")) {
		return nil, errors.New("missing TPDL postamble")
	}
	sections := map[string]bool{"META": true, "TRUST": true, "RULES": true}
	reader := bufio.NewReader(bytes.NewReader(data))
	var currSection string
	meta := make(map[string]string)
	var trust []TrustEntry
	var rules []Rule
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err.Error() != "EOF" {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if sections[line] {
			currSection = line
			continue
		}
		if currSection == "META" && strings.Contains(line, ": ") {
			kv := strings.SplitN(line, ": ", 2)
			meta[kv[0]] = kv[1]
		}
		if currSection == "TRUST" && strings.HasPrefix(line, "Key: ") {
			key := strings.TrimPrefix(line, "Key: ")
			roleLine, _ := reader.ReadString('\n')
			roleLine = strings.TrimSpace(roleLine)
			if !strings.HasPrefix(roleLine, "Role: ") {
				return nil, errors.New("expected Role after Key")
			}
			role := strings.TrimPrefix(roleLine, "Role: ")
			trust = append(trust, TrustEntry{Key: key, Role: role})
		}
		if currSection == "RULES" && strings.HasPrefix(line, "Require:") {
			var r Rule
			r.Quorum = 1
			for {
				l, _ := reader.ReadString('\n')
				l = strings.TrimSpace(l)
				if l == "" || strings.HasSuffix(l, ":") || l == "-----END XDAO TRUST POLICY-----" {
					break
				}
				if strings.HasPrefix(l, "Type: ") {
					r.Type = strings.TrimPrefix(l, "Type: ")
				}
				if strings.HasPrefix(l, "Role: ") {
					r.Role = strings.TrimPrefix(l, "Role: ")
				}
				if strings.HasPrefix(l, "Quorum: ") {
					qStr := strings.TrimPrefix(l, "Quorum: ")
					q, qErr := strconv.Atoi(qStr)
					if qErr != nil || q < 1 {
						return nil, errors.New("invalid Quorum")
					}
					r.Quorum = q
				}
			}
			if r.Type == "" || r.Role == "" {
				return nil, errors.New("Require block missing Type or Role")
			}
			rules = append(rules, r)
		}
		if err != nil {
			break
		}
	}
	return &Policy{Meta: meta, Trust: trust, Rules: rules}, nil
}
