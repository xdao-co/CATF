package crof

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// CanonicalizeCROF is the mandatory canonicalization choke point for CROF.
//
// CROF evidence MUST be canonical before CID derivation, signing, or supersession
// validation. This function enforces byte-level canonical rules by rejecting any
// non-canonical input.
func CanonicalizeCROF(input []byte) ([]byte, error) {
	if !utf8.Valid(input) {
		return nil, errors.New("CROF must be valid UTF-8")
	}
	if bytes.HasPrefix(input, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("BOM not allowed")
	}
	if bytes.Contains(input, []byte("\r")) {
		return nil, errors.New("CR line endings not allowed")
	}
	if len(input) == 0 {
		return nil, errors.New("empty CROF")
	}
	// Canonical CROF emitted by Render always ends with a newline.
	if input[len(input)-1] != '\n' {
		return nil, errors.New("missing trailing newline")
	}
	for _, line := range bytes.Split(input, []byte("\n")) {
		if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
			return nil, errors.New("trailing whitespace forbidden")
		}
	}

	if err := validateCanonicalCROF(string(input)); err != nil {
		return nil, err
	}

	// Return a copy to prevent caller mutation.
	return append([]byte(nil), input...), nil
}

var crofSectionOrder = []string{"META", "INPUTS", "RESULT", "PATHS", "FORKS", "EXCLUSIONS", "VERDICTS", "CRYPTO"}

func validateCanonicalCROF(doc string) error {
	lines := strings.Split(doc, "\n")
	// Canonical CROF has a trailing newline, so last line is always empty.
	if len(lines) < 3 {
		return errors.New("CROF too short")
	}
	if lines[0] != Preamble {
		return errors.New("missing CROF preamble")
	}
	if lines[len(lines)-1] != "" {
		return errors.New("missing trailing newline")
	}
	if lines[len(lines)-2] != Postamble {
		return errors.New("missing CROF postamble")
	}

	i := 1
	for _, sec := range crofSectionOrder {
		if i >= len(lines)-2 {
			return fmt.Errorf("missing section %q", sec)
		}
		if lines[i] != sec {
			return fmt.Errorf("sections missing or out of order (expected %q got %q)", sec, lines[i])
		}
		i++
		start := i
		for i < len(lines)-2 && lines[i] != "" {
			i++
		}
		if i >= len(lines)-2 {
			return fmt.Errorf("missing blank line after section %q", sec)
		}
		body := lines[start:i]
		if err := validateSection(sec, body); err != nil {
			return err
		}
		// Consume the required section terminator blank line.
		i++
	}

	if i != len(lines)-2 {
		return errors.New("unexpected content before postamble")
	}
	return nil
}

func validateSection(section string, body []string) error {
	switch section {
	case "META":
		return validateMeta(body)
	case "INPUTS":
		return validateInputs(body)
	case "RESULT":
		return validateResult(body)
	case "PATHS":
		return validatePaths(body)
	case "FORKS":
		return validateForks(body)
	case "EXCLUSIONS":
		return validateExclusions(body)
	case "VERDICTS":
		return validateVerdicts(body)
	case "CRYPTO":
		return validateCrypto(body)
	default:
		return fmt.Errorf("unknown section %q", section)
	}
}

func validateSortedStrict(lines []string) error {
	seen := make(map[string]bool)
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if l == "" {
			return errors.New("empty line inside section")
		}
		if seen[l] {
			return errors.New("duplicate line")
		}
		seen[l] = true
		if i > 0 && !(lines[i-1] < lines[i]) {
			return errors.New("lines not sorted lexicographically")
		}
	}
	return nil
}

func validateKVLine(line string) (string, string, error) {
	if !strings.Contains(line, ": ") {
		return "", "", errors.New("invalid key-value formatting")
	}
	k, v, _ := strings.Cut(line, ": ")
	if k == "" {
		return "", "", errors.New("empty key")
	}
	if v == "" {
		return "", "", errors.New("empty value")
	}
	return k, v, nil
}

func validateMeta(body []string) error {
	if err := validateSortedStrict(body); err != nil {
		return fmt.Errorf("META: %w", err)
	}
	need := map[string]bool{"Resolver-ID": false, "Spec": false, "Version": false}
	for _, l := range body {
		k, _, err := validateKVLine(l)
		if err != nil {
			return fmt.Errorf("META: %w", err)
		}
		if _, ok := need[k]; ok {
			need[k] = true
		}
	}
	for k, ok := range need {
		if !ok {
			return fmt.Errorf("META: missing %s", k)
		}
	}
	return nil
}

func validateInputs(body []string) error {
	if len(body) == 0 {
		return errors.New("INPUTS: missing Trust-Policy-CID")
	}
	if !strings.HasPrefix(body[0], "Trust-Policy-CID: ") {
		return errors.New("INPUTS: first line must be Trust-Policy-CID")
	}
	_, v, err := validateKVLine(body[0])
	if err != nil || v == "" {
		return errors.New("INPUTS: invalid Trust-Policy-CID")
	}
	var att []string
	var hashes []string
	seenHash := false
	for i := 1; i < len(body); i++ {
		if strings.HasPrefix(body[i], "Attestation-CID: ") {
			if seenHash {
				return errors.New("INPUTS: Attestation-CID after Input-Hash")
			}
			_, v, err := validateKVLine(body[i])
			if err != nil || v == "" {
				return errors.New("INPUTS: invalid Attestation-CID")
			}
			att = append(att, v)
			continue
		}
		if strings.HasPrefix(body[i], "Input-Hash: ") {
			seenHash = true
			_, v, err := validateKVLine(body[i])
			if err != nil || v == "" {
				return errors.New("INPUTS: invalid Input-Hash")
			}
			hashes = append(hashes, v)
			continue
		}
		return errors.New("INPUTS: unexpected line")
	}
	for i := 1; i < len(att); i++ {
		if att[i-1] > att[i] {
			return errors.New("INPUTS: Attestation-CID not sorted")
		}
	}
	for i := 1; i < len(hashes); i++ {
		if hashes[i-1] > hashes[i] {
			return errors.New("INPUTS: Input-Hash not sorted")
		}
	}
	return nil
}

func validateResult(body []string) error {
	if err := validateSortedStrict(body); err != nil {
		return fmt.Errorf("RESULT: %w", err)
	}
	need := map[string]bool{"Subject-CID": false, "Confidence": false, "State": false}
	for _, l := range body {
		k, v, err := validateKVLine(l)
		if err != nil {
			return fmt.Errorf("RESULT: %w", err)
		}
		switch k {
		case "Subject-CID", "Confidence", "State":
			need[k] = true
		case "Policy-Verdict":
			if err := validatePolicyVerdictValue(v); err != nil {
				return fmt.Errorf("RESULT: %w", err)
			}
		case "Policy-Issuer-Key":
			if err := validatePolicyIssuerKeyValue(v); err != nil {
				return fmt.Errorf("RESULT: %w", err)
			}
		case "Policy-Verdict-Reason":
			if err := validatePolicyVerdictReasonValue(v); err != nil {
				return fmt.Errorf("RESULT: %w", err)
			}
		default:
			return fmt.Errorf("RESULT: unknown key %q", k)
		}
	}
	for k, ok := range need {
		if !ok {
			return fmt.Errorf("RESULT: missing %s", k)
		}
	}
	return nil
}

func validatePolicyKVParts(value string, requiredKeys map[string]func(string) error) error {
	parts := strings.Split(value, "; ")
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		if p == "" {
			return errors.New("empty policy field")
		}
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return errors.New("invalid policy field formatting")
		}
		if k == "" {
			return errors.New("empty policy field key")
		}
		if v == "" {
			return errors.New("empty policy field value")
		}
		if seen[k] {
			return errors.New("duplicate policy field")
		}
		seen[k] = true
		check, ok := requiredKeys[k]
		if !ok {
			return fmt.Errorf("unknown policy field %q", k)
		}
		if err := check(v); err != nil {
			return err
		}
	}
	for k := range requiredKeys {
		if !seen[k] {
			return fmt.Errorf("missing policy field %q", k)
		}
	}
	return nil
}

func validatePolicyVerdictValue(value string) error {
	required := map[string]func(string) error{
		"Type": func(v string) error { return nil },
		"Role": func(v string) error { return nil },
		"Quorum": func(v string) error {
			for _, r := range v {
				if r < '0' || r > '9' {
					return errors.New("invalid Quorum")
				}
			}
			return nil
		},
		"Observed": func(v string) error {
			for _, r := range v {
				if r < '0' || r > '9' {
					return errors.New("invalid Observed")
				}
			}
			return nil
		},
		"Satisfied": func(v string) error {
			if v != "true" && v != "false" {
				return errors.New("invalid Satisfied")
			}
			return nil
		},
	}
	return validatePolicyKVParts(value, required)
}

func validatePolicyIssuerKeyValue(value string) error {
	required := map[string]func(string) error{
		"Type":       func(v string) error { return nil },
		"Role":       func(v string) error { return nil },
		"Issuer-Key": func(v string) error { return nil },
	}
	return validatePolicyKVParts(value, required)
}

func validatePolicyVerdictReasonValue(value string) error {
	required := map[string]func(string) error{
		"Type":   func(v string) error { return nil },
		"Role":   func(v string) error { return nil },
		"Reason": func(v string) error { return nil },
	}
	return validatePolicyKVParts(value, required)
}

func validatePaths(body []string) error {
	if len(body) == 0 {
		return nil
	}
	var lastID string
	i := 0
	for i < len(body) {
		if !strings.HasPrefix(body[i], "Path-ID: ") {
			return errors.New("PATHS: expected Path-ID")
		}
		_, id, err := validateKVLine(body[i])
		if err != nil {
			return fmt.Errorf("PATHS: %w", err)
		}
		if lastID != "" && !(lastID < id) {
			return errors.New("PATHS: Path-ID not sorted")
		}
		lastID = id
		i++
		for i < len(body) && strings.HasPrefix(body[i], "Attestation-CID: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil || v == "" {
				return errors.New("PATHS: invalid Attestation-CID")
			}
			i++
		}
	}
	return nil
}

func validateForks(body []string) error {
	if len(body) == 0 {
		return nil
	}
	var lastID string
	i := 0
	for i < len(body) {
		if !strings.HasPrefix(body[i], "Fork-ID: ") {
			return errors.New("FORKS: expected Fork-ID")
		}
		_, id, err := validateKVLine(body[i])
		if err != nil {
			return fmt.Errorf("FORKS: %w", err)
		}
		if lastID != "" && !(lastID < id) {
			return errors.New("FORKS: Fork-ID not sorted")
		}
		lastID = id
		i++
		var paths []string
		for i < len(body) && strings.HasPrefix(body[i], "Conflicting-Path: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil || v == "" {
				return errors.New("FORKS: invalid Conflicting-Path")
			}
			paths = append(paths, v)
			i++
		}
		for j := 1; j < len(paths); j++ {
			if paths[j-1] > paths[j] {
				return errors.New("FORKS: Conflicting-Path not sorted")
			}
		}
	}
	return nil
}

type exclusionRecord struct {
	cid    string
	hash   string
	reason string
}

func validateExclusions(body []string) error {
	if len(body) == 0 {
		return nil
	}
	var recs []exclusionRecord
	i := 0
	for i < len(body) {
		cid := ""
		hash := ""
		for i < len(body) {
			if strings.HasPrefix(body[i], "Attestation-CID: ") {
				if cid != "" {
					return errors.New("EXCLUSIONS: duplicate Attestation-CID")
				}
				_, v, err := validateKVLine(body[i])
				if err != nil {
					return fmt.Errorf("EXCLUSIONS: %w", err)
				}
				cid = v
				i++
				continue
			}
			if strings.HasPrefix(body[i], "Input-Hash: ") {
				if hash != "" {
					return errors.New("EXCLUSIONS: duplicate Input-Hash")
				}
				_, v, err := validateKVLine(body[i])
				if err != nil {
					return fmt.Errorf("EXCLUSIONS: %w", err)
				}
				hash = v
				i++
				continue
			}
			break
		}
		if i >= len(body) || !strings.HasPrefix(body[i], "Reason: ") {
			return errors.New("EXCLUSIONS: expected Reason")
		}
		_, reason, err := validateKVLine(body[i])
		if err != nil {
			return fmt.Errorf("EXCLUSIONS: %w", err)
		}
		recs = append(recs, exclusionRecord{cid: cid, hash: hash, reason: reason})
		i++
	}
	for i := 1; i < len(recs); i++ {
		p, c := recs[i-1], recs[i]
		if p.cid == c.cid {
			if p.hash == c.hash {
				if p.reason > c.reason {
					return errors.New("EXCLUSIONS: not sorted")
				}
				continue
			}
			if p.hash > c.hash {
				return errors.New("EXCLUSIONS: not sorted")
			}
			continue
		}
		if p.cid > c.cid {
			return errors.New("EXCLUSIONS: not sorted")
		}
	}
	return nil
}

type verdictRecord struct {
	cid                string
	inputHash          string
	attestedSubjectCID string
	issuerKey          string
	claimType          string
	status             string
	trusted            bool
	revoked            bool
	revokedBy          []string
	trustRoles         []string
	reasons            []string
	excluded           string
	lineJoinRole       string
	lineJoinReasons    string
	lineJoinRevokedBy  string
}

func parseBoolLine(line, key string) (bool, error) {
	prefix := key + ": "
	if !strings.HasPrefix(line, prefix) {
		return false, fmt.Errorf("expected %s", key)
	}
	v := strings.TrimPrefix(line, prefix)
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid %s boolean", key)
	}
}

func validateVerdicts(body []string) error {
	if len(body) == 0 {
		return nil
	}
	var recs []verdictRecord
	i := 0
	for i < len(body) {
		if !(strings.HasPrefix(body[i], "Attestation-CID: ") || strings.HasPrefix(body[i], "Input-Hash: ")) {
			return errors.New("VERDICTS: each record must start with Attestation-CID or Input-Hash")
		}
		vr := verdictRecord{}
		for i < len(body) {
			if strings.HasPrefix(body[i], "Attestation-CID: ") {
				if vr.cid != "" {
					return errors.New("VERDICTS: duplicate Attestation-CID")
				}
				_, cid, err := validateKVLine(body[i])
				if err != nil {
					return fmt.Errorf("VERDICTS: %w", err)
				}
				vr.cid = cid
				i++
				continue
			}
			if strings.HasPrefix(body[i], "Input-Hash: ") {
				if vr.inputHash != "" {
					return errors.New("VERDICTS: duplicate Input-Hash")
				}
				_, h, err := validateKVLine(body[i])
				if err != nil {
					return fmt.Errorf("VERDICTS: %w", err)
				}
				vr.inputHash = h
				i++
				continue
			}
			break
		}
		if vr.cid == "" && vr.inputHash == "" {
			return errors.New("VERDICTS: missing Attestation-CID/Input-Hash")
		}

		if i < len(body) && strings.HasPrefix(body[i], "Attested-Subject-CID: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.attestedSubjectCID = v
			i++
		}

		if i < len(body) && strings.HasPrefix(body[i], "Issuer-Key: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.issuerKey = v
			i++
		}
		if i < len(body) && strings.HasPrefix(body[i], "Claim-Type: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.claimType = v
			i++
		}
		if i < len(body) && strings.HasPrefix(body[i], "Status: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.status = v
			i++
		}

		if i >= len(body) {
			return errors.New("VERDICTS: missing Trusted")
		}
		trusted, err := parseBoolLine(body[i], "Trusted")
		if err != nil {
			return fmt.Errorf("VERDICTS: %w", err)
		}
		vr.trusted = trusted
		i++

		if i >= len(body) {
			return errors.New("VERDICTS: missing Revoked")
		}
		revoked, err := parseBoolLine(body[i], "Revoked")
		if err != nil {
			return fmt.Errorf("VERDICTS: %w", err)
		}
		vr.revoked = revoked
		i++

		for i < len(body) && strings.HasPrefix(body[i], "Revoked-By: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.revokedBy = append(vr.revokedBy, v)
			i++
		}
		for j := 1; j < len(vr.revokedBy); j++ {
			if vr.revokedBy[j-1] > vr.revokedBy[j] {
				return errors.New("VERDICTS: Revoked-By not sorted")
			}
		}

		for i < len(body) && strings.HasPrefix(body[i], "Trust-Role: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.trustRoles = append(vr.trustRoles, v)
			i++
		}
		for j := 1; j < len(vr.trustRoles); j++ {
			if vr.trustRoles[j-1] > vr.trustRoles[j] {
				return errors.New("VERDICTS: Trust-Role not sorted")
			}
		}

		for i < len(body) && strings.HasPrefix(body[i], "Reason: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.reasons = append(vr.reasons, v)
			i++
		}
		for j := 1; j < len(vr.reasons); j++ {
			if vr.reasons[j-1] > vr.reasons[j] {
				return errors.New("VERDICTS: Reason not sorted")
			}
		}

		if i < len(body) && strings.HasPrefix(body[i], "Excluded-Reason: ") {
			_, v, err := validateKVLine(body[i])
			if err != nil {
				return fmt.Errorf("VERDICTS: %w", err)
			}
			vr.excluded = v
			i++
		}

		vr.lineJoinRole = strings.Join(vr.trustRoles, ",")
		vr.lineJoinReasons = strings.Join(vr.reasons, ",")
		vr.lineJoinRevokedBy = strings.Join(vr.revokedBy, ",")
		recs = append(recs, vr)
	}

	for i := 1; i < len(recs); i++ {
		if verdictLess(recs[i], recs[i-1]) {
			return errors.New("VERDICTS: records not sorted")
		}
	}
	return nil
}

func verdictLess(a, b verdictRecord) bool {
	if a.cid != b.cid {
		return a.cid < b.cid
	}
	if a.inputHash != b.inputHash {
		return a.inputHash < b.inputHash
	}
	if a.excluded != b.excluded {
		return a.excluded < b.excluded
	}
	if a.issuerKey != b.issuerKey {
		return a.issuerKey < b.issuerKey
	}
	if a.claimType != b.claimType {
		return a.claimType < b.claimType
	}
	if a.attestedSubjectCID != b.attestedSubjectCID {
		return a.attestedSubjectCID < b.attestedSubjectCID
	}
	if a.status != b.status {
		return a.status < b.status
	}
	if a.trusted != b.trusted {
		return a.trusted && !b.trusted
	}
	if a.revoked != b.revoked {
		return !a.revoked && b.revoked
	}
	if a.lineJoinRole != b.lineJoinRole {
		return a.lineJoinRole < b.lineJoinRole
	}
	if a.lineJoinReasons != b.lineJoinReasons {
		return a.lineJoinReasons < b.lineJoinReasons
	}
	return a.lineJoinRevokedBy < b.lineJoinRevokedBy
}

func validateCrypto(body []string) error {
	if len(body) == 0 {
		return nil
	}
	if err := validateSortedStrict(body); err != nil {
		return fmt.Errorf("CRYPTO: %w", err)
	}
	need := map[string]bool{"Hash-Alg": false, "Resolver-Key": false, "Signature-Alg": false, "Signature": false}
	for _, l := range body {
		k, _, err := validateKVLine(l)
		if err != nil {
			return fmt.Errorf("CRYPTO: %w", err)
		}
		if _, ok := need[k]; ok {
			need[k] = true
		}
	}
	for k, ok := range need {
		if !ok {
			return fmt.Errorf("CRYPTO: missing %s", k)
		}
	}
	return nil
}
