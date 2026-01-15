package crof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"xdao.co/catf/resolver"
)

func TestCID_RejectsMissingTrailingNewline(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Fatalf("expected Render to produce trailing newline")
	}
	_, err := CID(b[:len(b)-1])
	if err == nil {
		t.Fatalf("expected CID error")
	}
}

func TestCID_RejectsCRLF(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	bad := []byte(strings.ReplaceAll(string(b), "\n", "\r\n"))
	_, err := CID(bad)
	if err == nil {
		t.Fatalf("expected CID error")
	}
}

func TestCID_RejectsTrailingWhitespace(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	bad := bytes.Replace(b, []byte("META\n"), []byte("META \n"), 1)
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	_, err := CID(bad)
	if err == nil {
		t.Fatalf("expected CID error")
	}
}

func TestCanonicalizeCROF_RejectsMissingOrOutOfOrderSection(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	// Break section order by removing RESULT header.
	bad := []byte(strings.Replace(string(b), "\nRESULT\n", "\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsUnsortedMetaLines(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	// Swap META line order: Spec before Resolver-ID.
	text := string(b)
	from := "Resolver-ID: xdao-resolver-reference\nSpec: xdao-crof-1\n"
	to := "Spec: xdao-crof-1\nResolver-ID: xdao-resolver-reference\n"
	badText := strings.Replace(text, from, to, 1)
	bad := []byte(badText)
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsMissingRequiredMetaKey(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	bad := []byte(strings.Replace(string(b), "Spec: xdao-crof-1\n", "", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsMissingBlankLineAfterSection(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	// Remove the required blank line after META by collapsing the separator.
	bad := []byte(strings.Replace(string(b), "Version: 1\n\nINPUTS\n", "Version: 1\nINPUTS\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsBOM(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	bad := append([]byte{0xEF, 0xBB, 0xBF}, b...)
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsInvalidUTF8(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	bad := append([]byte(nil), b...)
	bad[0] = 0xFF
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsMissingPreamble(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text, Preamble+"\n", "BOGUS-PREAMBLE\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsMissingPostamble(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text, "\n"+Postamble+"\n", "\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsUnexpectedContentBeforePostamble(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text, "\n"+Postamble+"\n", "\nX\n"+Postamble+"\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsEmptyInput(t *testing.T) {
	if _, err := CanonicalizeCROF(nil); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsExclusionsMissingReason(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID:     "bafy-doc-1",
		State:          resolver.StateResolved,
		Confidence:     resolver.ConfidenceHigh,
		Exclusions:     []resolver.Exclusion{{CID: "bafy-a1", Reason: "EXCLUSION-REASON-1"}},
		Verdicts:       []resolver.Verdict{{CID: "bafy-a1", Trusted: true, Revoked: false}},
		PolicyVerdicts: nil,
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text, "Reason: EXCLUSION-REASON-1\n\nVERDICTS\n", "\n\nVERDICTS\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsExclusionsDuplicateAttestationCID(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Exclusions: []resolver.Exclusion{{CID: "bafy-a1", Reason: "EXCLUSION-REASON-2"}},
		Verdicts:   []resolver.Verdict{{CID: "bafy-a1", Trusted: true, Revoked: false}},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text,
		"EXCLUSIONS\nAttestation-CID: bafy-a1\n",
		"EXCLUSIONS\nAttestation-CID: bafy-a1\nAttestation-CID: bafy-a1\n",
		1,
	))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsExclusionsDuplicateInputHash(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Exclusions: []resolver.Exclusion{{InputHash: "sha256:aa", Reason: "EXCLUSION-REASON-3"}},
		Verdicts:   []resolver.Verdict{{InputHash: "sha256:aa", Trusted: false, Revoked: false, ExcludedReason: "EXCLUSION-REASON-3"}},
	}
	b := Render(res, "bafy-policy", []string{"sha256:aa"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text,
		"EXCLUSIONS\nInput-Hash: sha256:aa\n",
		"EXCLUSIONS\nInput-Hash: sha256:aa\nInput-Hash: sha256:aa\n",
		1,
	))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsVerdictsMissingTrusted(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Verdicts:   []resolver.Verdict{{CID: "bafy-a1", Trusted: true, Revoked: false}},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text, "Trusted: true\n", "", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsVerdictsDuplicateAttestationCID(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Verdicts:   []resolver.Verdict{{CID: "bafy-a1", Trusted: true, Revoked: false}},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text,
		"VERDICTS\nAttestation-CID: bafy-a1\n",
		"VERDICTS\nAttestation-CID: bafy-a1\nAttestation-CID: bafy-a1\n",
		1,
	))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsVerdictsRecordNotStartingWithCIDOrHash(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Verdicts:   []resolver.Verdict{{CID: "bafy-a1", Trusted: true, Revoked: false}},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text,
		"VERDICTS\nAttestation-CID: bafy-a1\nTrusted: true\n",
		"VERDICTS\nTrusted: true\nAttestation-CID: bafy-a1\n",
		1,
	))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsPathsNotStartingWithPathID(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Paths: []resolver.Path{
			{ID: "path-a", CIDs: []string{"bafy-a1"}},
		},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text, "Path-ID: path-a\n", "Attestation-CID: bafy-a1\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsUnsortedPathIDs(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Paths: []resolver.Path{
			{ID: "path-a", CIDs: []string{"bafy-a1"}},
			{ID: "path-b", CIDs: []string{"bafy-a2"}},
		},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1", "bafy-a2"}, RenderOptions{})

	text := string(b)
	// Make the second ID lexicographically smaller than the first.
	bad := []byte(strings.Replace(text, "Path-ID: path-b\n", "Path-ID: path-0\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsForksNotStartingWithForkID(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Forks: []resolver.Fork{
			{ID: "fork-a", ConflictingPath: []string{"path-a"}},
		},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text, "Fork-ID: fork-a\n", "Conflicting-Path: path-a\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsUnsortedForkIDs(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Forks: []resolver.Fork{
			{ID: "fork-a", ConflictingPath: []string{"path-a"}},
			{ID: "fork-b", ConflictingPath: []string{"path-b"}},
		},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	// Make the second ID lexicographically smaller than the first.
	bad := []byte(strings.Replace(text, "Fork-ID: fork-b\n", "Fork-ID: fork-0\n", 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsUnsortedConflictingPaths(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		Forks: []resolver.Fork{
			{ID: "fork-a", ConflictingPath: []string{"path-a", "path-b"}},
		},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	bad := []byte(strings.Replace(text,
		"Conflicting-Path: path-a\nConflicting-Path: path-b\n",
		"Conflicting-Path: path-b\nConflicting-Path: path-a\n",
		1,
	))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsResultMissingSubjectCID(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	start := strings.Index(text, "Subject-CID: ")
	if start < 0 {
		t.Fatalf("missing Subject-CID line in rendered CROF")
	}
	end := strings.Index(text[start:], "\n")
	if end < 0 {
		t.Fatalf("missing newline after Subject-CID line")
	}
	end = start + end + 1
	bad := []byte(text[:start] + text[end:])
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsResultMissingConfidence(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	start := strings.Index(text, "Confidence: ")
	if start < 0 {
		t.Fatalf("missing Confidence line in rendered CROF")
	}
	end := strings.Index(text[start:], "\n")
	if end < 0 {
		t.Fatalf("missing newline after Confidence line")
	}
	end = start + end + 1
	bad := []byte(text[:start] + text[end:])
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsResultMissingState(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	start := strings.Index(text, "State: ")
	if start < 0 {
		t.Fatalf("missing State line in rendered CROF")
	}
	end := strings.Index(text[start:], "\n")
	if end < 0 {
		t.Fatalf("missing newline after State line")
	}
	end = start + end + 1
	bad := []byte(text[:start] + text[end:])
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsResultInvalidKVFormatting(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	start := strings.Index(text, "State: ")
	if start < 0 {
		t.Fatalf("missing State line in rendered CROF")
	}
	end := strings.Index(text[start:], "\n")
	if end < 0 {
		t.Fatalf("missing newline after State line")
	}
	end = start + end + 1
	line := text[start:end]
	mutated := strings.Replace(line, ": ", " ", 1)
	if mutated == line {
		t.Fatalf("failed to mutate key-value formatting")
	}
	bad := []byte(text[:start] + mutated + text[end:])
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsResultDuplicateLine(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	start := strings.Index(text, "State: ")
	if start < 0 {
		t.Fatalf("missing State line in rendered CROF")
	}
	end := strings.Index(text[start:], "\n")
	if end < 0 {
		t.Fatalf("missing newline after State line")
	}
	end = start + end + 1
	line := text[start:end]
	// Duplicate an existing RESULT line; validateSortedStrict should reject duplicates.
	bad := []byte(strings.Replace(text, line, line+line, 1))
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsCryptoMissingResolverKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x44
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})

	text := string(out)
	start := strings.Index(text, "Resolver-Key: "+resolverKey+"\n")
	if start < 0 {
		t.Fatalf("missing Resolver-Key line in signed output")
	}
	bad := []byte(strings.Replace(text, "Resolver-Key: "+resolverKey+"\n", "", 1))
	if bytes.Equal(out, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsCryptoInvalidKVFormatting(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x45
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})

	text := string(out)
	idx := strings.Index(text, "Signature-Alg: ")
	if idx < 0 {
		t.Fatalf("missing Signature-Alg line in signed output")
	}
	lineEnd := strings.Index(text[idx:], "\n")
	if lineEnd < 0 {
		t.Fatalf("malformed signed output")
	}
	lineEnd = idx + lineEnd + 1
	line := text[idx:lineEnd]
	mutated := strings.Replace(line, ": ", " ", 1)
	if mutated == line {
		t.Fatalf("failed to mutate key-value formatting")
	}
	bad := []byte(text[:idx] + mutated + text[lineEnd:])
	if bytes.Equal(out, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsCryptoDuplicateLine(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x46
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})

	text := string(out)
	idx := strings.Index(text, "Hash-Alg: ")
	if idx < 0 {
		t.Fatalf("missing Hash-Alg line in signed output")
	}
	lineEnd := strings.Index(text[idx:], "\n")
	if lineEnd < 0 {
		t.Fatalf("malformed signed output")
	}
	lineEnd = idx + lineEnd + 1
	line := text[idx:lineEnd]
	bad := []byte(text[:idx] + line + text[idx:])
	if bytes.Equal(out, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsResultUnknownKey(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})

	text := string(b)
	idx := strings.Index(text, "RESULT\n")
	if idx < 0 {
		t.Fatalf("missing RESULT section")
	}
	idx += len("RESULT\n")
	bad := []byte(text[:idx] + "Bogus: x\n" + text[idx:])
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsResultMalformedPolicyVerdictLine(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateResolved,
		Confidence: resolver.ConfidenceHigh,
		PolicyVerdicts: []resolver.PolicyVerdict{{
			Type:      "authorship",
			Role:      "author",
			Quorum:    1,
			Observed:  1,
			Satisfied: true,
		}},
	}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	if _, err := CanonicalizeCROF(b); err != nil {
		t.Fatalf("expected canonical output, got: %v", err)
	}

	text := string(b)
	idx := strings.Index(text, "Policy-Verdict: ")
	if idx < 0 {
		t.Fatalf("missing Policy-Verdict line")
	}
	end := strings.Index(text[idx:], "\n")
	if end < 0 {
		t.Fatalf("malformed output")
	}
	end = idx + end + 1
	line := text[idx:end]
	// Remove one required field.
	mut := strings.Replace(line, "; Observed=1", "", 1)
	if mut == line {
		t.Fatalf("failed to mutate policy verdict line")
	}
	bad := []byte(text[:idx] + mut + text[end:])
	if bytes.Equal(b, bad) {
		t.Fatalf("failed to mutate CROF bytes")
	}
	if _, err := CanonicalizeCROF(bad); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}
