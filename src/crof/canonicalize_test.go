package crof

import (
	"bytes"
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
