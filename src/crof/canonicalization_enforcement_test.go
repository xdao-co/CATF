package crof

import (
	"strings"
	"testing"

	"xdao.co/catf/resolver"
)

func TestRender_OmitsAttestationCIDLineWhenEmpty(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-subject",
		State:      resolver.StateUnresolved,
		Confidence: resolver.ConfidenceUndefined,
		Exclusions: []resolver.Exclusion{{CID: "", InputHash: "sha256:deadbeef", Reason: "CATF parse/canonicalization failed"}},
		Verdicts:   []resolver.Verdict{{CID: "", InputHash: "sha256:deadbeef", ExcludedReason: "CATF parse/canonicalization failed"}},
	}

	out := Render(res, "bafy-policy", nil, RenderOptions{})
	text := string(out)
	if strings.Contains(text, "Attestation-CID: ") {
		t.Fatalf("did not expect Attestation-CID line when CID is empty")
	}
	if !strings.Contains(text, "Input-Hash: sha256:deadbeef") {
		t.Fatalf("expected Input-Hash line when CID is empty")
	}
	if !strings.Contains(text, "Reason: CATF parse/canonicalization failed") {
		t.Fatalf("expected exclusion reason to be rendered")
	}
	if !strings.Contains(text, "Excluded-Reason: CATF parse/canonicalization failed") {
		t.Fatalf("expected verdict excluded reason to be rendered")
	}
}

func TestCanonicalizeCROF_AllowsMixedInputsWithCanonicalOrdering(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a2", "sha256:bb", "bafy-a1", "sha256:aa"}, RenderOptions{})
	if _, err := CanonicalizeCROF(out); err != nil {
		t.Fatalf("CanonicalizeCROF: %v", err)
	}

	text := string(out)
	inputsStart := strings.Index(text, "\nINPUTS\n")
	if inputsStart < 0 {
		t.Fatalf("missing INPUTS section")
	}
	inputsStart += len("\nINPUTS\n")
	inputsEnd := strings.Index(text[inputsStart:], "\n\n")
	if inputsEnd < 0 {
		t.Fatalf("missing INPUTS terminator")
	}
	inputsBody := text[inputsStart : inputsStart+inputsEnd]
	lines := strings.Split(inputsBody, "\n")
	// Trust-Policy-CID is first line; rest must be Attestation-CID sorted then Input-Hash sorted.
	if len(lines) < 1 || !strings.HasPrefix(lines[0], "Trust-Policy-CID: ") {
		t.Fatalf("unexpected INPUTS first line: %q", lines[0])
	}
	got := strings.Join(lines[1:], "\n") + "\n"
	want := strings.Join([]string{
		"Attestation-CID: bafy-a1",
		"Attestation-CID: bafy-a2",
		"Input-Hash: sha256:aa",
		"Input-Hash: sha256:bb",
	}, "\n") + "\n"
	if got != want {
		t.Fatalf("unexpected INPUTS ordering\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestCanonicalizeCROF_RejectsAttestationCIDAfterInputHash(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1", "sha256:aa"}, RenderOptions{})
	text := string(out)
	text = strings.ReplaceAll(text,
		"Attestation-CID: bafy-a1\nInput-Hash: sha256:aa\n",
		"Input-Hash: sha256:aa\nAttestation-CID: bafy-a1\n",
	)
	if _, err := CanonicalizeCROF([]byte(text)); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}

func TestCanonicalizeCROF_RejectsUnsortedInputHashes(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"sha256:aa", "sha256:bb"}, RenderOptions{})
	text := string(out)
	text = strings.ReplaceAll(text,
		"Input-Hash: sha256:aa\nInput-Hash: sha256:bb\n",
		"Input-Hash: sha256:bb\nInput-Hash: sha256:aa\n",
	)
	if _, err := CanonicalizeCROF([]byte(text)); err == nil {
		t.Fatalf("expected CanonicalizeCROF error")
	}
}
