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
		Exclusions: []resolver.Exclusion{{CID: "", Reason: "CATF parse/canonicalization failed"}},
		Verdicts:   []resolver.Verdict{{CID: "", ExcludedReason: "CATF parse/canonicalization failed"}},
	}

	out := Render(res, "bafy-policy", nil, RenderOptions{})
	text := string(out)
	if strings.Contains(text, "Attestation-CID: ") {
		t.Fatalf("did not expect Attestation-CID line when CID is empty")
	}
	if !strings.Contains(text, "Reason: CATF parse/canonicalization failed") {
		t.Fatalf("expected exclusion reason to be rendered")
	}
	if !strings.Contains(text, "Excluded-Reason: CATF parse/canonicalization failed") {
		t.Fatalf("expected verdict excluded reason to be rendered")
	}
}
