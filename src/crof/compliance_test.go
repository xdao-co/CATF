package crof

import (
	"testing"
	"time"

	"xdao.co/catf/compliance"
	"xdao.co/catf/resolver"
)

func TestRenderWithCompliance_StrictRejectsAmbiguityAndResolvedAt(t *testing.T) {
	res := &resolver.Resolution{
		SubjectCID: "bafy-doc-1",
		State:      resolver.StateForked,
		Confidence: resolver.ConfidenceMedium,
		Forks:      []resolver.Fork{{ID: "fork-1", ConflictingPath: []string{"path-1", "path-2"}}},
		Exclusions: []resolver.Exclusion{{CID: "bafy-a1", Reason: "Issuer not trusted"}},
	}

	_, err := RenderWithCompliance(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"}, compliance.Strict)
	if err == nil {
		t.Fatalf("expected strict mode error")
	}

	res.State = resolver.StateResolved
	res.Forks = nil
	res.Exclusions = nil
	_, err = RenderWithCompliance(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference", ResolvedAt: time.Unix(1, 0).UTC()}, compliance.Strict)
	if err == nil {
		t.Fatalf("expected strict mode error for Resolved-At")
	}
}

func TestRenderWithCompliance_StrictRequiresResolverID(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	_, err := RenderWithCompliance(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{}, compliance.Strict)
	if err == nil {
		t.Fatalf("expected strict mode error")
	}
}

func TestRenderWithCompliance_PermissiveAllowsResolvedAt(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b, err := RenderWithCompliance(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolvedAt: time.Unix(1, 0).UTC()}, compliance.Permissive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("expected CROF bytes")
	}
}
