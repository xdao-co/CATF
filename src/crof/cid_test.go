package crof

import (
	"testing"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/resolver"
)

func TestCID_MatchesCIDv1RawSHA256(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	got, err := CID(b)
	if err != nil {
		t.Fatalf("CID failed: %v", err)
	}
	want := cidutil.CIDv1RawSHA256(b)
	if got != want {
		t.Fatalf("CID mismatch: got %q want %q", got, want)
	}
}

func TestRenderWithCID_Stable(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	b1, cid1, err := RenderWithCID(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderWithCID failed: %v", err)
	}
	b2, cid2, err := RenderWithCID(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderWithCID failed: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("expected identical CROF bytes")
	}
	if cid1 != cid2 {
		t.Fatalf("expected identical CIDs")
	}
}
