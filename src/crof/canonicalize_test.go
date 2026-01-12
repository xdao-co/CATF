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
