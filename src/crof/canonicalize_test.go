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
