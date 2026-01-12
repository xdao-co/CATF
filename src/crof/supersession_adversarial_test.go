package crof

import (
	"strings"
	"testing"

	"xdao.co/catf/resolver"
)

func TestValidateSupersession_RejectsNonCanonicalInputs(t *testing.T) {
	oldRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	oldBytes := Render(oldRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})
	oldCID, err := CID(oldBytes)
	if err != nil {
		t.Fatalf("CID(old): %v", err)
	}

	newRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	newBytes := Render(newRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference", SupersedesCROFCID: oldCID})

	// Introduce CRLF, which is non-canonical.
	newCRLF := []byte(strings.ReplaceAll(string(newBytes), "\n", "\r\n"))
	if err := ValidateSupersession(newCRLF, oldBytes); err == nil {
		t.Fatalf("expected non-canonical new CROF rejection")
	}

	oldCRLF := []byte(strings.ReplaceAll(string(oldBytes), "\n", "\r\n"))
	if err := ValidateSupersession(newBytes, oldCRLF); err == nil {
		t.Fatalf("expected non-canonical old CROF rejection")
	}
}
