package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

const minimalPolicy = "-----BEGIN XDAO TRUST POLICY-----\n" +
	"META\n" +
	"Spec: xdao-tpdl-1\n" +
	"Version: 1\n" +
	"\n" +
	"TRUST\n" +
	"Key: ed25519:AA==\n" +
	"Role: author\n" +
	"\n" +
	"RULES\n" +
	"Require:\n" +
	"Type: authorship\n" +
	"Role: author\n" +
	"Quorum: 1\n" +
	"\n" +
	"-----END XDAO TRUST POLICY-----\n"

func TestResolve_DoesNotAssignCIDToNonCanonicalCATF(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "catf", "xdao-catf-1")
	crlfPath := filepath.Join(root, "authorship_1.noncanonical_crlf.catf")
	crlfBytes, err := os.ReadFile(crlfPath)
	if err != nil {
		t.Fatalf("read CRLF vector: %v", err)
	}

	res, err := Resolve([][]byte{crlfBytes}, []byte(minimalPolicy), "bafy-subject-does-not-matter")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Verdicts) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(res.Verdicts))
	}
	if res.Verdicts[0].CID != "" {
		t.Fatalf("expected empty CID for non-canonical CATF input")
	}
	if res.Verdicts[0].ExcludedReason == "" {
		t.Fatalf("expected exclusion reason")
	}
}
