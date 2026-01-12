package catf

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConformanceVectors_CATF_CanonicalAndCID(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "catf", "xdao-catf-1")

	attPath := filepath.Join(root, "authorship_1.catf")
	cidPath := filepath.Join(root, "authorship_1.cid")

	attBytes, err := os.ReadFile(attPath)
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	wantCIDBytes, err := os.ReadFile(cidPath)
	if err != nil {
		t.Fatalf("read cid: %v", err)
	}
	wantCID := strings.TrimSpace(string(wantCIDBytes))
	if wantCID == "" {
		t.Fatalf("empty expected CID")
	}

	parsed, err := Parse(attBytes)
	if err != nil {
		t.Fatalf("Parse(canonical): %v", err)
	}

	// Canonicalization idempotence (bytes must remain unchanged).
	canon, err := CanonicalizeCATF(attBytes)
	if err != nil {
		t.Fatalf("CanonicalizeCATF(canonical): %v", err)
	}
	if !bytes.Equal(canon, attBytes) {
		t.Fatalf("canonical bytes mismatch")
	}

	// Canonical equivalence: re-render from parsed structure yields identical bytes.
	rendered, err := Render(Document{
		Meta:    parsed.Sections["META"].Pairs,
		Subject: parsed.Sections["SUBJECT"].Pairs,
		Claims:  parsed.Sections["CLAIMS"].Pairs,
		Crypto:  parsed.Sections["CRYPTO"].Pairs,
	})
	if err != nil {
		t.Fatalf("Render(parsed): %v", err)
	}
	if !bytes.Equal(rendered, attBytes) {
		t.Fatalf("re-rendered bytes mismatch")
	}

	cid, err := parsed.CID()
	if err != nil {
		t.Fatalf("CID(): %v", err)
	}
	if cid != wantCID {
		t.Fatalf("CID mismatch: got %s want %s", cid, wantCID)
	}
}

func TestConformanceVectors_CATF_NonCanonicalRejected(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "catf", "xdao-catf-1")
	files := []string{
		"authorship_1.noncanonical_crlf.catf",
		"authorship_1.noncanonical_double_space.catf",
	}
	for _, name := range files {
		path := filepath.Join(root, name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := Parse(b); err == nil {
			t.Fatalf("expected Parse to reject non-canonical input: %s", name)
		}
	}
}
