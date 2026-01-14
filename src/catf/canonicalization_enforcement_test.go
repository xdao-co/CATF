package catf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRender_IsDeterministicAcrossMapInsertionOrder(t *testing.T) {
	// Same semantic document, different map insertion order.
	m1 := map[string]string{}
	m1["Version"] = "1"
	m1["Spec"] = "xdao-catf-1"

	m2 := map[string]string{}
	m2["Spec"] = "xdao-catf-1"
	m2["Version"] = "1"

	d1 := Document{
		Meta:    m1,
		Subject: map[string]string{"CID": "bafy-doc-1", "Description": "d"},
		Claims:  map[string]string{"Type": "authorship", "Role": "author"},
		Crypto:  map[string]string{"Hash-Alg": "sha256", "Issuer-Key": "ed25519:AA==", "Signature-Alg": "ed25519", "Signature": "AA=="},
	}
	d2 := Document{
		Meta:    m2,
		Subject: map[string]string{"Description": "d", "CID": "bafy-doc-1"},
		Claims:  map[string]string{"Role": "author", "Type": "authorship"},
		Crypto:  map[string]string{"Signature": "AA==", "Signature-Alg": "ed25519", "Issuer-Key": "ed25519:AA==", "Hash-Alg": "sha256"},
	}

	b1, err := Render(d1)
	if err != nil {
		t.Fatalf("Render(d1): %v", err)
	}
	b2, err := Render(d2)
	if err != nil {
		t.Fatalf("Render(d2): %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("Render output must be byte-identical for equivalent Documents")
	}

	// Repeated runs must stay stable.
	for i := 0; i < 25; i++ {
		bi, err := Render(d1)
		if err != nil {
			t.Fatalf("Render(d1) run %d: %v", i, err)
		}
		if !bytes.Equal(b1, bi) {
			t.Fatalf("Render output changed across runs")
		}
	}
}

func TestCanonicalizeCATF_RejectsNonCanonicalInput(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "catf", "xdao-catf-1")

	canonicalPath := filepath.Join(root, "authorship_1.catf")
	crlfPath := filepath.Join(root, "authorship_1.noncanonical_crlf.catf")
	doubleSpacePath := filepath.Join(root, "authorship_1.noncanonical_double_space.catf")

	canonicalBytes, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical vector: %v", err)
	}
	crlfBytes, err := os.ReadFile(crlfPath)
	if err != nil {
		t.Fatalf("read CRLF vector: %v", err)
	}
	doubleSpaceBytes, err := os.ReadFile(doubleSpacePath)
	if err != nil {
		t.Fatalf("read double-space vector: %v", err)
	}

	// Canonical input is accepted and preserved.
	canon, err := CanonicalizeCATF(canonicalBytes)
	if err != nil {
		t.Fatalf("CanonicalizeCATF(canonical): %v", err)
	}
	if !bytes.Equal(canon, canonicalBytes) {
		t.Fatalf("CanonicalizeCATF must be identity on canonical bytes")
	}

	// Non-canonical variants must fail loudly.
	if _, err := CanonicalizeCATF(crlfBytes); err == nil {
		t.Fatalf("expected CanonicalizeCATF(CRLF) to reject non-canonical bytes")
	}
	if _, err := CanonicalizeCATF(doubleSpaceBytes); err == nil {
		t.Fatalf("expected CanonicalizeCATF(double-space) to reject non-canonical bytes")
	}
	if _, err := CanonicalizeCATF(append(append([]byte(nil), canonicalBytes...), '\n')); err == nil {
		t.Fatalf("expected CanonicalizeCATF(trailing newline) to reject non-canonical bytes")
	}
}
