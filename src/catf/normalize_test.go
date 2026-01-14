package catf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeCATF_FromCRLFVector(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "catf", "xdao-catf-1")

	canonicalPath := filepath.Join(root, "authorship_1.catf")
	crlfPath := filepath.Join(root, "authorship_1.noncanonical_crlf.catf")

	canonicalBytes, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical vector: %v", err)
	}
	crlfBytes, err := os.ReadFile(crlfPath)
	if err != nil {
		t.Fatalf("read CRLF vector: %v", err)
	}

	if _, err := Parse(crlfBytes); err == nil {
		t.Fatalf("expected Parse(CRLF) to reject non-canonical bytes")
	}
	if _, err := NormalizeCATF(crlfBytes); err == nil {
		t.Fatalf("expected NormalizeCATF(CRLF) to reject non-canonical bytes")
	}
	// Canonical bytes remain accepted.
	if _, err := NormalizeCATF(canonicalBytes); err != nil {
		t.Fatalf("NormalizeCATF(canonical): %v", err)
	}
}

func TestNormalizeCATF_DoesNotFixDoubleSpaceDelimiter(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "catf", "xdao-catf-1")
	path := filepath.Join(root, "authorship_1.noncanonical_double_space.catf")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	if _, err := NormalizeCATF(b); err == nil {
		t.Fatalf("expected NormalizeCATF to reject double-space delimiter variant")
	}
}

func TestNormalizeCATF_SortsKeys(t *testing.T) {
	// Construct a syntactically valid CATF with keys intentionally out of order.
	nonCanonical := []byte(
		"-----BEGIN XDAO ATTESTATION-----\n" +
			"META\n" +
			"Version: 1\n" +
			"Spec: xdao-catf-1\n" +
			"\n" +
			"SUBJECT\n" +
			"Description: d\n" +
			"CID: bafy-doc-1\n" +
			"\n" +
			"CLAIMS\n" +
			"Type: authorship\n" +
			"Role: author\n" +
			"\n" +
			"CRYPTO\n" +
			"Signature: AA==\n" +
			"Signature-Alg: ed25519\n" +
			"Issuer-Key: ed25519:AA==\n" +
			"Hash-Alg: sha256\n" +
			"-----END XDAO ATTESTATION-----",
	)

	if _, err := Parse(nonCanonical); err == nil {
		t.Fatalf("expected Parse to reject unsorted keys")
	}

	expectedCanonical, err := Render(Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": "bafy-doc-1", "Description": "d"},
		Claims:  map[string]string{"Role": "author", "Type": "authorship"},
		Crypto: map[string]string{
			"Hash-Alg":      "sha256",
			"Issuer-Key":    "ed25519:AA==",
			"Signature":     "AA==",
			"Signature-Alg": "ed25519",
		},
	})
	if err != nil {
		t.Fatalf("Render(expected): %v", err)
	}

	if _, err := NormalizeCATF(nonCanonical); err == nil {
		t.Fatalf("expected NormalizeCATF to reject unsorted keys variant")
	}
	// Canonical bytes remain accepted.
	norm, err := NormalizeCATF(expectedCanonical)
	if err != nil {
		t.Fatalf("NormalizeCATF(expected canonical): %v", err)
	}
	if !bytes.Equal(norm, expectedCanonical) {
		t.Fatalf("NormalizeCATF should be identity on canonical bytes")
	}
}
