package catf

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func mustKeypair(t *testing.T, seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func issuerKey(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

func validCATFBytes(t *testing.T) []byte {
	t.Helper()
	pub, priv := mustKeypair(t, 0xA1)

	// First render with empty Signature to compute Signed scope.
	doc := Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": "bafy-doc-1", "Description": "Scientific paper draft"},
		Claims:  map[string]string{"Role": "author", "Type": "authorship"},
		Crypto: map[string]string{
			"Hash-Alg":      "sha256",
			"Issuer-Key":    issuerKey(pub),
			"Signature":     "0",
			"Signature-Alg": "ed25519",
		},
	}
	pre, err := Render(doc)
	if err != nil {
		t.Fatalf("render pre: %v", err)
	}
	parsed, err := Parse(pre)
	if err != nil {
		t.Fatalf("parse pre: %v", err)
	}

	doc.Crypto["Signature"] = SignEd25519SHA256(parsed.SignedBytes(), priv)
	out, err := Render(doc)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	final, err := Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := final.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return out
}

func TestParseValidCATF(t *testing.T) {
	catf, err := Parse(validCATFBytes(t))
	if err != nil {
		t.Fatalf("expected valid CATF, got error: %v", err)
	}
	if catf.Sections["CLAIMS"].Pairs["Type"] != "authorship" {
		t.Errorf("expected Type=authorship, got %v", catf.Sections["CLAIMS"].Pairs["Type"])
	}
	if len(catf.SignedBytes()) == 0 {
		t.Fatalf("expected non-empty signed bytes")
	}
}

func TestParseInvalidCATF_MissingPreamble(t *testing.T) {
	_, err := Parse([]byte("META\nVersion: 1\n"))
	if err == nil {
		t.Error("expected error for missing preamble")
	}
}

func TestParseInvalidCATF_TrailingWhitespace(t *testing.T) {
	good := string(validCATFBytes(t))
	bad := good[:len(good)-1] + " "
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Error("expected error for trailing whitespace")
	}
}

func TestParseInvalidCATF_UnsortedKeys(t *testing.T) {
	bad := `-----BEGIN XDAO ATTESTATION-----
META
Version: 1
Spec: xdao-catf-1

SUBJECT
CID: bafy-doc-1
Description: Scientific paper draft

CLAIMS
Type: authorship
Role: author

CRYPTO
Issuer-Key: ed25519:AUTHOR_KEY
Signature-Alg: ed25519
Hash-Alg: sha256
Signature: SIG_A1
-----END XDAO ATTESTATION-----`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected error for unsorted keys")
	}
}

func TestCATF_Verify_RejectsMutatedSignedScope(t *testing.T) {
	attBytes := validCATFBytes(t)
	a, err := Parse(attBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("Verify (baseline): %v", err)
	}

	// Attempt to bypass signature scope by mutating the Signed bytes on the parsed object.
	// Verify must be derived from canonical bytes, not caller-controlled fields.
	signed := a.SignedBytes()
	if len(signed) == 0 {
		t.Fatalf("expected non-empty signed scope")
	}
	signed[0] ^= 0x01
	// Mutating the caller's copy must not impact the parsed attestation.
	if err := a.Verify(); err != nil {
		t.Fatalf("Verify should remain stable after mutating SignedBytes() copy: %v", err)
	}
}

func TestCATF_CID_RejectsMutatedRawBytes(t *testing.T) {
	attBytes := validCATFBytes(t)
	a, err := Parse(attBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := a.CID(); err != nil {
		t.Fatalf("CID (baseline): %v", err)
	}

	// Attempt to bypass canonicalization by mutating Raw bytes after Parse.
	raw := a.CanonicalBytes()
	if len(raw) == 0 {
		t.Fatalf("expected non-empty raw bytes")
	}
	raw[0] ^= 0x01
	// Mutating the caller's copy must not impact the parsed attestation.
	if _, err := a.CID(); err != nil {
		t.Fatalf("CID should remain stable after mutating CanonicalBytes() copy: %v", err)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("Verify should remain stable after mutating CanonicalBytes() copy: %v", err)
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	good := validCATFBytes(t)
	text := string(good)
	text = strings.Replace(text, "Signature: ", "Signature: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", 1)
	a, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := a.Verify(); err == nil {
		t.Fatalf("expected verify error")
	}
}

func TestParseInvalidCATF_ExtraBlankLineBetweenSections(t *testing.T) {
	good := string(validCATFBytes(t))
	bad := strings.Replace(good, "\n\nSUBJECT\n", "\n\n\nSUBJECT\n", 1)
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatalf("expected error for extra blank line between sections")
	}
}

func TestParseInvalidCATF_MissingBlankLineBetweenSections(t *testing.T) {
	good := string(validCATFBytes(t))
	bad := strings.Replace(good, "\n\nSUBJECT\n", "\nSUBJECT\n", 1)
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatalf("expected error for missing blank line between sections")
	}
}

func TestParseInvalidCATF_DoubleSpaceAfterColon(t *testing.T) {
	good := string(validCATFBytes(t))
	bad := strings.Replace(good, "Spec: xdao-catf-1", "Spec:  xdao-catf-1", 1)
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatalf("expected error for non-canonical spacing after colon")
	}
}

func TestParseInvalidCATF_NonUTF8(t *testing.T) {
	good := validCATFBytes(t)
	bad := append([]byte(nil), good...)
	bad[10] = 0xFF
	_, err := Parse(bad)
	if err == nil {
		t.Fatalf("expected error for non-UTF8 input")
	}
}

func TestParseInvalidCATF_TrailingNewline(t *testing.T) {
	good := validCATFBytes(t)
	bad := append(append([]byte(nil), good...), '\n')
	_, err := Parse(bad)
	if err == nil {
		t.Fatalf("expected error for trailing newline")
	}
}
