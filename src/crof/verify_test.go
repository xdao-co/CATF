package crof

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"xdao.co/catf/resolver"
)

func TestVerifySignature_UnsignedReturnsFalse(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	ok, err := VerifySignature(out)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if ok {
		t.Fatalf("expected unsigned CROF to return ok=false")
	}
}

func TestVerifySignature_SignedVerifies(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x5A
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})

	ok, err := VerifySignature(out)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true")
	}
}

func TestVerifySignature_RejectsNonCanonicalBytes(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x11
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})

	bad := []byte(strings.ReplaceAll(string(out), "\n", "\r\n"))
	ok, err := VerifySignature(bad)
	if err == nil {
		t.Fatalf("expected error")
	}
	if ok {
		t.Fatalf("expected ok=false")
	}
}

func TestVerifySignature_RejectsIncompleteCryptoSection(t *testing.T) {
	// Start from a valid signed CROF then corrupt the CRYPTO section to be partially populated.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x22
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})

	// Remove Resolver-Key line to make CRYPTO incomplete.
	bad := []byte(strings.Replace(string(out), "Resolver-Key: "+resolverKey+"\n", "", 1))
	_, err := VerifySignature(bad)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestVerifySignature_RejectsMultipleSignatureLines(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x33
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})

	// Duplicate Signature line inside CRYPTO section. This should be rejected.
	text := string(out)
	idx := strings.Index(text, "Signature: ")
	if idx < 0 {
		t.Fatalf("missing Signature line in signed output")
	}
	lineEnd := strings.Index(text[idx:], "\n")
	if lineEnd < 0 {
		t.Fatalf("malformed output")
	}
	sigLine := text[idx : idx+lineEnd+1]
	bad := []byte(text[:idx] + sigLine + text[idx:])

	_, err := VerifySignature(bad)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRenderDocument_ProducesCanonicalBytesAndStableCID(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	doc, err := RenderDocument(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderDocument: %v", err)
	}
	if _, err := CanonicalizeCROF(doc.Bytes); err != nil {
		t.Fatalf("document bytes not canonical: %v", err)
	}
	cid2, err := CID(doc.Bytes)
	if err != nil {
		t.Fatalf("CID: %v", err)
	}
	if doc.CID != cid2 {
		t.Fatalf("CID mismatch: %s vs %s", doc.CID, cid2)
	}
}
