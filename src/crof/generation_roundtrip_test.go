package crof

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"xdao.co/catf/catf"
	"xdao.co/catf/keys"
	"xdao.co/catf/resolver"
)

func TestResolverToCROF_RoundTripVerify_StableCID(t *testing.T) {
	subject := "bafy-doc-roundtrip-1"

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0xAA
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	issuer := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	policy := []byte("-----BEGIN XDAO TRUST POLICY-----\n" +
		"META\n" +
		"Version: 1\n" +
		"Spec: xdao-tpdl-1\n\n" +
		"TRUST\n" +
		"Key: " + issuer + "\n" +
		"Role: author\n\n" +
		"RULES\n" +
		"Require:\n" +
		"  Type: authorship\n" +
		"  Role: author\n\n" +
		"-----END XDAO TRUST POLICY-----\n")

	// Build one minimal canonical attestation.
	doc := catf.Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": subject, "Description": "roundtrip"},
		Claims:  map[string]string{"Type": "authorship", "Role": "author"},
		Crypto: map[string]string{
			"Hash-Alg":      "sha256",
			"Issuer-Key":    issuer,
			"Signature":     "0",
			"Signature-Alg": "ed25519",
		},
	}
	pre, err := catf.Render(doc)
	if err != nil {
		t.Fatalf("Render pre: %v", err)
	}
	parsed, err := catf.Parse(pre)
	if err != nil {
		t.Fatalf("Parse pre: %v", err)
	}
	doc.Crypto["Signature"] = keys.SignEd25519SHA256(parsed.SignedBytes(), priv)
	att, err := catf.Render(doc)
	if err != nil {
		t.Fatalf("Render final: %v", err)
	}
	finalAtt, err := catf.Parse(att)
	if err != nil {
		t.Fatalf("Parse final: %v", err)
	}

	res, err := resolver.Resolve([][]byte{att}, policy, subject)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	attCID, err := finalAtt.CID()
	if err != nil {
		t.Fatalf("att CID: %v", err)
	}
	policyCID := PolicyCID(policy)

	b1, cid1, err := RenderWithCID(res, policyCID, []string{attCID}, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderWithCID failed: %v", err)
	}
	b2, cid2, err := RenderWithCID(res, policyCID, []string{attCID}, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderWithCID failed: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("expected byte-identical CROF")
	}
	if cid1 != cid2 {
		t.Fatalf("expected stable CID")
	}

	ok, err := VerifySignature(b1)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if ok {
		t.Fatalf("expected unsigned CROF")
	}
}

func TestRenderSignedWithCID_Verifies(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x55
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	b, cid1, err := RenderSignedWithCID(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{
		ResolverKey: resolverKey,
		PrivateKey:  priv,
	})
	if err != nil {
		t.Fatalf("RenderSignedWithCID failed: %v", err)
	}
	ok, err := VerifySignature(b)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected signed CROF")
	}

	_, cid2, err := RenderSignedWithCID(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{
		ResolverKey: resolverKey,
		PrivateKey:  priv,
	})
	if err != nil {
		t.Fatalf("RenderSignedWithCID failed: %v", err)
	}
	if cid1 != cid2 {
		t.Fatalf("expected stable CID for signed CROF")
	}
}
