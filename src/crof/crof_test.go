package crof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"xdao.co/catf/resolver"
)

func TestRender_AlwaysHasAllSections(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateUnresolved, Confidence: resolver.ConfidenceUndefined}
	out := string(Render(res, "sha256:policy", []string{"sha256:a1"}, RenderOptions{}))

	if !strings.HasPrefix(out, Preamble+"\n") {
		t.Fatalf("expected CROF preamble")
	}
	if !strings.Contains(out, Postamble+"\n") {
		t.Fatalf("expected CROF postamble")
	}
	for _, sec := range []string{"META", "INPUTS", "RESULT", "PATHS", "FORKS", "EXCLUSIONS", "VERDICTS", "CRYPTO"} {
		if !strings.Contains(out, "\n"+sec+"\n") {
			t.Fatalf("expected CROF to contain section %s", sec)
		}
	}
}

func TestRender_SignsWhenKeyProvided(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x5A
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resolverKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	out := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverKey: resolverKey, PrivateKey: priv})
	text := string(out)
	if !strings.Contains(text, "\nCRYPTO\n") {
		t.Fatalf("missing CRYPTO section")
	}
	if !strings.Contains(text, "Resolver-Key: "+resolverKey+"\n") {
		t.Fatalf("missing Resolver-Key")
	}
	if !strings.Contains(text, "Signature: ") {
		t.Fatalf("missing Signature line")
	}

	scope, err := crofSignatureScope(out)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	digest := sha256.Sum256(scope)
	// Extract signature value.
	var sigB64 string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Signature: ") {
			sigB64 = strings.TrimPrefix(line, "Signature: ")
			break
		}
	}
	if sigB64 == "" {
		t.Fatalf("signature empty")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		t.Fatalf("signature did not verify")
	}
}
