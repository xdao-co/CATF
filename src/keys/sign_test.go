package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

type deterministicReader struct{ b byte }

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func TestSignEd25519SHA256_Verifies(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	msg := []byte("hello")
	sigB64 := SignEd25519SHA256(msg, priv)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	digest := sha256.Sum256(msg)
	if !ed25519.Verify(pub, digest[:], sig) {
		t.Fatalf("signature did not verify")
	}
}

func TestSignDilithium3_Verifies_SHA3_256(t *testing.T) {
	pk, sk, err := GenerateDilithium3Keypair(io.Reader(&deterministicReader{}))
	if err != nil {
		t.Fatalf("GenerateDilithium3Keypair: %v", err)
	}

	msg := []byte("hello")
	sigB64, err := SignDilithium3(msg, "sha3-256", sk)
	if err != nil {
		t.Fatalf("SignDilithium3: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != mode3.SignatureSize {
		t.Fatalf("unexpected signature size: got %d want %d", len(sig), mode3.SignatureSize)
	}

	digest, err := digestFor("sha3-256", msg)
	if err != nil {
		t.Fatalf("digestFor: %v", err)
	}
	if !mode3.Verify(pk, digest, sig) {
		t.Fatalf("signature did not verify")
	}
}
