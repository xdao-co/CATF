package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeriveRoleSeedDeterministic(t *testing.T) {
	root := make([]byte, ed25519.SeedSize)
	for i := range root {
		root[i] = byte(i)
	}

	a, err := DeriveRoleSeed(root, "approver")
	if err != nil {
		t.Fatalf("DeriveRoleSeed: %v", err)
	}
	b, err := DeriveRoleSeed(root, "approver")
	if err != nil {
		t.Fatalf("DeriveRoleSeed: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("expected deterministic derivation")
	}

	c, err := DeriveRoleSeed(root, "issuer")
	if err != nil {
		t.Fatalf("DeriveRoleSeed: %v", err)
	}
	if string(a) == string(c) {
		t.Fatalf("expected different roles to derive different seeds")
	}
}

func TestGenerateIssuerKeyFromSeedFormat(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	issuerKey := GenerateIssuerKeyFromSeed(seed)
	if !strings.HasPrefix(issuerKey, "ed25519:") {
		t.Fatalf("expected ed25519 prefix, got %q", issuerKey)
	}
	b64 := strings.TrimPrefix(issuerKey, "ed25519:")
	pubBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("expected valid base64: %v", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("expected %d pubkey bytes, got %d", ed25519.PublicKeySize, len(pubBytes))
	}
}
