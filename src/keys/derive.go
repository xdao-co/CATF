package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// GenerateIssuerKeyFromSeed returns the CATF issuer key string for an Ed25519 seed.
//
// Format matches the CLI's KMS-lite behavior: "ed25519:" + base64(pubkey).
func GenerateIssuerKeyFromSeed(seed []byte) string {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// DeriveRoleSeed deterministically derives a role-specific Ed25519 seed from a root seed.
//
// This mirrors the CLI derivation for compatibility.
func DeriveRoleSeed(rootSeed []byte, role string) ([]byte, error) {
	if len(rootSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("root seed must be %d bytes", ed25519.SeedSize)
	}
	if err := CheckRole(role); err != nil {
		return nil, err
	}

	h := sha256.New()
	_, _ = h.Write(rootSeed)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte("xdao-catf-kms-lite-v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte("role:"))
	_, _ = h.Write([]byte(role))
	sum := h.Sum(nil)
	if len(sum) < ed25519.SeedSize {
		return nil, errors.New("kdf output too short")
	}
	out := make([]byte, ed25519.SeedSize)
	copy(out, sum[:ed25519.SeedSize])
	return out, nil
}
