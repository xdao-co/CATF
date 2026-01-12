package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// IssuerKeyFromPublicKey encodes an Ed25519 public key into the CATF issuer-key string.
func IssuerKeyFromPublicKey(pub ed25519.PublicKey) (string, error) {
	if l := len(pub); l != ed25519.PublicKeySize {
		return "", fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, l)
	}
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub), nil
}
