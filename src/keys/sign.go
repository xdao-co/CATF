package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"
)

func digestFor(hashAlg string, message []byte) ([]byte, error) {
	switch hashAlg {
	case "sha256":
		s := sha256.Sum256(message)
		return s[:], nil
	case "sha512":
		s := sha512.Sum512(message)
		return s[:], nil
	case "sha3-256":
		s := sha3.Sum256(message)
		return s[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %q", hashAlg)
	}
}

// SignEd25519SHA256 returns a base64 signature over sha256(message).
func SignEd25519SHA256(message []byte, privateKey ed25519.PrivateKey) string {
	digest := sha256.Sum256(message)
	sig := ed25519.Sign(privateKey, digest[:])
	return base64.StdEncoding.EncodeToString(sig)
}

// SignDilithium3 returns a base64 dilithium3 signature over hash(message).
// hashAlg must be one of: sha256, sha512, sha3-256.
func SignDilithium3(message []byte, hashAlg string, privateKey *mode3.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("missing private key")
	}
	digest, err := digestFor(hashAlg, message)
	if err != nil {
		return "", err
	}
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, digest, sig)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// GenerateDilithium3Keypair returns a new Dilithium3 keypair.
func GenerateDilithium3Keypair(rand io.Reader) (*mode3.PublicKey, *mode3.PrivateKey, error) {
	return mode3.GenerateKey(rand)
}
