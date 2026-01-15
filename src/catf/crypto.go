package catf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"
)

func (c *CATF) SignatureAlg() string {
	if sec, ok := c.Sections["CRYPTO"]; ok {
		return sec.Pairs["Signature-Alg"]
	}
	return ""
}

func (c *CATF) HashAlg() string {
	if sec, ok := c.Sections["CRYPTO"]; ok {
		return sec.Pairs["Hash-Alg"]
	}
	return ""
}

func (c *CATF) Signature() string {
	if sec, ok := c.Sections["CRYPTO"]; ok {
		return sec.Pairs["Signature"]
	}
	return ""
}

// IssuerPublicKeyBytes returns the raw public key bytes for the issuer.
// Supported encodings:
// - ed25519:<base64>
// - dilithium3:<base64>
func (c *CATF) IssuerPublicKeyBytes() ([]byte, error) {
	issuer := c.IssuerKey()
	if issuer == "" {
		return nil, newError(KindCrypto, "CATF-CRYPTO-103", "missing Issuer-Key")
	}

	alg, enc, ok := strings.Cut(issuer, ":")
	if !ok {
		return nil, newError(KindCrypto, "CATF-CRYPTO-111", "invalid Issuer-Key encoding")
	}
	pub, err := decodeBase64(enc)
	if err != nil {
		return nil, wrapError(KindCrypto, "CATF-CRYPTO-113", "invalid issuer key base64", err)
	}

	switch alg {
	case "ed25519":
		if len(pub) != ed25519.PublicKeySize {
			return nil, newError(KindCrypto, "CATF-CRYPTO-114", "invalid ed25519 public key length")
		}
		return pub, nil
	case "dilithium3":
		var pk mode3.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return nil, wrapError(KindCrypto, "CATF-CRYPTO-115", "invalid dilithium3 public key", err)
		}
		return pub, nil
	default:
		return nil, newError(KindCrypto, "CATF-CRYPTO-112", "unsupported issuer key encoding")
	}
}

func (c *CATF) SignatureBytes() ([]byte, error) {
	s := c.Signature()
	if s == "" {
		return nil, newError(KindCrypto, "CATF-CRYPTO-104", "missing Signature")
	}
	sig, err := decodeBase64(s)
	if err != nil {
		return nil, wrapError(KindCrypto, "CATF-CRYPTO-131", "invalid signature base64", err)
	}
	if c.SignatureAlg() == "" {
		return nil, newError(KindCrypto, "CATF-CRYPTO-101", "missing Signature-Alg")
	}
	// Validate signature lengths where we can (some schemes have fixed sizes).
	switch c.SignatureAlg() {
	case "ed25519":
		if len(sig) != ed25519.SignatureSize {
			return nil, newError(KindCrypto, "CATF-CRYPTO-132", "invalid ed25519 signature length")
		}
	case "dilithium3":
		if len(sig) != mode3.SignatureSize {
			return nil, newError(KindCrypto, "CATF-CRYPTO-133", "invalid dilithium3 signature length")
		}
	}
	return sig, nil
}

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
		return nil, newError(KindCrypto, "CATF-CRYPTO-201", "unsupported Hash-Alg")
	}
}

// Verify verifies the CATF signature according to v1 rules.
// For Signature-Alg=ed25519 and Hash-Alg=sha256, the signed message is sha256(Signed).
// This library also supports:
// - Hash-Alg: sha512, sha3-256
// - Signature-Alg: dilithium3 (post-quantum)
func (c *CATF) Verify() error {
	if c == nil {
		return newError(KindCrypto, "CATF-CRYPTO-001", "nil CATF")
	}
	// Re-parse the receiver bytes to enforce canonicalization cannot be bypassed
	// via a manually-constructed CATF or mutated fields.
	parsed, err := Parse(c.raw)
	if err != nil {
		return err
	}
	// Use the parsed view for all cryptographic fields.
	c = parsed

	if c.SignatureAlg() == "" {
		return newError(KindCrypto, "CATF-CRYPTO-101", "missing Signature-Alg")
	}
	if c.HashAlg() == "" {
		return newError(KindCrypto, "CATF-CRYPTO-102", "missing Hash-Alg")
	}

	issuer := c.IssuerKey()
	if issuer == "" {
		return newError(KindCrypto, "CATF-CRYPTO-103", "missing Issuer-Key")
	}
	issuerAlg, _, ok := strings.Cut(issuer, ":")
	if !ok {
		return newError(KindCrypto, "CATF-CRYPTO-111", "invalid Issuer-Key encoding")
	}
	if issuerAlg != c.SignatureAlg() {
		return newError(KindCrypto, "CATF-CRYPTO-121", "Issuer-Key alg does not match Signature-Alg")
	}

	pub, err := c.IssuerPublicKeyBytes()
	if err != nil {
		return err
	}
	sig, err := c.SignatureBytes()
	if err != nil {
		return err
	}
	signedScope, err := signedScopeFromCanonical(c.raw)
	if err != nil {
		return err
	}
	digest, err := digestFor(c.HashAlg(), signedScope)
	if err != nil {
		return err
	}

	switch c.SignatureAlg() {
	case "ed25519":
		if !ed25519.Verify(ed25519.PublicKey(pub), digest, sig) {
			return newError(KindCrypto, "CATF-CRYPTO-401", "signature invalid")
		}
		return nil
	case "dilithium3":
		var pk mode3.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return wrapError(KindCrypto, "CATF-CRYPTO-115", "invalid dilithium3 public key", err)
		}
		if !mode3.Verify(&pk, digest, sig) {
			return newError(KindCrypto, "CATF-CRYPTO-401", "signature invalid")
		}
		return nil
	default:
		return newError(KindCrypto, "CATF-CRYPTO-301", "unsupported Signature-Alg")
	}
}

func decodeBase64(s string) ([]byte, error) {
	// Prefer standard padded encoding, but accept raw encoding too.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// SignEd25519SHA256 returns a base64 signature over sha256(message).
//
// Deprecated: use `keys.SignEd25519SHA256`.
func SignEd25519SHA256(message []byte, privateKey ed25519.PrivateKey) string {
	digest := sha256.Sum256(message)
	sig := ed25519.Sign(privateKey, digest[:])
	return base64.StdEncoding.EncodeToString(sig)
}

// SignDilithium3 returns a base64 dilithium3 signature over hash(message).
// hashAlg must be one of: sha256, sha512, sha3-256.
//
// Deprecated: use `keys.SignDilithium3`.
func SignDilithium3(message []byte, hashAlg string, privateKey *mode3.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", newError(KindCrypto, "CATF-CRYPTO-501", "missing private key")
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
//
// Deprecated: use `keys.GenerateDilithium3Keypair`.
func GenerateDilithium3Keypair(rand io.Reader) (*mode3.PublicKey, *mode3.PrivateKey, error) {
	return mode3.GenerateKey(rand)
}
