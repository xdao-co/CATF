package catf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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
// For v1 core, this expects Issuer-Key formatted as: ed25519:<base64>.
func (c *CATF) IssuerPublicKeyBytes() ([]byte, error) {
	issuer := c.IssuerKey()
	if issuer == "" {
		return nil, errors.New("missing Issuer-Key")
	}
	const prefix = "ed25519:"
	if !strings.HasPrefix(issuer, prefix) {
		return nil, fmt.Errorf("unsupported issuer key encoding: %q", issuer)
	}
	enc := strings.TrimPrefix(issuer, prefix)
	pub, err := decodeBase64(enc)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer key base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length: %d", len(pub))
	}
	return pub, nil
}

func (c *CATF) SignatureBytes() ([]byte, error) {
	s := c.Signature()
	if s == "" {
		return nil, errors.New("missing Signature")
	}
	sig, err := decodeBase64(s)
	if err != nil {
		return nil, fmt.Errorf("invalid signature base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid ed25519 signature length: %d", len(sig))
	}
	return sig, nil
}

// Verify verifies the CATF signature according to v1 rules.
// For Signature-Alg=ed25519 and Hash-Alg=sha256, the signed message is sha256(Signed).
func (c *CATF) Verify() error {
	if c.SignatureAlg() == "" {
		return errors.New("missing Signature-Alg")
	}
	if c.HashAlg() == "" {
		return errors.New("missing Hash-Alg")
	}

	if c.SignatureAlg() != "ed25519" {
		return fmt.Errorf("unsupported Signature-Alg: %s", c.SignatureAlg())
	}
	if c.HashAlg() != "sha256" {
		return fmt.Errorf("unsupported Hash-Alg: %s", c.HashAlg())
	}

	pub, err := c.IssuerPublicKeyBytes()
	if err != nil {
		return err
	}
	sig, err := c.SignatureBytes()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(c.Signed)
	if !ed25519.Verify(ed25519.PublicKey(pub), digest[:], sig) {
		return errors.New("signature invalid")
	}
	return nil
}

func decodeBase64(s string) ([]byte, error) {
	// Prefer standard padded encoding, but accept raw encoding too.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// SignEd25519SHA256 returns a base64 signature over sha256(message).
func SignEd25519SHA256(message []byte, privateKey ed25519.PrivateKey) string {
	digest := sha256.Sum256(message)
	sig := ed25519.Sign(privateKey, digest[:])
	return base64.StdEncoding.EncodeToString(sig)
}
