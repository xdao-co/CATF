package crof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// VerifySignature verifies the CROF CRYPTO signature, if present.
//
// Returns (true, nil) if the document is signed and the signature verifies.
// Returns (false, nil) if the document is not signed (empty CRYPTO section).
// Returns (false, err) for malformed, non-canonical, or invalid signatures.
//
// Verification requires canonical CROF bytes; non-canonical inputs are rejected.
func VerifySignature(crofBytes []byte) (bool, error) {
	canon, err := CanonicalizeCROF(crofBytes)
	if err != nil {
		return false, fmt.Errorf("canonical CROF required: %w", err)
	}

	cryptoLines, err := sectionLines(canon, "CRYPTO")
	if err != nil {
		return false, err
	}
	if len(cryptoLines) == 0 {
		return false, nil
	}

	sigAlg, hasAlg, err := singleFieldFromSection(canon, "CRYPTO", "Signature-Alg")
	if err != nil {
		return false, err
	}
	hashAlg, hasHash, err := singleFieldFromSection(canon, "CRYPTO", "Hash-Alg")
	if err != nil {
		return false, err
	}
	resolverKey, hasKey, err := singleFieldFromSection(canon, "CRYPTO", "Resolver-Key")
	if err != nil {
		return false, err
	}
	sigB64, hasSig, err := singleFieldFromSection(canon, "CRYPTO", "Signature")
	if err != nil {
		return false, err
	}

	// Partially populated CRYPTO is invalid.
	if !(hasKey && hasAlg && hasHash && hasSig) {
		return false, errors.New("CRYPTO: incomplete signature fields")
	}
	if sigAlg != "ed25519" {
		return false, fmt.Errorf("CRYPTO: unsupported Signature-Alg %q", sigAlg)
	}
	if hashAlg != "sha256" {
		return false, fmt.Errorf("CRYPTO: unsupported Hash-Alg %q", hashAlg)
	}

	pub, err := parseEd25519PublicKey(resolverKey)
	if err != nil {
		return false, err
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("CRYPTO: invalid Signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, errors.New("CRYPTO: invalid Signature length")
	}

	scope, err := crofSignatureScope(canon)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(scope)
	if !ed25519.Verify(pub, digest[:], sig) {
		return false, errors.New("CRYPTO: signature did not verify")
	}
	return true, nil
}

func parseEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("CRYPTO: unsupported Resolver-Key %q", s)
	}
	b64 := strings.TrimPrefix(s, prefix)
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("CRYPTO: invalid Resolver-Key encoding: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("CRYPTO: invalid Resolver-Key length")
	}
	return ed25519.PublicKey(b), nil
}
