package crof

import (
	"xdao.co/catf/cidutil"
	"xdao.co/catf/resolver"
)

// Document is a first-class CROF evidence object.
//
// Bytes are canonical CROF bytes. CID is derived from Bytes.
//
// CROF is intentionally treated as a document (not ephemeral output) so it can be
// archived, inspected, and re-verified.
//
// Note: this is a lightweight wrapper; it does not add any trust semantics.
type Document struct {
	Bytes []byte
	CID   string
}

// NewDocumentFromBytes canonicalizes CROF bytes and computes the CROF CID.
func NewDocumentFromBytes(crofBytes []byte) (*Document, error) {
	canon, err := CanonicalizeCROF(crofBytes)
	if err != nil {
		return nil, err
	}
	return &Document{Bytes: canon, CID: cidutil.CIDv1RawSHA256(canon)}, nil
}

// RenderDocument renders CROF bytes from a resolver Resolution and returns a
// canonical Document (bytes + CID).
func RenderDocument(res *resolver.Resolution, trustPolicyCID string, attestationCIDs []string, opts RenderOptions) (*Document, error) {
	b := Render(res, trustPolicyCID, attestationCIDs, opts)
	return NewDocumentFromBytes(b)
}
