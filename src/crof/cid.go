package crof

import (
	"xdao.co/catf/cidutil"
	"xdao.co/catf/resolver"
)

// CID returns an IPFS-compatible CIDv1 (raw + sha2-256) for CROF bytes.
//
// For protocol safety, callers should only compute CIDs over canonical CROF.
// Output produced by Render is canonical by construction.
func CID(crofBytes []byte) string {
	return cidutil.CIDv1RawSHA256(crofBytes)
}

// RenderWithCID renders CROF and returns its CID.
func RenderWithCID(res *resolver.Resolution, trustPolicyCID string, attestationCIDs []string, opts RenderOptions) ([]byte, string) {
	b := Render(res, trustPolicyCID, attestationCIDs, opts)
	return b, CID(b)
}
