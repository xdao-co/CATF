package crof

import (
	"fmt"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/resolver"
)

// CID returns an IPFS-compatible CIDv1 (raw + sha2-256) for CROF bytes.
//
// CROF evidence must be canonical before CID derivation. If input is not
// canonical, this function fails.
func CID(crofBytes []byte) (string, error) {
	canon, err := CanonicalizeCROF(crofBytes)
	if err != nil {
		return "", fmt.Errorf("canonical CROF required: %w", err)
	}
	return cidutil.CIDv1RawSHA256(canon), nil
}

// RenderWithCID renders CROF and returns its CID.
func RenderWithCID(res *resolver.Resolution, trustPolicyCID string, attestationCIDs []string, opts RenderOptions) ([]byte, string, error) {
	b := Render(res, trustPolicyCID, attestationCIDs, opts)
	cid, err := CID(b)
	if err != nil {
		return nil, "", err
	}
	return b, cid, nil
}
