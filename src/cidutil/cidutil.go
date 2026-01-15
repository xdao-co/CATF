package cidutil

import (
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// CIDv1RawSHA256 returns a CIDv1 string using the "raw" multicodec
// and a sha2-256 multihash.
func CIDv1RawSHA256(data []byte) string {
	sum, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		// multihash.Sum only errors for invalid inputs; with SHA2_256 and -1 length,
		// this should be unreachable.
		return ""
	}
	return cid.NewCidV1(cid.Raw, sum).String()
}

// CIDv1RawSHA256CID returns a CIDv1 (raw + sha2-256) derived from data.
func CIDv1RawSHA256CID(data []byte) (cid.Cid, error) {
	sum, err := multihash.Sum(data, multihash.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, sum), nil
}
