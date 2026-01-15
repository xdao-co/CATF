package storage

import "github.com/ipfs/go-cid"

// CAS is a minimal content-addressable storage interface.
//
// Contract:
// - Put MUST be idempotent.
// - Stored objects MUST be immutable.
// - CIDs MUST be derived from the bytes written (callers are responsible for supplying canonical bytes).
// - Get MUST return ErrNotFound when the CID is absent.
type CAS interface {
	Put(bytes []byte) (cid.Cid, error)
	Get(id cid.Cid) ([]byte, error)
	Has(id cid.Cid) bool
}
