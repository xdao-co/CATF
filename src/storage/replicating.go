package storage

import (
	"fmt"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
)

// NamedCAS associates a CAS with a stable backend name.
//
// This is used for multi-backend orchestration where callers need to retain
// per-backend metadata (e.g., for reporting or auditing).
type NamedCAS struct {
	Name string
	CAS  CAS
}

// ReplicatingCAS writes to all configured backends.
//
// Reads fall back in order. Writes go to all backends and require all returned
// CIDs to match (otherwise ErrCIDMismatch is returned).
//
// Use PutAll when you need the per-backend CID mapping.
type ReplicatingCAS struct {
	Backends []NamedCAS
}

var _ CAS = (*ReplicatingCAS)(nil)

// PutAll writes the same bytes to all backends.
//
// It returns:
// - the canonical CID (computed from bytes)
// - a map of backend name -> returned CID
//
// If any backend returns a different CID, ErrCIDMismatch is returned.
func (r ReplicatingCAS) PutAll(bytes []byte) (cid.Cid, map[string]cid.Cid, error) {
	want, err := cidutil.CIDv1RawSHA256CID(bytes)
	if err != nil {
		return cid.Undef, nil, err
	}
	if !want.Defined() {
		return cid.Undef, nil, ErrInvalidCID
	}
	if len(r.Backends) == 0 {
		return cid.Undef, nil, fmt.Errorf("storage: ReplicatingCAS has no backends")
	}

	out := make(map[string]cid.Cid, len(r.Backends))
	for _, b := range r.Backends {
		if b.CAS == nil {
			return cid.Undef, nil, fmt.Errorf("storage: nil CAS for backend %q", b.Name)
		}
		got, err := b.CAS.Put(bytes)
		if err != nil {
			return cid.Undef, nil, err
		}
		out[b.Name] = got
		if got != want {
			return cid.Undef, out, ErrCIDMismatch
		}
	}
	return want, out, nil
}

func (r ReplicatingCAS) Put(bytes []byte) (cid.Cid, error) {
	id, _, err := r.PutAll(bytes)
	return id, err
}

func (r ReplicatingCAS) Get(id cid.Cid) ([]byte, error) {
	var sawNotFound bool
	for _, b := range r.Backends {
		if b.CAS == nil {
			continue
		}
		out, err := b.CAS.Get(id)
		if err == nil {
			return out, nil
		}
		if IsNotFound(err) {
			sawNotFound = true
			continue
		}
		return nil, err
	}
	if sawNotFound {
		return nil, ErrNotFound
	}
	return nil, ErrNotFound
}

func (r ReplicatingCAS) Has(id cid.Cid) bool {
	for _, b := range r.Backends {
		if b.CAS != nil && b.CAS.Has(id) {
			return true
		}
	}
	return false
}
