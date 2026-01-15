package storage

import (
	"errors"

	"github.com/ipfs/go-cid"
)

// MultiCAS provides deterministic, ordered fallback across multiple CAS adapters.
//
// Hydration order is the slice order in Adapters; callers MUST supply a fixed order.
// This avoids map-iteration nondeterminism and makes the retrieval strategy explicit.
//
// Put is defined to write only to the first adapter.
type MultiCAS struct {
	Adapters []CAS
}

func (m MultiCAS) Put(bytes []byte) (cid.Cid, error) {
	if len(m.Adapters) == 0 {
		return cid.Undef, errors.New("storage: MultiCAS has no adapters")
	}
	return m.Adapters[0].Put(bytes)
}

func (m MultiCAS) Get(id cid.Cid) ([]byte, error) {
	var sawNotFound bool
	for _, cas := range m.Adapters {
		b, err := cas.Get(id)
		if err == nil {
			return b, nil
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

func (m MultiCAS) Has(id cid.Cid) bool {
	for _, cas := range m.Adapters {
		if cas.Has(id) {
			return true
		}
	}
	return false
}
