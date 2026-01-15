package localfs

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
)

// CAS is a local filesystem-backed content-addressable store.
//
// Objects are stored immutably and keyed strictly by CID.
// This implementation is offline and deterministic: it never uses the network
// and never depends on wall-clock time.
type CAS struct {
	root string
}

// New constructs a filesystem CAS rooted at root. The directory will be created if needed.
func New(root string) (*CAS, error) {
	if root == "" {
		return nil, errors.New("localfs: root directory is required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &CAS{root: root}, nil
}

func (c *CAS) Put(bytes []byte) (cid.Cid, error) {
	id, err := cidutil.CIDv1RawSHA256CID(bytes)
	if err != nil {
		return cid.Undef, err
	}
	if !id.Defined() {
		return cid.Undef, storage.ErrInvalidCID
	}

	path := c.pathFor(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return cid.Undef, err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		if os.IsExist(err) {
			existing, rerr := c.Get(id)
			if rerr != nil {
				// If the file exists but is unreadable or corrupted, treat as an immutability violation.
				return cid.Undef, storage.ErrImmutable
			}
			if string(existing) != string(bytes) {
				return cid.Undef, storage.ErrImmutable
			}
			return id, nil
		}
		return cid.Undef, err
	}
	defer f.Close()

	if _, err := f.Write(bytes); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return cid.Undef, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return cid.Undef, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return cid.Undef, err
	}

	return id, nil
}

func (c *CAS) Get(id cid.Cid) ([]byte, error) {
	if !id.Defined() {
		return nil, storage.ErrInvalidCID
	}
	path := c.pathFor(id)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	got, err := cidutil.CIDv1RawSHA256CID(b)
	if err != nil {
		return nil, err
	}
	if got != id {
		return nil, storage.ErrCIDMismatch
	}
	return b, nil
}

func (c *CAS) Has(id cid.Cid) bool {
	if !id.Defined() {
		return false
	}
	_, err := os.Stat(c.pathFor(id))
	return err == nil
}

func (c *CAS) pathFor(id cid.Cid) string {
	s := id.String()
	if len(s) < 2 {
		return filepath.Join(c.root, s)
	}
	return filepath.Join(c.root, s[:2], s)
}
