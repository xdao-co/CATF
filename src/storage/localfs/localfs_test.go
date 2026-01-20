//go:build removed
// +build removed

package localfs

import (
	"os"
	"testing"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
	"xdao.co/catf/storage/testkit"
)

func TestLocalFS_Conformance(t *testing.T) {
	testkit.RunCASConformance(t, func(t *testing.T) storage.CAS {
		t.Helper()
		dir := t.TempDir()
		cas, err := New(dir)
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		return cas
	})
}

func TestLocalFS_RejectMutationByOverwrite(t *testing.T) {
	dir := t.TempDir()
	cas, err := New(dir)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	orig := []byte("original")
	id, err := cas.Put(orig)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Corrupt the stored object out-of-band.
	path := cas.pathFor(id)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("corrupted"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Get must detect hash mismatch.
	_, err = cas.Get(id)
	if err != storage.ErrCIDMismatch {
		t.Fatalf("Get mismatch: got %v want %v", err, storage.ErrCIDMismatch)
	}

	// Put must not "repair" or overwrite the corrupted object.
	_, err = cas.Put(orig)
	if err != storage.ErrImmutable {
		t.Fatalf("Put after corruption: got %v want %v", err, storage.ErrImmutable)
	}

	// Sanity: the CID is still the CID of the original bytes.
	wantID, err := cidutil.CIDv1RawSHA256CID(orig)
	if err != nil {
		t.Fatalf("CIDv1RawSHA256CID failed: %v", err)
	}
	if id != wantID {
		t.Fatalf("unexpected CID: got %s want %s", id, wantID)
	}
}
