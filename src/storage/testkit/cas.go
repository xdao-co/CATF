package testkit

import (
	"bytes"
	"testing"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
)

// NewCAS constructs a fresh, empty CAS instance for a test.
// The returned CAS MUST be isolated from other tests.
type NewCAS func(t *testing.T) storage.CAS

func RunCASConformance(t *testing.T, newCAS NewCAS) {
	t.Helper()

	t.Run("PutGetRoundTrip", func(t *testing.T) {
		cas := newCAS(t)
		want := []byte("hello, catf storage")

		id, err := cas.Put(want)
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		wantID, err := cidutil.CIDv1RawSHA256CID(want)
		if err != nil {
			t.Fatalf("CIDv1RawSHA256CID failed: %v", err)
		}
		if id != wantID {
			t.Fatalf("Put CID mismatch: got %s want %s", id, wantID)
		}

		got, err := cas.Get(id)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Get bytes mismatch")
		}

		gotID, err := cidutil.CIDv1RawSHA256CID(got)
		if err != nil {
			t.Fatalf("CIDv1RawSHA256CID(got) failed: %v", err)
		}
		if gotID != id {
			t.Fatalf("Get returned bytes not matching requested CID")
		}
	})

	t.Run("PutIdempotent", func(t *testing.T) {
		cas := newCAS(t)
		b := []byte("same bytes")

		id1, err := cas.Put(b)
		if err != nil {
			t.Fatalf("Put(1) failed: %v", err)
		}
		id2, err := cas.Put(b)
		if err != nil {
			t.Fatalf("Put(2) failed: %v", err)
		}
		if id1 != id2 {
			t.Fatalf("Put not idempotent: %s vs %s", id1, id2)
		}
	})

	t.Run("HasAndNotFound", func(t *testing.T) {
		cas := newCAS(t)
		b := []byte("missing")
		id, err := cidutil.CIDv1RawSHA256CID(b)
		if err != nil {
			t.Fatalf("CIDv1RawSHA256CID failed: %v", err)
		}

		if cas.Has(id) {
			t.Fatalf("Has returned true for missing CID")
		}
		_, err = cas.Get(id)
		if !storage.IsNotFound(err) {
			t.Fatalf("Get missing: got err=%v want ErrNotFound", err)
		}

		_, err = cas.Put(b)
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		if !cas.Has(id) {
			t.Fatalf("Has returned false after Put")
		}
	})

	t.Run("RejectUndefCID", func(t *testing.T) {
		cas := newCAS(t)
		var undef cid.Cid
		if cas.Has(undef) {
			t.Fatalf("Has should be false for undefined CID")
		}
		if _, err := cas.Get(undef); err == nil {
			t.Fatalf("Get should fail for undefined CID")
		}
	})
}
