package bundle_test

import (
	"archive/tar"
	"bytes"
	"testing"
	"time"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
	"xdao.co/catf/storage/bundle"
	"xdao.co/catf/storage/localfs"
)

func TestBundle_ExportIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	cas, err := localfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	id1, err := cas.Put([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	id2, err := cas.Put([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}

	var outA bytes.Buffer
	if err := bundle.Export(&outA, cas, []cid.Cid{id2, id1}, bundle.ExportOptions{IncludeIndex: true}); err != nil {
		t.Fatal(err)
	}
	var outB bytes.Buffer
	if err := bundle.Export(&outB, cas, []cid.Cid{id1, id2}, bundle.ExportOptions{IncludeIndex: true}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(outA.Bytes(), outB.Bytes()) {
		t.Fatalf("expected deterministic bundle bytes")
	}
}

func TestBundle_ImportRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	src, err := localfs.New(srcDir)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("payload")
	id, err := src.Put(payload)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := bundle.Export(&buf, src, []cid.Cid{id}, bundle.ExportOptions{IncludeIndex: true}); err != nil {
		t.Fatal(err)
	}

	dstDir := t.TempDir()
	dst, err := localfs.New(dstDir)
	if err != nil {
		t.Fatal(err)
	}

	if err := bundle.Import(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatal(err)
	}

	got, err := dst.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestBundle_ImportRejectsCIDMismatch(t *testing.T) {
	good := []byte("good")
	goodCID, err := cidutil.CIDv1RawSHA256CID(good)
	if err != nil {
		t.Fatal(err)
	}
	otherCID, err := cidutil.CIDv1RawSHA256CID([]byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	if goodCID.String() == otherCID.String() {
		t.Fatal("expected different CIDs")
	}

	// Name says "otherCID" but bytes are "good" => computed CID mismatch.
	bundleBytes := makeDeterministicTar(t, "blocks/"+otherCID.String(), good)

	dstDir := t.TempDir()
	dst, err := localfs.New(dstDir)
	if err != nil {
		t.Fatal(err)
	}

	if err := bundle.Import(bytes.NewReader(bundleBytes), dst); err != storage.ErrCIDMismatch {
		t.Fatalf("expected ErrCIDMismatch, got %v", err)
	}
}

func makeDeterministicTar(t *testing.T, name string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	h := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(content)),
		Uid:      0,
		Gid:      0,
		Uname:    "",
		Gname:    "",
		ModTime:  time.Unix(0, 0).UTC(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
