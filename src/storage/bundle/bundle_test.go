package bundle_test

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
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

func TestBundle_ImportRejectsDuplicateBlockEntry(t *testing.T) {
	payload := []byte("dup")
	id, err := cidutil.CIDv1RawSHA256CID(payload)
	if err != nil {
		t.Fatal(err)
	}

	b := makeDeterministicTarEntries(t, []tarEntry{
		{name: "blocks/" + id.String(), content: payload},
		{name: "blocks/" + id.String(), content: payload},
	})

	dstDir := t.TempDir()
	dst, err := localfs.New(dstDir)
	if err != nil {
		t.Fatal(err)
	}

	err = bundle.Import(bytes.NewReader(b), dst)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "duplicate block entry") {
		t.Fatalf("expected duplicate block entry error, got %v", err)
	}
}

func TestBundle_ImportFailsClosedOnUnknownEntry(t *testing.T) {
	payload := []byte("ok")
	id, err := cidutil.CIDv1RawSHA256CID(payload)
	if err != nil {
		t.Fatal(err)
	}

	b := makeDeterministicTarEntries(t, []tarEntry{
		{name: "index.json", content: []byte("{}\n")},
		{name: "random.txt", content: []byte("ignore")},
		{name: "blocks/" + id.String(), content: payload},
	})

	dstDir := t.TempDir()
	dst, err := localfs.New(dstDir)
	if err != nil {
		t.Fatal(err)
	}

	err = bundle.Import(bytes.NewReader(b), dst)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unknown entry") {
		t.Fatalf("expected unknown entry error, got %v", err)
	}
}

func TestBundle_ImportAllowsUnknownEntriesWhenOptionSet(t *testing.T) {
	payload := []byte("ok")
	id, err := cidutil.CIDv1RawSHA256CID(payload)
	if err != nil {
		t.Fatal(err)
	}

	b := makeDeterministicTarEntries(t, []tarEntry{
		{name: "index.json", content: []byte("{}\n")},
		{name: "random.txt", content: []byte("ignore")},
		{name: "blocks/" + id.String(), content: payload},
	})

	dstDir := t.TempDir()
	dst, err := localfs.New(dstDir)
	if err != nil {
		t.Fatal(err)
	}

	if err := bundle.ImportWithOptions(bytes.NewReader(b), dst, bundle.ImportOptions{IgnoreUnknown: true}); err != nil {
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

func TestBundle_ImportRejectsTraversalPath(t *testing.T) {
	b := makeDeterministicTarEntries(t, []tarEntry{{name: "../evil", content: []byte("nope")}})

	dstDir := t.TempDir()
	dst, err := localfs.New(dstDir)
	if err != nil {
		t.Fatal(err)
	}

	err = bundle.ImportWithOptions(bytes.NewReader(b), dst, bundle.ImportOptions{IgnoreUnknown: true})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "invalid entry path") {
		t.Fatalf("expected invalid entry path error, got %v", err)
	}
}

func TestBundle_ExportTarOrderingAndHeaders(t *testing.T) {
	dir := t.TempDir()
	cas, err := localfs.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	id1, err := cas.Put([]byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	id2, err := cas.Put([]byte("b"))
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := bundle.Export(&out, cas, []cid.Cid{id2, id1}, bundle.ExportOptions{IncludeIndex: true}); err != nil {
		t.Fatal(err)
	}

	tr := tar.NewReader(bytes.NewReader(out.Bytes()))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)

		if h.Typeflag != tar.TypeReg {
			t.Fatalf("expected regular file, got type %v", h.Typeflag)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Fatalf("expected normalized uid/gid/uname/gname")
		}
		if h.Mode != 0o644 {
			t.Fatalf("expected mode 0644, got %#o", h.Mode)
		}
		if !h.ModTime.Equal(time.Unix(0, 0).UTC()) {
			t.Fatalf("expected epoch mtime")
		}
	}

	blockA := "blocks/" + id1.String()
	blockB := "blocks/" + id2.String()
	if blockB < blockA {
		blockA, blockB = blockB, blockA
	}
	expected := []string{blockA, blockB, "index.json"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(names))
	}
	for i := range expected {
		if names[i] != expected[i] {
			t.Fatalf("unexpected entry order: got %v", names)
		}
	}
}

type tarEntry struct {
	name    string
	content []byte
}

func makeDeterministicTar(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	return makeDeterministicTarEntries(t, []tarEntry{{name: name, content: content}})
}

func makeDeterministicTarEntries(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.content)),
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
		if _, err := tw.Write(e.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
