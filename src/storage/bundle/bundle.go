package bundle

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
)

// FormatVersion is the current bundle index schema version.
const FormatVersion = 1

// ExportOptions controls bundle export behavior.
type ExportOptions struct {
	// Labels is optional, non-authoritative metadata mapping names to CIDs.
	Labels map[string]cid.Cid
	// IncludeIndex controls whether index.json is included.
	IncludeIndex bool
}

// Export writes a deterministic TAR bundle containing the blocks for the given CIDs.
//
// The bundle bytes are deterministic: entry order is lexicographic and TAR headers are normalized.
// All exported bytes are validated against their CIDs.
func Export(w io.Writer, cas storage.CAS, ids []cid.Cid, opts ExportOptions) error {
	if cas == nil {
		return fmt.Errorf("bundle: nil CAS")
	}

	uniq := make(map[string]cid.Cid, len(ids))
	for _, id := range ids {
		if !id.Defined() {
			return storage.ErrInvalidCID
		}
		uniq[id.String()] = id
	}

	cidStrings := make([]string, 0, len(uniq))
	for s := range uniq {
		cidStrings = append(cidStrings, s)
	}
	sort.Strings(cidStrings)

	tw := tar.NewWriter(w)

	blocks := make([]indexBlock, 0, len(cidStrings))
	for _, s := range cidStrings {
		id := uniq[s]
		b, err := cas.Get(id)
		if err != nil {
			_ = tw.Close()
			return err
		}
		got, err := cidutil.CIDv1RawSHA256CID(b)
		if err != nil {
			_ = tw.Close()
			return err
		}
		if got.String() != id.String() {
			_ = tw.Close()
			return storage.ErrCIDMismatch
		}

		entryPath := "blocks/" + id.String()
		if err := writeFile(tw, entryPath, b); err != nil {
			_ = tw.Close()
			return err
		}
		blocks = append(blocks, indexBlock{CID: id.String(), Size: len(b)})
	}

	if opts.IncludeIndex {
		idx := indexJSON{
			Version:   FormatVersion,
			CIDCodec:  "raw",
			Multihash: "sha2-256",
			Blocks:    blocks,
			Labels:    nil,
		}

		if len(opts.Labels) > 0 {
			keys := make([]string, 0, len(opts.Labels))
			for k := range opts.Labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			labels := make([]indexLabel, 0, len(keys))
			for _, k := range keys {
				if k == "" {
					_ = tw.Close()
					return fmt.Errorf("bundle: empty label key")
				}
				v := opts.Labels[k]
				if !v.Defined() {
					_ = tw.Close()
					return storage.ErrInvalidCID
				}
				labels = append(labels, indexLabel{Name: k, CID: v.String()})
			}
			idx.Labels = labels
		}

		b, err := marshalCanonicalIndexJSON(idx)
		if err != nil {
			_ = tw.Close()
			return err
		}
		if err := writeFile(tw, "index.json", b); err != nil {
			_ = tw.Close()
			return err
		}
	}

	return tw.Close()
}

// ImportOptions controls bundle import behavior.
type ImportOptions struct {
	// IgnoreUnknown controls whether unknown TAR entries are ignored.
	//
	// Default (false) is fail-closed: unknown entries cause Import to return an error.
	IgnoreUnknown bool
}

// Import reads a bundle from r and imports all blocks into cas.
//
// Default behavior is fail-closed: unknown entries cause an error.
// Use ImportWithOptions to allow ignoring unknown entries.
func Import(r io.Reader, cas storage.CAS) error {
	return ImportWithOptions(r, cas, ImportOptions{})
}

// ImportWithOptions reads a bundle from r and imports all blocks into cas.
//
// It validates that each block's bytes match both the filename CID and the computed CID.
func ImportWithOptions(r io.Reader, cas storage.CAS, opts ImportOptions) error {
	if cas == nil {
		return fmt.Errorf("bundle: nil CAS")
	}

	tr := tar.NewReader(r)
	seen := map[string]struct{}{}

	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := cleanTarPath(h.Name)
		if name == "" {
			return fmt.Errorf("bundle: invalid entry path: %q", h.Name)
		}

		if h.Typeflag != tar.TypeReg {
			if opts.IgnoreUnknown {
				continue
			}
			return fmt.Errorf("bundle: unexpected tar entry type: %v (%s)", h.Typeflag, name)
		}

		// Non-authoritative metadata.
		if name == "index.json" || strings.HasPrefix(name, "manifests/") {
			_, _ = io.Copy(io.Discard, tr)
			continue
		}

		if !strings.HasPrefix(name, "blocks/") {
			if opts.IgnoreUnknown {
				_, _ = io.Copy(io.Discard, tr)
				continue
			}
			return fmt.Errorf("bundle: unknown entry: %s", name)
		}

		cidStr := strings.TrimPrefix(name, "blocks/")
		id, derr := cid.Decode(cidStr)
		if derr != nil || !id.Defined() {
			return storage.ErrInvalidCID
		}

		payload, rerr := io.ReadAll(tr)
		if rerr != nil {
			return rerr
		}
		got, herr := cidutil.CIDv1RawSHA256CID(payload)
		if herr != nil {
			return herr
		}
		if got.String() != id.String() {
			return storage.ErrCIDMismatch
		}

		key := id.String()
		if _, ok := seen[key]; ok {
			return fmt.Errorf("bundle: duplicate block entry: %s", key)
		}
		seen[key] = struct{}{}

		putID, perr := cas.Put(payload)
		if perr != nil {
			return perr
		}
		if putID.String() != id.String() {
			return storage.ErrCIDMismatch
		}
	}
}

type indexJSON struct {
	Version   int          `json:"version"`
	CIDCodec  string       `json:"cidCodec"`
	Multihash string       `json:"multihash"`
	Blocks    []indexBlock `json:"blocks"`
	Labels    []indexLabel `json:"labels,omitempty"`
}

type indexBlock struct {
	CID  string `json:"cid"`
	Size int    `json:"size"`
}

type indexLabel struct {
	Name string `json:"name"`
	CID  string `json:"cid"`
}

func marshalCanonicalIndexJSON(idx indexJSON) ([]byte, error) {
	// indexJSON is composed only of structs + slices; encoding/json will be deterministic.
	b, err := json.Marshal(idx)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func writeFile(tw *tar.Writer, name string, content []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(content)),
		Uid:      0,
		Gid:      0,
		Uname:    "",
		Gname:    "",
		ModTime:  epoch0,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := io.Copy(tw, bytes.NewReader(content))
	return err
}

func cleanTarPath(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		return ""
	}

	parts := strings.Split(name, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			return ""
		}
		if part == ".." {
			return ""
		}
		out = append(out, part)
	}
	return strings.Join(out, "/")
}
