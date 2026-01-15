package ipfs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/storage"
)

// CAS is a content-addressable store backed by the local Kubo "ipfs" CLI.
//
// This is an optional adapter package. The core library remains storage-provider
// agnostic; any external CAS can integrate by implementing storage.CAS.
//
// Properties:
// - Offline: operates on the local IPFS repo; does not require an IPFS daemon.
// - Deterministic: no wall-clock usage; validates bytes against the requested CID.
// - Best-effort: relies on an external "ipfs" binary (configurable).
//
// CID contract: CIDv1 raw + sha2-256, matching cidutil.CIDv1RawSHA256CID.
//
// Warning: This adapter is not authoritative. Transport/reachability is not
// validity; CID verification is.
//
// Note: This package name is "ipfs" for familiarity, but it does not embed a
// network client; it shells out to the local Kubo CLI.
type CAS struct {
	bin string
	env []string
	pin bool
}

type Options struct {
	// Bin is the path to the ipfs binary. If empty, "ipfs" is used.
	Bin string
	// Env optionally overrides the command environment (e.g. to set IPFS_PATH).
	// If nil, the process environment is used.
	Env []string
	// Pin controls whether written blocks are pinned in the local IPFS repo.
	// If nil, the default is true.
	Pin *bool
}

func New(opts Options) *CAS {
	bin := opts.Bin
	if bin == "" {
		bin = "ipfs"
	}
	pin := true
	if opts.Pin != nil {
		pin = *opts.Pin
	}
	return &CAS{bin: bin, env: opts.Env, pin: pin}
}

func (c *CAS) Put(data []byte) (cid.Cid, error) {
	id, err := cidutil.CIDv1RawSHA256CID(data)
	if err != nil {
		return cid.Undef, err
	}
	if !id.Defined() {
		return cid.Undef, storage.ErrInvalidCID
	}

	// Store as a raw block so the returned CID matches the CATF/CROF CID contract.
	// Different Kubo versions use different flag names; try a couple.
	//
	// We intentionally write via a temp file rather than /dev/stdin so this works
	// across platforms (including Windows builds).
	f, err := os.CreateTemp("", "xdao-catf-ipfs-*")
	if err != nil {
		return cid.Undef, err
	}
	path := f.Name()
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return cid.Undef, werr
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return cid.Undef, cerr
	}
	defer os.Remove(path)

	base := []string{"block", "put", "--quiet"}
	if c.pin {
		base = append(base, "--pin")
	}
	variants := [][]string{
		append(append([]string{}, base...), "--cid-codec=raw", "--mhtype=sha2-256", "--mhlen=32", path),
		append(append([]string{}, base...), "--format=raw", "--mhtype=sha2-256", "--mhlen=32", path),
		append(append([]string{}, base...), "--cid-version=1", "--format=raw", "--mhtype=sha2-256", "--mhlen=32", path),
	}

	var lastErr error
	var stdout string
	for _, argv := range variants {
		out, runErr := c.run(nil, argv...)
		if runErr != nil {
			lastErr = runErr
			continue
		}
		stdout = strings.TrimSpace(string(out))
		fields := strings.Fields(stdout)
		if len(fields) == 0 {
			lastErr = fmt.Errorf("ipfs: block put returned empty output")
			continue
		}
		stdout = fields[0]
		lastErr = nil
		break
	}
	if lastErr != nil {
		return cid.Undef, lastErr
	}

	got, err := cid.Decode(stdout)
	if err != nil {
		return cid.Undef, fmt.Errorf("ipfs: unexpected block put output: %w", err)
	}
	if got.String() != id.String() {
		return cid.Undef, storage.ErrCIDMismatch
	}
	return id, nil
}

func (c *CAS) Get(id cid.Cid) ([]byte, error) {
	if !id.Defined() {
		return nil, storage.ErrInvalidCID
	}

	out, err := c.run(nil, "block", "get", id.String())
	if err != nil {
		if isLikelyNotFound(err) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}

	got, herr := cidutil.CIDv1RawSHA256CID(out)
	if herr != nil {
		return nil, herr
	}
	if got.String() != id.String() {
		return nil, storage.ErrCIDMismatch
	}
	return out, nil
}

func (c *CAS) Has(id cid.Cid) bool {
	if !id.Defined() {
		return false
	}
	_, err := c.run(nil, "block", "stat", id.String())
	return err == nil
}

func (c *CAS) run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(c.bin, args...)
	if c.env != nil {
		cmd.Env = c.env
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	out, err := cmd.Output()
	if err == nil {
		return out, nil
	}

	var ee *exec.ExitError
	if errors.As(err, &ee) {
		msg := strings.TrimSpace(string(ee.Stderr))
		if msg == "" {
			return nil, fmt.Errorf("ipfs: %v", err)
		}
		return nil, fmt.Errorf("ipfs: %s", msg)
	}
	return nil, err
}

func isLikelyNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "block not found")
}

// Bool returns a pointer to v.
//
// This is a small convenience for configuring Options values like Pin.
func Bool(v bool) *bool {
	return &v
}
