package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/model"
	"xdao.co/catf/storage"
	"xdao.co/catf/storage/ipfs"
	"xdao.co/catf/storage/localfs"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		printUsage(errOut)
		return 2
	}

	switch args[0] {
	case "put":
		return cmdPut(args[1:], out, errOut)
	case "get":
		return cmdGet(args[1:], out, errOut)
	case "resolve":
		return cmdResolve(args[1:], out, errOut)
	case "help", "-h", "--help":
		printUsage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown command: %s\n\n", args[0])
		printUsage(errOut)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "cascli: minimal CAS tool for walkthroughs")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  cascli put --backend localfs --localfs-dir <dir> <file>")
	fmt.Fprintln(w, "  cascli get --backend localfs --localfs-dir <dir> --cid <cid> [--out <file>]")
	fmt.Fprintln(w, "  cascli resolve --backend localfs --localfs-dir <dir> --subject <cid> --policy <cid> --att <cid> [--att ...] [--mode strict|permissive]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "IPFS backend:")
	fmt.Fprintln(w, "  cascli put --backend ipfs --ipfs-path <repo> [--pin=true|false] <file>")
	fmt.Fprintln(w, "  cascli resolve --backend ipfs --ipfs-path <repo> ...")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - ipfs backend shells out to the local Kubo 'ipfs' CLI")
	fmt.Fprintln(w, "  - cascli stores raw blocks (CIDv1 raw + sha2-256)")
}

type commonFlags struct {
	backend    string
	localDir   string
	ipfsPath   string
	ipfsBin    string
	pinFlagRaw string
}

func (c *commonFlags) add(fs *flag.FlagSet) {
	fs.StringVar(&c.backend, "backend", "localfs", "CAS backend: localfs|ipfs")
	fs.StringVar(&c.localDir, "localfs-dir", "", "LocalFS CAS directory (for --backend=localfs)")
	fs.StringVar(&c.ipfsPath, "ipfs-path", "", "IPFS repo path (sets IPFS_PATH; for --backend=ipfs)")
	fs.StringVar(&c.ipfsBin, "ipfs-bin", "", "Path to ipfs binary (optional; defaults to 'ipfs')")
	fs.StringVar(&c.pinFlagRaw, "pin", "", "Pin blocks when writing (for --backend=ipfs). If omitted, backend default applies")
}

func (c *commonFlags) openCAS() (storage.CAS, error) {
	switch c.backend {
	case "localfs":
		if c.localDir == "" {
			return nil, fmt.Errorf("missing --localfs-dir")
		}
		return localfs.New(c.localDir)
	case "ipfs":
		bin := c.ipfsBin
		if bin == "" {
			bin = "ipfs"
		}
		if _, err := exec.LookPath(bin); err != nil {
			return nil, fmt.Errorf("ipfs not found on PATH (or at --ipfs-bin): %w", err)
		}
		env := os.Environ()
		if c.ipfsPath != "" {
			env = append(env, "IPFS_PATH="+c.ipfsPath)
		}

		opts := ipfs.Options{Bin: bin, Env: env}
		if c.pinFlagRaw != "" {
			switch strings.ToLower(strings.TrimSpace(c.pinFlagRaw)) {
			case "true", "1", "yes", "y":
				opts.Pin = ipfs.Bool(true)
			case "false", "0", "no", "n":
				opts.Pin = ipfs.Bool(false)
			default:
				return nil, fmt.Errorf("invalid --pin: %q", c.pinFlagRaw)
			}
		}
		return ipfs.New(opts), nil
	default:
		return nil, fmt.Errorf("unknown --backend: %s", c.backend)
	}
}

func cmdPut(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("put", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var common commonFlags
	common.add(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: cascli put [common flags] <file>")
		return 2
	}

	cas, err := common.openCAS()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}

	p := fs.Arg(0)
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(errOut, "read %s: %v\n", filepath.Base(p), err)
		return 1
	}
	id, err := cas.Put(b)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	_, _ = fmt.Fprintln(out, id.String())
	return 0
}

func cmdGet(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var common commonFlags
	common.add(fs)

	var cidStr string
	var outPath string
	fs.StringVar(&cidStr, "cid", "", "CID to fetch")
	fs.StringVar(&outPath, "out", "", "Output file (optional; default stdout)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if cidStr == "" {
		fmt.Fprintln(errOut, "missing --cid")
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "usage: cascli get [common flags] --cid <cid> [--out <file>]")
		return 2
	}

	cas, err := common.openCAS()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}

	id, err := cid.Decode(cidStr)
	if err != nil {
		fmt.Fprintln(errOut, storage.ErrInvalidCID)
		return 1
	}

	b, err := cas.Get(id)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}

	if outPath == "" {
		_, _ = out.Write(b)
		return 0
	}
	if err := os.WriteFile(outPath, b, 0o600); err != nil {
		fmt.Fprintf(errOut, "write %s: %v\n", outPath, err)
		return 1
	}
	return 0
}

func cmdResolve(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var common commonFlags
	common.add(fs)

	var subjectCID string
	var policyCID string
	var atts multiString
	var mode string
	fs.StringVar(&subjectCID, "subject", "", "Subject CID")
	fs.StringVar(&policyCID, "policy", "", "Policy CID")
	fs.Var(&atts, "att", "Attestation CID (repeatable)")
	fs.StringVar(&mode, "mode", "strict", "Compliance mode: strict|permissive")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if subjectCID == "" || policyCID == "" || len(atts) == 0 {
		fmt.Fprintln(errOut, "usage: cascli resolve [common flags] --subject <cid> --policy <cid> --att <cid> [--att ...] [--mode strict|permissive]")
		return 2
	}

	cas, err := common.openCAS()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}

	compliance := model.ComplianceStrict
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "strict":
		compliance = model.ComplianceStrict
	case "permissive":
		compliance = model.CompliancePermissive
	default:
		fmt.Fprintln(errOut, "invalid --mode")
		return 2
	}

	req := model.ResolverRequest{
		SubjectCID: subjectCID,
		Policy:     model.BlobRef{CID: policyCID},
		Compliance: compliance,
		Attestations: func() []model.BlobRef {
			out := make([]model.BlobRef, 0, len(atts))
			for _, a := range atts {
				out = append(out, model.BlobRef{CID: a})
			}
			return out
		}(),
	}

	resp, err := model.ResolveAndRenderCROF(req, model.ResolveOptions{CAS: cas})
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}

	_, _ = out.Write(resp.CROF.Bytes)
	_, _ = fmt.Fprintf(errOut, "CROF-CID: %s\n", resp.CROF.CID)
	return 0
}

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }

func (m *multiString) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("empty value")
	}
	*m = append(*m, v)
	return nil
}
