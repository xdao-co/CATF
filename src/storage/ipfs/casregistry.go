package ipfs

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"xdao.co/catf/storage"
	"xdao.co/catf/storage/casregistry"
)

var (
	flagIPFSPath string
	flagIPFSBin  string
	flagPinRaw   string
)

func init() {
	casregistry.MustRegister(casregistry.Backend{
		Name:        "ipfs",
		Description: "Local Kubo CLI-backed CAS (offline; shells out to ipfs)",
		Usage:       casregistry.UsageCLI | casregistry.UsageDaemon,
		RegisterFlags: func(fs *flag.FlagSet) {
			fs.StringVar(&flagIPFSPath, "ipfs-path", "", "IPFS repo path (sets IPFS_PATH; for --backend=ipfs)")
			fs.StringVar(&flagIPFSBin, "ipfs-bin", "", "Path to ipfs binary (optional; defaults to 'ipfs')")
			fs.StringVar(&flagPinRaw, "pin", "", "Pin blocks when writing (for --backend=ipfs). If omitted, backend default applies")
		},
		Open: func() (storage.CAS, func() error, error) {
			bin := flagIPFSBin
			if bin == "" {
				bin = "ipfs"
			}
			if _, err := exec.LookPath(bin); err != nil {
				return nil, nil, fmt.Errorf("ipfs not found on PATH (or at --ipfs-bin): %w", err)
			}

			env := os.Environ()
			if flagIPFSPath != "" {
				env = append(env, "IPFS_PATH="+flagIPFSPath)
			}

			opts := Options{Bin: bin, Env: env}
			if flagPinRaw != "" {
				switch strings.ToLower(strings.TrimSpace(flagPinRaw)) {
				case "true", "1", "yes", "y":
					opts.Pin = Bool(true)
				case "false", "0", "no", "n":
					opts.Pin = Bool(false)
				default:
					return nil, nil, fmt.Errorf("invalid --pin: %q", flagPinRaw)
				}
			}
			return New(opts), nil, nil
		},
	})
}
