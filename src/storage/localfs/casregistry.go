package localfs

import (
	"flag"
	"fmt"

	"xdao.co/catf/storage"
	"xdao.co/catf/storage/casregistry"
)

var (
	flagLocalDir string
)

func init() {
	casregistry.MustRegister(casregistry.Backend{
		Name:        "localfs",
		Description: "Local filesystem CAS (directory)",
		Usage:       casregistry.UsageCLI | casregistry.UsageDaemon,
		RegisterFlags: func(fs *flag.FlagSet) {
			fs.StringVar(&flagLocalDir, "localfs-dir", "", "LocalFS CAS directory (for --backend=localfs)")
		},
		Open: func() (storage.CAS, func() error, error) {
			if flagLocalDir == "" {
				return nil, nil, fmt.Errorf("missing --localfs-dir")
			}
			cas, err := New(flagLocalDir)
			return cas, nil, err
		},
	})
}
