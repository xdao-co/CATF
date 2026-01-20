package grpccas

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"xdao.co/catf/storage"
	"xdao.co/catf/storage/casregistry"
)

var (
	flagTarget      string
	flagDialTimeout time.Duration
	flagTimeout     time.Duration
	flagMaxMsgBytes int
)

func init() {
	casregistry.MustRegister(casregistry.Backend{
		Name:        "grpc",
		Description: "gRPC CAS client (talks to a CAS gRPC daemon, e.g. xdao-casgrpcd-localfs)",
		Usage:       casregistry.UsageCLI,
		RegisterFlags: func(fs *flag.FlagSet) {
			fs.StringVar(&flagTarget, "grpc-target", "", "gRPC target host:port (for --backend=grpc)")
			fs.DurationVar(&flagDialTimeout, "grpc-dial-timeout", 5*time.Second, "Dial timeout (for --backend=grpc)")
			fs.DurationVar(&flagTimeout, "grpc-timeout", 0, "Per-RPC timeout (for --backend=grpc)")
			fs.IntVar(&flagMaxMsgBytes, "grpc-max-msg-bytes", 0, "Max gRPC message size in bytes (send+recv); 0 uses grpc defaults")
		},
		Open: func() (storage.CAS, func() error, error) {
			target := strings.TrimSpace(flagTarget)
			if target == "" {
				return nil, nil, fmt.Errorf("missing --grpc-target")
			}
			client, err := Dial(target, DialOptions{Timeout: flagDialTimeout, MaxMsgBytes: flagMaxMsgBytes})
			if err != nil {
				return nil, nil, err
			}
			client.Timeout = flagTimeout
			return client, client.Close, nil
		},
	})
}
