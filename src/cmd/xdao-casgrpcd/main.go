package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"

	"google.golang.org/grpc"

	"xdao.co/catf/storage"
	"xdao.co/catf/storage/grpccas"
	"xdao.co/catf/storage/ipfs"
	"xdao.co/catf/storage/localfs"
)

func main() {
	fs := flag.NewFlagSet("xdao-casgrpcd", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:7777", "listen address")
	backend := fs.String("backend", "localfs", "CAS backend: localfs|ipfs")

	localDir := fs.String("localfs-dir", "", "LocalFS CAS directory (for --backend=localfs)")

	ipfsPath := fs.String("ipfs-path", "", "IPFS repo path (sets IPFS_PATH; for --backend=ipfs)")
	ipfsBin := fs.String("ipfs-bin", "", "Path to ipfs binary (optional; defaults to 'ipfs')")
	pin := fs.Bool("pin", true, "Pin blocks when writing (for --backend=ipfs)")

	_ = fs.Parse(os.Args[1:])

	var cas storage.CAS
	switch *backend {
	case "localfs":
		if *localDir == "" {
			fmt.Fprintln(os.Stderr, "missing --localfs-dir")
			os.Exit(2)
		}
		c, err := localfs.New(*localDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cas = c

	case "ipfs":
		bin := *ipfsBin
		if bin == "" {
			bin = "ipfs"
		}
		if _, err := exec.LookPath(bin); err != nil {
			fmt.Fprintf(os.Stderr, "ipfs not found on PATH (or at --ipfs-bin): %v\n", err)
			os.Exit(1)
		}

		env := os.Environ()
		if *ipfsPath != "" {
			env = append(env, "IPFS_PATH="+*ipfsPath)
		}

		cas = ipfs.New(ipfs.Options{Bin: bin, Env: env, Pin: ipfs.Bool(*pin)})

	default:
		fmt.Fprintln(os.Stderr, "invalid --backend")
		os.Exit(2)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer lis.Close()

	s := grpc.NewServer()
	grpccas.RegisterCASServer(s, &grpccas.Server{CAS: cas})

	fmt.Fprintf(os.Stderr, "xdao-casgrpcd listening on %s (backend=%s)\n", lis.Addr().String(), *backend)
	if err := s.Serve(lis); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
