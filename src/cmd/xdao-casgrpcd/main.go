package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"

	"xdao.co/catf/storage"
	"xdao.co/catf/storage/casconfig"
	"xdao.co/catf/storage/casregistry"
	"xdao.co/catf/storage/grpccas"

	_ "xdao.co/catf-ipfs/ipfs"
	_ "xdao.co/catf-localfs/localfs"
)

func main() {
	fs := flag.NewFlagSet("xdao-casgrpcd", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:7777", "listen address")
	backend := fs.String("backend", "localfs", "CAS backend name")
	casConfigPath := fs.String("cas-config", "", "Path to CAS JSON config (optional; uses casregistry OpenWithConfig)")
	listBackends := fs.Bool("list-backends", false, "List supported backends and exit")

	casregistry.RegisterFlags(fs, casregistry.UsageDaemon)

	_ = fs.Parse(os.Args[1:])
	if *listBackends {
		for _, b := range casregistry.List(casregistry.UsageDaemon) {
			if b.Description == "" {
				_, _ = fmt.Fprintf(os.Stdout, "%s\n", b.Name)
				continue
			}
			_, _ = fmt.Fprintf(os.Stdout, "%s\t%s\n", b.Name, b.Description)
		}
		return
	}

	var (
		cas     storage.CAS
		closeFn func() error
		err     error
	)
	if *casConfigPath != "" {
		cfg, cfgErr := casconfig.LoadFile(*casConfigPath)
		if cfgErr != nil {
			fmt.Fprintln(os.Stderr, cfgErr)
			os.Exit(2)
		}
		cas, closeFn, err = cfg.Open(casregistry.UsageDaemon, *backend)
	} else {
		cas, closeFn, err = casregistry.Open(*backend, casregistry.UsageDaemon)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if closeFn != nil {
		defer closeFn()
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
