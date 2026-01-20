package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"

	"xdao.co/catf/storage/casregistry"
	"xdao.co/catf/storage/grpccas"

	_ "xdao.co/catf-ipfs/ipfs"
	_ "xdao.co/catf-localfs/localfs"
)

func main() {
	fs := flag.NewFlagSet("xdao-casgrpcd", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:7777", "listen address")
	backend := fs.String("backend", "localfs", "CAS backend name")
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

	cas, closeFn, err := casregistry.Open(*backend, casregistry.UsageDaemon)
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
