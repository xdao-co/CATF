package main

import (
	"fmt"
	"os"
	"strings"

	"xdao.co/catf/catf"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: catf_cid <attestation.catf>")
		os.Exit(2)
	}
	path := os.Args[1]
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}
	a, err := catf.Parse(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		os.Exit(1)
	}
	cid, err := a.CID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cid: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(strings.TrimSpace(cid))
}
