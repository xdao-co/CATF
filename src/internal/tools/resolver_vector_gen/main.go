package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"xdao.co/catf/catf"
	"xdao.co/catf/crof"
	"xdao.co/catf/resolver"
)

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	var (
		attPaths   multiStringFlag
		policyPath = flag.String("policy", "", "path to a TPDL policy")
		subject    = flag.String("subject", "", "subject CID")
		outDir     = flag.String("out", "", "output directory")
	)
	flag.Var(&attPaths, "att", "path to a canonical CATF attestation (repeatable)")
	flag.Parse()

	if len(attPaths) == 0 || *policyPath == "" || *subject == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "usage: resolver_vector_gen -att <a1.catf> [-att <a2.catf> ...] -policy <policy.tpdl> -subject <cid> -out <dir>")
		os.Exit(2)
	}

	var attBytes [][]byte
	for _, p := range attPaths {
		b, err := os.ReadFile(p)
		if err != nil {
			fatalf("read attestation %s: %v", p, err)
		}
		attBytes = append(attBytes, b)
	}
	policyBytes, err := os.ReadFile(*policyPath)
	if err != nil {
		fatalf("read policy: %v", err)
	}

	res, err := resolver.Resolve(attBytes, policyBytes, *subject)
	if err != nil {
		fatalf("resolver.Resolve: %v", err)
	}

	// For CROF inputs, record the attestation CIDs deterministically.
	var attCIDs []string
	for _, b := range attBytes {
		if a, err := catf.Parse(b); err == nil {
			if cid, err := a.CID(); err == nil {
				attCIDs = append(attCIDs, cid)
				continue
			}
		}
		sum := sha256.Sum256(b)
		attCIDs = append(attCIDs, "sha256:"+hex.EncodeToString(sum[:]))
	}
	sort.Strings(attCIDs)

	policyCID := crof.PolicyCID(policyBytes)
	crofBytes, crofCID, err := crof.RenderWithCID(res, policyCID, attCIDs, crof.RenderOptions{ResolverID: "xdao-resolver-reference"})
	if err != nil {
		fatalf("crof.RenderWithCID: %v", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("mkdir out: %v", err)
	}
	crofPath := filepath.Join(*outDir, "resolution_1.crof")
	cidPath := filepath.Join(*outDir, "resolution_1.cid")
	if err := os.WriteFile(crofPath, crofBytes, 0o644); err != nil {
		fatalf("write crof: %v", err)
	}
	if err := os.WriteFile(cidPath, []byte(strings.TrimSpace(crofCID)+"\n"), 0o644); err != nil {
		fatalf("write cid: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
