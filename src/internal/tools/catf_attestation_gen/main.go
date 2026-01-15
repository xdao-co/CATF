package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"xdao.co/catf/catf"
	"xdao.co/catf/keys"
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
		extraClaims multiStringFlag
		seedByteStr = flag.String("seed", "", "single byte seed (decimal or 0xNN)")
		subjectCID  = flag.String("subject", "", "subject CID")
		description = flag.String("desc", "", "subject description")
		claimType   = flag.String("type", "authorship", "CLAIMS Type")
		claimRole   = flag.String("role", "author", "CLAIMS Role")
		outPath     = flag.String("out", "", "output file path")
	)
	flag.Var(&extraClaims, "claim", "extra CLAIMS entry 'Key=Value' (repeatable)")
	flag.Parse()

	if *seedByteStr == "" || *subjectCID == "" || *description == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: catf_attestation_gen -seed <0xA1> -subject <cid> -desc <text> -out <file.catf> [-type <t>] [-role <r>] [-claim Key=Value ...]")
		os.Exit(2)
	}
	seedByte, err := parseSeedByte(*seedByteStr)
	if err != nil {
		fatalf("parse -seed: %v", err)
	}

	pub, priv := keypairFromSeedByte(seedByte)
	issuer := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	claims := map[string]string{"Role": *claimRole, "Type": *claimType}
	for _, c := range extraClaims {
		k, v, ok := splitKeyValue(c)
		if !ok {
			fatalf("invalid -claim %q (expected Key=Value)", c)
		}
		claims[k] = v
	}

	doc := catf.Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": *subjectCID, "Description": *description},
		Claims:  claims,
		Crypto: map[string]string{
			"Hash-Alg":      "sha256",
			"Issuer-Key":    issuer,
			"Signature":     "0",
			"Signature-Alg": "ed25519",
		},
	}
	pre, err := catf.Render(doc)
	if err != nil {
		fatalf("catf.Render(pre): %v", err)
	}
	parsed, err := catf.Parse(pre)
	if err != nil {
		fatalf("catf.Parse(pre): %v", err)
	}
	doc.Crypto["Signature"] = keys.SignEd25519SHA256(parsed.SignedBytes(), priv)
	out, err := catf.Render(doc)
	if err != nil {
		fatalf("catf.Render(final): %v", err)
	}
	final, err := catf.Parse(out)
	if err != nil {
		fatalf("catf.Parse(final): %v", err)
	}
	if err := final.Verify(); err != nil {
		fatalf("catf.Verify(final): %v", err)
	}

	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		fatalf("write: %v", err)
	}
}

func parseSeedByte(s string) (byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 8)
	if err != nil {
		return 0, err
	}
	return byte(v), nil
}

func splitKeyValue(s string) (key, value string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	sep := strings.IndexByte(s, '=')
	if sep < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(s[:sep])
	value = strings.TrimSpace(s[sep+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func keypairFromSeedByte(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
