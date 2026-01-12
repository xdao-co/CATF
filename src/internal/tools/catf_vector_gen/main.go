package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"xdao.co/catf/catf"
)

func mustKeypair(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func issuerKey(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

func main() {
	pub, priv := mustKeypair(0xA1)
	doc := catf.Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": "bafy-doc-1", "Description": "Conformance vector"},
		Claims:  map[string]string{"Role": "author", "Type": "authorship"},
		Crypto: map[string]string{
			"Hash-Alg":      "sha256",
			"Issuer-Key":    issuerKey(pub),
			"Signature":     "0",
			"Signature-Alg": "ed25519",
		},
	}

	pre, err := catf.Render(doc)
	if err != nil {
		panic(err)
	}
	parsed, err := catf.Parse(pre)
	if err != nil {
		panic(err)
	}
	doc.Crypto["Signature"] = catf.SignEd25519SHA256(parsed.SignedBytes(), priv)

	finalBytes, err := catf.Render(doc)
	if err != nil {
		panic(err)
	}
	final, err := catf.Parse(finalBytes)
	if err != nil {
		panic(err)
	}
	cid, err := final.CID()
	if err != nil {
		panic(err)
	}

	fmt.Printf("CID=%s\n", cid)
	fmt.Printf("---BEGIN---\n%s\n---END---\n", string(finalBytes))
}
