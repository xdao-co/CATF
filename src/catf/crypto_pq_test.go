package catf

import (
	"encoding/base64"
	"io"
	"testing"

	"xdao.co/catf/keys"
)

type deterministicReader struct{}

func (deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

func TestCATF_Verify_Dilithium3_SHA3_256(t *testing.T) {
	pk, sk, err := keys.GenerateDilithium3Keypair(io.Reader(deterministicReader{}))
	if err != nil {
		t.Fatalf("GenerateDilithium3Keypair: %v", err)
	}

	issuer := "dilithium3:" + base64.StdEncoding.EncodeToString(pk.Bytes())

	doc := Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": "bafy-doc-pq-1", "Description": "PQ test"},
		Claims:  map[string]string{"Type": "authorship", "Role": "author"},
		Crypto: map[string]string{
			"Hash-Alg":      "sha3-256",
			"Issuer-Key":    issuer,
			"Signature":     "0",
			"Signature-Alg": "dilithium3",
		},
	}

	pre, err := Render(doc)
	if err != nil {
		t.Fatalf("Render pre: %v", err)
	}
	parsed, err := Parse(pre)
	if err != nil {
		t.Fatalf("Parse pre: %v", err)
	}

	sig, err := keys.SignDilithium3(parsed.SignedBytes(), "sha3-256", sk)
	if err != nil {
		t.Fatalf("SignDilithium3: %v", err)
	}
	doc.Crypto["Signature"] = sig

	finalBytes, err := Render(doc)
	if err != nil {
		t.Fatalf("Render final: %v", err)
	}
	final, err := Parse(finalBytes)
	if err != nil {
		t.Fatalf("Parse final: %v", err)
	}
	if err := final.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
