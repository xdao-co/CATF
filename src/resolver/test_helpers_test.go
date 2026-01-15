package resolver

import (
	"crypto/ed25519"
	"encoding/base64"
	"sort"
	"strings"
	"testing"

	"xdao.co/catf/catf"
	"xdao.co/catf/keys"
)

// ----- test helpers -----

type trustEntry struct{ key, role string }

type requireRule struct {
	typ, role string
	quorum    int
}

func trustPolicy(trust []trustEntry, rules []requireRule) string {
	var sb strings.Builder
	sb.WriteString("-----BEGIN XDAO TRUST POLICY-----\n")
	sb.WriteString("META\n")
	sb.WriteString("Spec: xdao-tpdl-1\n")
	sb.WriteString("Version: 1\n\n")

	sb.WriteString("TRUST\n")
	sort.Slice(trust, func(i, j int) bool {
		if trust[i].key == trust[j].key {
			return trust[i].role < trust[j].role
		}
		return trust[i].key < trust[j].key
	})
	for _, e := range trust {
		sb.WriteString("Key: ")
		sb.WriteString(e.key)
		sb.WriteString("\n")
		sb.WriteString("Role: ")
		sb.WriteString(e.role)
		sb.WriteString("\n\n")
	}

	sb.WriteString("RULES\n")
	for _, r := range rules {
		sb.WriteString("Require:\n")
		sb.WriteString("  Role: ")
		sb.WriteString(r.role)
		sb.WriteString("\n")
		sb.WriteString("  Type: ")
		sb.WriteString(r.typ)
		sb.WriteString("\n")
		if r.quorum > 1 {
			sb.WriteString("  Quorum: ")
			sb.WriteString(itoa(r.quorum))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("-----END XDAO TRUST POLICY-----\n")
	return sb.String()
}

func mustKeypair(t *testing.T, seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
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

func mustAttestation(t *testing.T, subjectCID, description string, claims map[string]string, issuer string, priv ed25519.PrivateKey) []byte {
	t.Helper()

	doc := catf.Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": subjectCID, "Description": description},
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
		t.Fatalf("render pre: %v", err)
	}
	parsed, err := catf.Parse(pre)
	if err != nil {
		t.Fatalf("parse pre: %v", err)
	}
	doc.Crypto["Signature"] = keys.SignEd25519SHA256(parsed.SignedBytes(), priv)
	out, err := catf.Render(doc)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	final, err := catf.Parse(out)
	if err != nil {
		t.Fatalf("parse final: %v", err)
	}
	if err := final.Verify(); err != nil {
		t.Fatalf("verify final: %v", err)
	}
	return out
}
