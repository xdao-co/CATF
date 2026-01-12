package crof

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"xdao.co/catf/catf"
	"xdao.co/catf/resolver"
)

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
		t.Fatalf("Render pre: %v", err)
	}
	parsed, err := catf.Parse(pre)
	if err != nil {
		t.Fatalf("Parse pre: %v", err)
	}
	doc.Crypto["Signature"] = catf.SignEd25519SHA256(parsed.SignedBytes(), priv)
	out, err := catf.Render(doc)
	if err != nil {
		t.Fatalf("Render final: %v", err)
	}
	final, err := catf.Parse(out)
	if err != nil {
		t.Fatalf("Parse final: %v", err)
	}
	if err := final.Verify(); err != nil {
		t.Fatalf("Verify final: %v", err)
	}
	return out
}

func permuteIndices(n int) [][]int {
	var out [][]int
	idx := make([]int, n)
	for i := 0; i < n; i++ {
		idx[i] = i
	}
	var gen func(int)
	gen = func(i int) {
		if i == n {
			p := append([]int(nil), idx...)
			out = append(out, p)
			return
		}
		for j := i; j < n; j++ {
			idx[i], idx[j] = idx[j], idx[i]
			gen(i + 1)
			idx[i], idx[j] = idx[j], idx[i]
		}
	}
	gen(0)
	return out
}

func TestDeterminism_CROF_ByteIdentical_ShuffledInputs(t *testing.T) {
	subject := "bafy-doc-determinism-1"

	pubA, privA := mustKeypair(t, 0xA1)
	pubR, privR := mustKeypair(t, 0xB2)
	issuerA := issuerKey(pubA)
	issuerR := issuerKey(pubR)

	a1 := mustAttestation(t, subject, "Determinism", map[string]string{"Type": "authorship", "Role": "author"}, issuerA, privA)
	r1 := mustAttestation(t, subject, "Determinism", map[string]string{"Type": "approval", "Role": "reviewer", "Effective-Date": "2026-01-01T00:00:00Z"}, issuerR, privR)

	policy := []byte("-----BEGIN XDAO TRUST POLICY-----\n" +
		"META\n" +
		"Version: 1\n" +
		"Spec: xdao-tpdl-1\n\n" +
		"TRUST\n" +
		"Key: " + issuerA + "\n" +
		"Role: author\n\n" +
		"Key: " + issuerR + "\n" +
		"Role: reviewer\n\n" +
		"RULES\n" +
		"Require:\n" +
		"  Type: authorship\n" +
		"  Role: author\n\n" +
		"Require:\n" +
		"  Type: approval\n" +
		"  Role: reviewer\n\n" +
		"-----END XDAO TRUST POLICY-----\n")

	inputs := [][]byte{a1, r1}
	var cids []string
	for _, b := range inputs {
		p, err := catf.Parse(b)
		if err != nil {
			t.Fatalf("Parse for CID: %v", err)
		}
		cid, err := p.CID()
		if err != nil {
			t.Fatalf("CID: %v", err)
		}
		cids = append(cids, cid)
	}

	perms := permuteIndices(len(inputs))
	var golden []byte

	for run := 0; run < 25; run++ {
		for _, p := range perms {
			var attBytes [][]byte
			var attCIDs []string
			for _, i := range p {
				attBytes = append(attBytes, inputs[i])
				attCIDs = append(attCIDs, cids[i])
			}

			res, err := resolver.Resolve(attBytes, policy, subject)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			out := Render(res, PolicyCID(policy), attCIDs, RenderOptions{ResolverID: "xdao-resolver-reference"})
			if golden == nil {
				golden = out
				continue
			}
			if string(out) != string(golden) {
				t.Fatalf("CROF output changed across runs/permutations")
			}
		}
	}
}
