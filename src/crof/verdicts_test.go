package crof

import (
	"crypto/ed25519"
	"testing"

	"xdao.co/catf/catf"
	"xdao.co/catf/cidutil"
	"xdao.co/catf/resolver"
)

func mustCATFCID(t *testing.T, b []byte) string {
	t.Helper()
	a, err := catf.Parse(b)
	if err != nil {
		t.Fatalf("Parse for CID: %v", err)
	}
	cid, err := a.CID()
	if err != nil {
		t.Fatalf("CID: %v", err)
	}
	return cid
}

func attestationBytes(t *testing.T, subjectCID, description string, claims map[string]string, issuer string, signingKey ed25519.PrivateKey, verify bool) []byte {
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
	doc.Crypto["Signature"] = catf.SignEd25519SHA256(parsed.SignedBytes(), signingKey)
	out, err := catf.Render(doc)
	if err != nil {
		t.Fatalf("Render final: %v", err)
	}
	if verify {
		final, err := catf.Parse(out)
		if err != nil {
			t.Fatalf("Parse final: %v", err)
		}
		if err := final.Verify(); err != nil {
			t.Fatalf("Verify final: %v", err)
		}
	}
	return out
}

func sectionBody(doc []byte, section string) string {
	lines := splitLines(string(doc))
	idx := -1
	for i, l := range lines {
		if l == section {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ""
	}
	start := idx + 1
	end := start
	for end < len(lines) {
		if lines[end] == "" {
			break
		}
		end++
	}
	return joinLines(lines[start:end])
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	out := lines[0]
	for i := 1; i < len(lines); i++ {
		out += "\n" + lines[i]
	}
	return out
}

func TestVerdicts_AreCompleteAndSurfaced_DeterministicUnderShuffle(t *testing.T) {
	subject := "bafy-doc-verdicts-1"

	pubA, privA := mustKeypair(t, 0xA1)
	pubB, privB := mustKeypair(t, 0xB2)
	pubX, privX := mustKeypair(t, 0xC3)

	issuerA := issuerKey(pubA)
	issuerB := issuerKey(pubB)
	issuerX := issuerKey(pubX)

	// Valid trusted attestation.
	a1 := mustAttestation(t, subject, "Verdicts", map[string]string{"Type": "authorship", "Role": "author"}, issuerA, privA)

	// Valid CATF but issuer not trusted by policy.
	u1 := mustAttestation(t, subject, "Verdicts", map[string]string{"Type": "authorship", "Role": "author"}, issuerX, privX)

	// Valid signature but missing required core claim (Effective-Date for approval).
	m1 := attestationBytes(t, subject, "Verdicts", map[string]string{"Type": "approval", "Role": "reviewer"}, issuerB, privB, true)

	// Invalid signature: issuer key A but signed with B.
	badSig := attestationBytes(t, subject, "Verdicts", map[string]string{"Type": "authorship", "Role": "author"}, issuerA, privB, false)

	// Corrupted / non-CATF bytes.
	corrupt := []byte("not a catf")

	policy := []byte("-----BEGIN XDAO TRUST POLICY-----\n" +
		"META\n" +
		"Version: 1\n" +
		"Spec: xdao-tpdl-1\n\n" +
		"TRUST\n" +
		"Key: " + issuerA + "\n" +
		"Role: author\n\n" +
		"Key: " + issuerB + "\n" +
		"Role: reviewer\n\n" +
		"RULES\n" +
		"Require:\n" +
		"  Type: authorship\n" +
		"  Role: author\n\n" +
		"-----END XDAO TRUST POLICY-----\n")

	expected := map[string]func(v resolver.Verdict) bool{}

	a1CID := mustCATFCID(t, a1)
	expected[a1CID] = func(v resolver.Verdict) bool {
		return v.Trusted && v.ExcludedReason == "" && len(v.TrustRoles) > 0
	}

	u1CID := mustCATFCID(t, u1)
	expected[u1CID] = func(v resolver.Verdict) bool {
		return !v.Trusted && v.ExcludedReason == "Issuer not trusted"
	}

	m1CID := mustCATFCID(t, m1)
	expected[m1CID] = func(v resolver.Verdict) bool {
		return v.ExcludedReason == "missing required claim: Effective-Date"
	}

	badSigCID := cidutil.CIDv1RawSHA256(badSig)
	expected[badSigCID] = func(v resolver.Verdict) bool {
		return v.ExcludedReason == "Signature invalid"
	}

	corruptCID := cidutil.CIDv1RawSHA256(corrupt)
	expected[corruptCID] = func(v resolver.Verdict) bool {
		return v.ExcludedReason == "CATF parse/canonicalization failed"
	}

	inputs := [][]byte{a1, u1, m1, badSig, corrupt, corrupt}
	perms := permuteIndices(len(inputs))

	var golden []byte
	for run := 0; run < 15; run++ {
		for _, p := range perms {
			var attBytes [][]byte
			var attCIDs []string
			for _, i := range p {
				attBytes = append(attBytes, inputs[i])
				// Only canonical CATF bytes have a CATF CID; otherwise fall back to raw CID.
				if a, err := catf.Parse(inputs[i]); err == nil {
					cid, cidErr := a.CID()
					if cidErr != nil {
						t.Fatalf("CID: %v", cidErr)
					}
					attCIDs = append(attCIDs, cid)
				} else {
					attCIDs = append(attCIDs, cidutil.CIDv1RawSHA256(inputs[i]))
				}
			}

			res, err := resolver.Resolve(attBytes, policy, subject)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			// Assert verdict presence + reason for each expected CID.
			seen := make(map[string]resolver.Verdict)
			for _, v := range res.Verdicts {
				if v.CID == "" {
					continue
				}
				// Keep the first; duplicates are allowed.
				if _, ok := seen[v.CID]; !ok {
					seen[v.CID] = v
				}
			}
			for cid, check := range expected {
				v, ok := seen[cid]
				if !ok {
					t.Fatalf("missing verdict for CID %s", cid)
				}
				if !check(v) {
					t.Fatalf("verdict mismatch for CID %s: %+v", cid, v)
				}
			}

			out := Render(res, PolicyCID(policy), attCIDs, RenderOptions{ResolverID: "xdao-resolver-reference"})
			if golden == nil {
				golden = out
			} else if string(out) != string(golden) {
				t.Fatalf("CROF output changed across runs/permutations")
			}

			verdictBody := sectionBody(out, "VERDICTS")
			if verdictBody == "" {
				t.Fatalf("missing VERDICTS section")
			}
			for cid := range expected {
				if !containsLine(verdictBody, "Attestation-CID: "+cid) {
					t.Fatalf("VERDICTS section missing Attestation-CID %s", cid)
				}
			}
		}
	}
}

func containsLine(body, line string) bool {
	lines := splitLines(body)
	for _, l := range lines {
		if l == line {
			return true
		}
	}
	return false
}
