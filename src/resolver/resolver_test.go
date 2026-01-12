package resolver

import (
	"strings"
	"testing"

	"xdao.co/catf/catf"
)

func TestResolve_MultiRoleTrustCanSatisfyMultipleRules(t *testing.T) {
	subject := "bafy-contract-roles"
	pub, priv := mustKeypair(t, 0x11)

	att := mustAttestation(t, subject, "Contract", map[string]string{
		"Effective-Date": "2026-01-10",
		"Role":           "buyer",
		"Type":           "approval",
	}, issuerKey(pub), priv)

	policy := trustPolicy(
		[]trustEntry{{issuerKey(pub), "buyer"}, {issuerKey(pub), "seller"}},
		[]requireRule{{"approval", "buyer", 1}, {"approval", "seller", 1}},
	)

	res, err := Resolve([][]byte{att}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}
}

func TestResolve_SupersedesDisallowedByPolicyIsExcluded(t *testing.T) {
	subject := "bafy-doc-supersedes-policy"
	pub, priv := mustKeypair(t, 0x22)

	a1Bytes := mustAttestation(t, subject, "Paper", map[string]string{
		"Role": "author",
		"Type": "authorship",
	}, issuerKey(pub), priv)
	a1, err := catf.Parse(a1Bytes)
	if err != nil {
		t.Fatalf("parse a1: %v", err)
	}

	s2Bytes := mustAttestation(t, subject, "Paper", map[string]string{
		"Supersedes": func() string {
			cid, cidErr := a1.CID()
			if cidErr != nil {
				t.Fatalf("a1 CID: %v", cidErr)
			}
			return cid
		}(),
		"Type": "supersedes",
	}, issuerKey(pub), priv)

	// Policy trusts the issuer as "author" but only allows supersession by "buyer".
	policy := strings.Join([]string{
		"-----BEGIN XDAO TRUST POLICY-----",
		"META",
		"Spec: xdao-tpdl-1",
		"Version: 1",
		"",
		"TRUST",
		"Key: " + issuerKey(pub),
		"Role: author",
		"",
		"RULES",
		"Require:",
		"  Role: author",
		"  Type: authorship",
		"",
		"Supersedes:",
		"  Allowed-By: buyer",
		"",
		"-----END XDAO TRUST POLICY-----",
		"",
	}, "\n")

	res, err := Resolve([][]byte{a1Bytes, s2Bytes}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}

	found := false
	for _, e := range res.Exclusions {
		if e.CID == catfMustCID(t, s2Bytes) && e.Reason == "Supersedes not allowed by policy" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected supersedes exclusion, got %+v", res.Exclusions)
	}
}

func catfMustCID(t *testing.T, attBytes []byte) string {
	t.Helper()
	a, err := catf.Parse(attBytes)
	if err != nil {
		t.Fatalf("parse attestation: %v", err)
	}
	cid, err := a.CID()
	if err != nil {
		t.Fatalf("CID: %v", err)
	}
	return cid
}
