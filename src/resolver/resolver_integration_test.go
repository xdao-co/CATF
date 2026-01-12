package resolver

import (
	"testing"

	"xdao.co/catf/catf"
)

func TestVector1_SingleAuthorResolved(t *testing.T) {
	subject := "bafy-doc-1"
	pub, priv := mustKeypair(t, 0xA1)
	a1 := mustAttestation(t, subject, "Scientific paper draft", map[string]string{
		"Role": "author",
		"Type": "authorship",
	}, issuerKey(pub), priv)

	policy := trustPolicy(
		[]trustEntry{{issuerKey(pub), "author"}},
		[]requireRule{{"authorship", "author", 1}},
	)

	res, err := Resolve([][]byte{a1}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(res.Paths))
	}
	if len(res.Forks) != 0 {
		t.Fatalf("expected 0 forks, got %d", len(res.Forks))
	}
}

func TestVector2_CompetingRevisionsForked(t *testing.T) {
	subject := "bafy-doc-1"
	pubA, privA := mustKeypair(t, 0xA2)
	pubB, privB := mustKeypair(t, 0xA3)
	a1 := mustAttestation(t, subject, "Paper", map[string]string{"Role": "author", "Type": "authorship"}, issuerKey(pubA), privA)
	a2 := mustAttestation(t, subject, "Paper", map[string]string{"Role": "author", "Type": "authorship"}, issuerKey(pubB), privB)

	policy := trustPolicy(
		[]trustEntry{{issuerKey(pubA), "author"}, {issuerKey(pubB), "author"}},
		[]requireRule{{"authorship", "author", 1}},
	)

	res, err := Resolve([][]byte{a1, a2}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateForked {
		t.Fatalf("expected Forked, got %s", res.State)
	}
	if len(res.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(res.Paths))
	}
	if len(res.Forks) != 1 {
		t.Fatalf("expected 1 fork, got %d", len(res.Forks))
	}
}

func TestVector3_ExplicitSupersession(t *testing.T) {
	subject := "bafy-doc-1"
	pub, priv := mustKeypair(t, 0xB1)
	a1Bytes := mustAttestation(t, subject, "Paper", map[string]string{"Role": "author", "Type": "authorship"}, issuerKey(pub), priv)
	a1, err := catf.Parse(a1Bytes)
	if err != nil {
		t.Fatalf("parse a1: %v", err)
	}
	a2Bytes := mustAttestation(t, subject, "Paper", map[string]string{"Supersedes": a1.CID(), "Type": "supersedes"}, issuerKey(pub), priv)

	policy := trustPolicy(
		[]trustEntry{{issuerKey(pub), "author"}},
		[]requireRule{{"authorship", "author", 1}},
	)

	res, err := Resolve([][]byte{a1Bytes, a2Bytes}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(res.Paths))
	}
	if len(res.Paths[0].CIDs) != 2 {
		t.Fatalf("expected path length 2, got %d", len(res.Paths[0].CIDs))
	}
}

func TestVector4_RealEstateMultiPartyApproval(t *testing.T) {
	subject := "bafy-contract-1"
	pubBuyer, privBuyer := mustKeypair(t, 0xC1)
	pubSeller, privSeller := mustKeypair(t, 0xC2)
	buyer := mustAttestation(t, subject, "Contract", map[string]string{
		"Effective-Date": "2026-01-10",
		"Role":           "buyer",
		"Type":           "approval",
	}, issuerKey(pubBuyer), privBuyer)
	seller := mustAttestation(t, subject, "Contract", map[string]string{
		"Effective-Date": "2026-01-10",
		"Role":           "seller",
		"Type":           "approval",
	}, issuerKey(pubSeller), privSeller)

	policy := trustPolicy(
		[]trustEntry{{issuerKey(pubBuyer), "buyer"}, {issuerKey(pubSeller), "seller"}},
		[]requireRule{{"approval", "buyer", 1}, {"approval", "seller", 1}},
	)

	res, err := Resolve([][]byte{buyer, seller}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}
}

func TestVector5_MissingRequiredPartyUnresolved(t *testing.T) {
	subject := "bafy-contract-1"
	pubBuyer, privBuyer := mustKeypair(t, 0xD1)
	pubSeller, _ := mustKeypair(t, 0xD2)
	buyer := mustAttestation(t, subject, "Contract", map[string]string{
		"Effective-Date": "2026-01-10",
		"Role":           "buyer",
		"Type":           "approval",
	}, issuerKey(pubBuyer), privBuyer)

	policy := trustPolicy(
		[]trustEntry{{issuerKey(pubBuyer), "buyer"}, {issuerKey(pubSeller), "seller"}},
		[]requireRule{{"approval", "buyer", 1}, {"approval", "seller", 1}},
	)

	res, err := Resolve([][]byte{buyer}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateUnresolved {
		t.Fatalf("expected Unresolved, got %s", res.State)
	}
}

func TestVector6_Revocation(t *testing.T) {
	subject := "bafy-contract-1"
	pub, priv := mustKeypair(t, 0xE1)
	a1Bytes := mustAttestation(t, subject, "Contract", map[string]string{
		"Effective-Date": "2026-01-10",
		"Role":           "buyer",
		"Type":           "approval",
	}, issuerKey(pub), priv)
	a1, err := catf.Parse(a1Bytes)
	if err != nil {
		t.Fatalf("parse a1: %v", err)
	}
	a2Bytes := mustAttestation(t, subject, "Contract", map[string]string{
		"Target-Attestation": a1.CID(),
		"Type":               "revocation",
	}, issuerKey(pub), priv)

	policy := trustPolicy(
		[]trustEntry{{issuerKey(pub), "buyer"}},
		[]requireRule{{"approval", "buyer", 1}},
	)

	res, err := Resolve([][]byte{a1Bytes, a2Bytes}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if res.State != StateRevoked {
		t.Fatalf("expected Revoked, got %s", res.State)
	}
}
