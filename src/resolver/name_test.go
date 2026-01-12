package resolver

import (
	"testing"

	"xdao.co/catf/catf"
)

func TestResolveName_SingleBindingResolved(t *testing.T) {
	pub, priv := mustKeypair(t, 0xF1)
	binding := mustAttestation(t, "bafy-name-record", "Name record", map[string]string{
		"Name":      "contracts.realestate.123-main-st",
		"Points-To": "bafy-doc-1",
		"Type":      "name-binding",
		"Version":   "final",
	}, issuerKey(pub), priv)

	policy := trustPolicy([]trustEntry{{issuerKey(pub), "registrar"}}, nil)

	res, err := ResolveName([][]byte{binding}, []byte(policy), "contracts.realestate.123-main-st", "final")
	if err != nil {
		t.Fatalf("ResolveName error: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}
	if res.PointsTo != "bafy-doc-1" {
		t.Fatalf("expected PointsTo bafy-doc-1, got %s", res.PointsTo)
	}
}

func TestResolveName_CompetingBindingsForked(t *testing.T) {
	pub, priv := mustKeypair(t, 0xF2)
	b1 := mustAttestation(t, "bafy-name-record", "Name record", map[string]string{
		"Name":      "contracts.realestate.123-main-st",
		"Points-To": "bafy-doc-1",
		"Type":      "name-binding",
		"Version":   "final",
	}, issuerKey(pub), priv)
	b2 := mustAttestation(t, "bafy-name-record", "Name record", map[string]string{
		"Name":      "contracts.realestate.123-main-st",
		"Points-To": "bafy-doc-2",
		"Type":      "name-binding",
		"Version":   "final",
	}, issuerKey(pub), priv)

	policy := trustPolicy([]trustEntry{{issuerKey(pub), "registrar"}}, nil)
	res, err := ResolveName([][]byte{b1, b2}, []byte(policy), "contracts.realestate.123-main-st", "final")
	if err != nil {
		t.Fatalf("ResolveName error: %v", err)
	}
	if res.State != StateForked {
		t.Fatalf("expected Forked, got %s", res.State)
	}
	if len(res.Bindings) != 2 {
		t.Fatalf("expected 2 head bindings, got %d", len(res.Bindings))
	}
	if len(res.Forks) != 1 {
		t.Fatalf("expected 1 name fork, got %d", len(res.Forks))
	}
}

func TestResolveName_SupersededBindingChoosesHead(t *testing.T) {
	pub, priv := mustKeypair(t, 0xF3)
	b1 := mustAttestation(t, "bafy-name-record", "Name record", map[string]string{
		"Name":      "contracts.realestate.123-main-st",
		"Points-To": "bafy-doc-1",
		"Type":      "name-binding",
		"Version":   "final",
	}, issuerKey(pub), priv)
	p1, err := catf.Parse(b1)
	if err != nil {
		t.Fatalf("parse b1: %v", err)
	}
	p1CID, err := p1.CID()
	if err != nil {
		t.Fatalf("b1 CID: %v", err)
	}

	b2 := mustAttestation(t, "bafy-name-record", "Name record", map[string]string{
		"Name":       "contracts.realestate.123-main-st",
		"Points-To":  "bafy-doc-2",
		"Supersedes": p1CID,
		"Type":       "name-binding",
		"Version":    "final",
	}, issuerKey(pub), priv)

	policy := trustPolicy([]trustEntry{{issuerKey(pub), "registrar"}}, nil)
	res, err := ResolveName([][]byte{b1, b2}, []byte(policy), "contracts.realestate.123-main-st", "final")
	if err != nil {
		t.Fatalf("ResolveName error: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}
	if res.PointsTo != "bafy-doc-2" {
		t.Fatalf("expected PointsTo bafy-doc-2, got %s", res.PointsTo)
	}
	if len(res.Bindings) != 1 {
		t.Fatalf("expected 1 head binding, got %d", len(res.Bindings))
	}
}
