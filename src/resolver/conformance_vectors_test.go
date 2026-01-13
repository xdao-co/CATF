package resolver_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xdao.co/catf/catf"
	"xdao.co/catf/crof"
	"xdao.co/catf/resolver"
)

func TestConformanceVectors_Resolver_CROFDeterminism(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "resolver", "xdao-resolver-1")

	attBytes, err := os.ReadFile(filepath.Join(root, "attestation_1.catf"))
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	policyBytes, err := os.ReadFile(filepath.Join(root, "policy.tpdl"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	subjectBytes, err := os.ReadFile(filepath.Join(root, "subject.cid"))
	if err != nil {
		t.Fatalf("read subject: %v", err)
	}
	subjectCID := strings.TrimSpace(string(subjectBytes))
	if subjectCID == "" {
		t.Fatalf("empty subject CID")
	}

	wantCROF, err := os.ReadFile(filepath.Join(root, "resolution_1.crof"))
	if err != nil {
		t.Fatalf("read expected CROF: %v", err)
	}
	wantCIDBytes, err := os.ReadFile(filepath.Join(root, "resolution_1.cid"))
	if err != nil {
		t.Fatalf("read expected CROF CID: %v", err)
	}
	wantCID := strings.TrimSpace(string(wantCIDBytes))
	if wantCID == "" {
		t.Fatalf("empty expected CROF CID")
	}

	res, err := resolver.Resolve([][]byte{attBytes}, policyBytes, subjectCID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	att, err := catf.Parse(attBytes)
	if err != nil {
		t.Fatalf("catf.Parse(attestation): %v", err)
	}
	attCID, err := att.CID()
	if err != nil {
		t.Fatalf("attestation CID: %v", err)
	}

	trustPolicyCID := crof.PolicyCID(policyBytes)
	gotCROF, gotCID, err := crof.RenderWithCID(res, trustPolicyCID, []string{attCID}, crof.RenderOptions{ResolverID: "xdao-resolver-reference"})
	if err != nil {
		t.Fatalf("crof.RenderWithCID: %v", err)
	}

	// Canonical CROF must be self-canonical under the canonicalizer.
	canon, err := crof.CanonicalizeCROF(gotCROF)
	if err != nil {
		t.Fatalf("CanonicalizeCROF(output): %v", err)
	}
	if !bytes.Equal(canon, gotCROF) {
		t.Fatalf("crof output is not canonical")
	}

	if gotCID != wantCID {
		t.Fatalf("CROF CID mismatch: got %s want %s", gotCID, wantCID)
	}
	if !bytes.Equal(gotCROF, wantCROF) {
		t.Fatalf("CROF bytes mismatch vs conformance vector")
	}
}

func TestConformanceVectors_Resolver_ForkDeterminism(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "resolver", "xdao-resolver-fork-1")

	att1, err := os.ReadFile(filepath.Join(root, "attestation_1.catf"))
	if err != nil {
		t.Fatalf("read attestation_1: %v", err)
	}
	att2, err := os.ReadFile(filepath.Join(root, "attestation_2.catf"))
	if err != nil {
		t.Fatalf("read attestation_2: %v", err)
	}
	policyBytes, err := os.ReadFile(filepath.Join(root, "policy.tpdl"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	subjectBytes, err := os.ReadFile(filepath.Join(root, "subject.cid"))
	if err != nil {
		t.Fatalf("read subject: %v", err)
	}
	subjectCID := strings.TrimSpace(string(subjectBytes))
	if subjectCID == "" {
		t.Fatalf("empty subject CID")
	}

	wantCROF, err := os.ReadFile(filepath.Join(root, "resolution_1.crof"))
	if err != nil {
		t.Fatalf("read expected CROF: %v", err)
	}
	wantCIDBytes, err := os.ReadFile(filepath.Join(root, "resolution_1.cid"))
	if err != nil {
		t.Fatalf("read expected CROF CID: %v", err)
	}
	wantCID := strings.TrimSpace(string(wantCIDBytes))
	if wantCID == "" {
		t.Fatalf("empty expected CROF CID")
	}

	trustPolicyCID := crof.PolicyCID(policyBytes)

	// Compute the deterministic, sorted attestation CID list for CROF inputs.
	a1, err := catf.Parse(att1)
	if err != nil {
		t.Fatalf("catf.Parse(attestation_1): %v", err)
	}
	a1CID, err := a1.CID()
	if err != nil {
		t.Fatalf("attestation_1 CID: %v", err)
	}
	a2, err := catf.Parse(att2)
	if err != nil {
		t.Fatalf("catf.Parse(attestation_2): %v", err)
	}
	a2CID, err := a2.CID()
	if err != nil {
		t.Fatalf("attestation_2 CID: %v", err)
	}
	attCIDs := []string{a1CID, a2CID}
	if attCIDs[0] > attCIDs[1] {
		attCIDs[0], attCIDs[1] = attCIDs[1], attCIDs[0]
	}

	// Assert determinism independent of input ordering.
	orders := [][][]byte{{att1, att2}, {att2, att1}}
	for _, in := range orders {
		res, err := resolver.Resolve(in, policyBytes, subjectCID)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		gotCROF, gotCID, err := crof.RenderWithCID(res, trustPolicyCID, attCIDs, crof.RenderOptions{ResolverID: "xdao-resolver-reference"})
		if err != nil {
			t.Fatalf("crof.RenderWithCID: %v", err)
		}
		canon, err := crof.CanonicalizeCROF(gotCROF)
		if err != nil {
			t.Fatalf("CanonicalizeCROF(output): %v", err)
		}
		if !bytes.Equal(canon, gotCROF) {
			t.Fatalf("crof output is not canonical")
		}
		if gotCID != wantCID {
			t.Fatalf("CROF CID mismatch: got %s want %s", gotCID, wantCID)
		}
		if !bytes.Equal(gotCROF, wantCROF) {
			t.Fatalf("CROF bytes mismatch vs conformance vector")
		}
	}
}

func TestConformanceVectors_Resolver_SupersedesDeterminism(t *testing.T) {
	root := filepath.Join("..", "testdata", "conformance", "resolver", "xdao-resolver-supersedes-1")

	att1, err := os.ReadFile(filepath.Join(root, "attestation_1.catf"))
	if err != nil {
		t.Fatalf("read attestation_1: %v", err)
	}
	att2, err := os.ReadFile(filepath.Join(root, "attestation_2.catf"))
	if err != nil {
		t.Fatalf("read attestation_2: %v", err)
	}
	att3, err := os.ReadFile(filepath.Join(root, "attestation_3.catf"))
	if err != nil {
		t.Fatalf("read attestation_3: %v", err)
	}
	pn, err := os.ReadFile(filepath.Join(root, "policy.tpdl"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	subjectBytes, err := os.ReadFile(filepath.Join(root, "subject.cid"))
	if err != nil {
		t.Fatalf("read subject: %v", err)
	}
	subjectCID := strings.TrimSpace(string(subjectBytes))
	if subjectCID == "" {
		t.Fatalf("empty subject CID")
	}

	wantCROF, err := os.ReadFile(filepath.Join(root, "resolution_1.crof"))
	if err != nil {
		t.Fatalf("read expected CROF: %v", err)
	}
	wantCIDBytes, err := os.ReadFile(filepath.Join(root, "resolution_1.cid"))
	if err != nil {
		t.Fatalf("read expected CROF CID: %v", err)
	}
	wantCID := strings.TrimSpace(string(wantCIDBytes))
	if wantCID == "" {
		t.Fatalf("empty expected CROF CID")
	}

	trustPolicyCID := crof.PolicyCID(pn)

	// Compute the deterministic, sorted attestation CID list for CROF inputs.
	atts := [][]byte{att1, att2, att3}
	var attCIDs []string
	for i, b := range atts {
		a, err := catf.Parse(b)
		if err != nil {
			t.Fatalf("catf.Parse(attestation_%d): %v", i+1, err)
		}
		cid, err := a.CID()
		if err != nil {
			t.Fatalf("attestation_%d CID: %v", i+1, err)
		}
		attCIDs = append(attCIDs, cid)
	}
	for i := 0; i < len(attCIDs); i++ {
		for j := i + 1; j < len(attCIDs); j++ {
			if attCIDs[j] < attCIDs[i] {
				attCIDs[i], attCIDs[j] = attCIDs[j], attCIDs[i]
			}
		}
	}

	// Assert determinism independent of input ordering.
	orders := [][][]byte{{att1, att2, att3}, {att3, att2, att1}, {att2, att1, att3}}
	for _, in := range orders {
		res, err := resolver.Resolve(in, pn, subjectCID)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		gotCROF, gotCID, err := crof.RenderWithCID(res, trustPolicyCID, attCIDs, crof.RenderOptions{ResolverID: "xdao-resolver-reference"})
		if err != nil {
			t.Fatalf("crof.RenderWithCID: %v", err)
		}
		canon, err := crof.CanonicalizeCROF(gotCROF)
		if err != nil {
			t.Fatalf("CanonicalizeCROF(output): %v", err)
		}
		if !bytes.Equal(canon, gotCROF) {
			t.Fatalf("crof output is not canonical")
		}
		if gotCID != wantCID {
			t.Fatalf("CROF CID mismatch: got %s want %s", gotCID, wantCID)
		}
		if !bytes.Equal(gotCROF, wantCROF) {
			t.Fatalf("CROF bytes mismatch vs conformance vector")
		}
	}
}
