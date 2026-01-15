package resolver

import (
	"bytes"
	"testing"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/compliance"
	"xdao.co/catf/storage"
)

type memCAS struct {
	m map[string][]byte
}

func newMemCAS() *memCAS {
	return &memCAS{m: make(map[string][]byte)}
}

func (c *memCAS) Put(b []byte) (cid.Cid, error) {
	id, err := cidutil.CIDv1RawSHA256CID(b)
	if err != nil {
		return cid.Undef, err
	}
	k := id.String()
	if existing, ok := c.m[k]; ok {
		if !bytes.Equal(existing, b) {
			return cid.Undef, storage.ErrImmutable
		}
		return id, nil
	}
	c.m[k] = append([]byte(nil), b...)
	return id, nil
}

func (c *memCAS) Get(id cid.Cid) ([]byte, error) {
	if !id.Defined() {
		return nil, storage.ErrInvalidCID
	}
	b, ok := c.m[id.String()]
	if !ok {
		return nil, storage.ErrNotFound
	}
	out := append([]byte(nil), b...)
	computed, err := cidutil.CIDv1RawSHA256CID(out)
	if err != nil {
		return nil, err
	}
	if computed != id {
		return nil, storage.ErrCIDMismatch
	}
	return out, nil
}

func (c *memCAS) Has(id cid.Cid) bool {
	if !id.Defined() {
		return false
	}
	_, ok := c.m[id.String()]
	return ok
}

func TestResolveWithCAS_HydratePolicyAndAttestations(t *testing.T) {
	subject := "bafybeigdyrzt4v5d5t2w7lkguux7t5nq4j3c5c2kz3xjbtg3v4d2z3o4sq" // stable-ish placeholder

	pub, priv := mustKeypair(t, 0x42)
	issuer := issuerKey(pub)

	policyBytes := []byte(trustPolicy(
		[]trustEntry{{key: issuer, role: "author"}},
		[]requireRule{{typ: "authorship", role: "author", quorum: 1}},
	))
	attBytes := mustAttestation(t, subject, "doc", map[string]string{
		"Type": "authorship",
		"Role": "author",
	}, issuer, priv)

	cas := newMemCAS()
	policyCID, err := cas.Put(policyBytes)
	if err != nil {
		t.Fatalf("Put policy failed: %v", err)
	}
	attCID, err := cas.Put(attBytes)
	if err != nil {
		t.Fatalf("Put att failed: %v", err)
	}

	got, err := ResolveWithCAS(ResolveRequestCAS{
		Attestations: []BlobRef{{CID: attCID}},
		Policy:       BlobRef{CID: policyCID},
		SubjectCID:   subject,
		Compliance:   compliance.Permissive,
		CAS:          cas,
	})
	if err != nil {
		t.Fatalf("ResolveWithCAS failed: %v", err)
	}

	want, err := Resolve([][]byte{attBytes}, policyBytes, subject)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if got.TrustPolicyCID == "" {
		t.Fatalf("expected TrustPolicyCID")
	}
	if got.AttestationIDs[0] != attCID.String() {
		t.Fatalf("unexpected AttestationIDs[0]: got %q want %q", got.AttestationIDs[0], attCID.String())
	}
	if got.Resolution.State != want.State || got.Resolution.Confidence != want.Confidence {
		t.Fatalf("resolution mismatch")
	}
}

func TestResolveWithCAS_MissingDataFailsExplicitly(t *testing.T) {
	missing, err := cidutil.CIDv1RawSHA256CID([]byte("missing"))
	if err != nil {
		t.Fatalf("CIDv1RawSHA256CID failed: %v", err)
	}

	_, err = ResolveWithCAS(ResolveRequestCAS{
		Attestations: []BlobRef{{CID: missing}},
		Policy:       BlobRef{Bytes: []byte(trustPolicy(nil, nil))},
		SubjectCID:   "bafy...",
		Compliance:   compliance.Permissive,
		CAS:          newMemCAS(),
	})
	if !storage.IsNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestResolveWithCAS_MultiAdapterOrderIsDeterministic(t *testing.T) {
	subject := "bafybeigdyrzt4v5d5t2w7lkguux7t5nq4j3c5c2kz3xjbtg3v4d2z3o4sq"

	pub, priv := mustKeypair(t, 0x11)
	issuer := issuerKey(pub)

	policyBytes := []byte(trustPolicy(
		[]trustEntry{{key: issuer, role: "author"}},
		[]requireRule{{typ: "authorship", role: "author", quorum: 1}},
	))
	attBytes := mustAttestation(t, subject, "doc", map[string]string{
		"Type": "authorship",
		"Role": "author",
	}, issuer, priv)

	present := newMemCAS()
	policyCID, _ := present.Put(policyBytes)
	attCID, _ := present.Put(attBytes)
	empty := newMemCAS()

	req := ResolveRequestCAS{
		Attestations: []BlobRef{{CID: attCID}},
		Policy:       BlobRef{CID: policyCID},
		SubjectCID:   subject,
		Compliance:   compliance.Permissive,
		CASAdapters:  []storage.CAS{empty, present},
	}
	a, err := ResolveWithCAS(req)
	if err != nil {
		t.Fatalf("ResolveWithCAS failed: %v", err)
	}

	req.CASAdapters = []storage.CAS{present, empty}
	b, err := ResolveWithCAS(req)
	if err != nil {
		t.Fatalf("ResolveWithCAS failed: %v", err)
	}

	if a.TrustPolicyCID != b.TrustPolicyCID {
		t.Fatalf("policy CID mismatch")
	}
	if a.Resolution.State != b.Resolution.State {
		t.Fatalf("resolution state mismatch")
	}
}
