package resolver

import "testing"

func TestResolveStrict_RejectsPolicyMissingExplicitQuorum(t *testing.T) {
	subject := "bafy-strict-policy-quorum"
	pub, priv := mustKeypair(t, 0x44)
	issuer := issuerKey(pub)

	att := mustAttestation(t, subject, "Doc", map[string]string{"Type": "authorship", "Role": "author"}, issuer, priv)

	// Valid-permissive policy: Require block omits Quorum (defaults to 1).
	// Strict mode must reject because it forbids defaults.
	policy := "" +
		"-----BEGIN XDAO TRUST POLICY-----\n" +
		"META\n" +
		"Spec: xdao-tpdl-1\n" +
		"Version: 1\n\n" +
		"TRUST\n" +
		"Key: " + issuer + "\n" +
		"Role: author\n\n" +
		"RULES\n" +
		"Require:\n" +
		"  Type: authorship\n" +
		"  Role: author\n" +
		"\n" +
		"-----END XDAO TRUST POLICY-----\n"

	// Permissive mode should succeed.
	res, err := Resolve([][]byte{att}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}

	// Strict mode should reject at policy parsing.
	if _, err := ResolveStrict([][]byte{att}, []byte(policy), subject); err == nil {
		t.Fatalf("expected strict mode error")
	}
}

func TestResolveNameStrict_RejectsPolicyMissingExplicitQuorum(t *testing.T) {
	name := "xdao:test"
	version := "v1"
	pub, priv := mustKeypair(t, 0x45)
	issuer := issuerKey(pub)

	att := mustAttestation(t, "bafy-ignored", "Name", map[string]string{
		"Type":      "name-binding",
		"Name":      name,
		"Version":   version,
		"Points-To": "bafy-doc-1",
	}, issuer, priv)

	policy := "" +
		"-----BEGIN XDAO TRUST POLICY-----\n" +
		"META\n" +
		"Spec: xdao-tpdl-1\n" +
		"Version: 1\n\n" +
		"TRUST\n" +
		"Key: " + issuer + "\n" +
		"Role: author\n\n" +
		"RULES\n" +
		"Require:\n" +
		"  Type: name-binding\n" +
		"  Role: author\n" +
		"\n" +
		"-----END XDAO TRUST POLICY-----\n"

	// Permissive mode should succeed.
	res, err := ResolveName([][]byte{att}, []byte(policy), name, version)
	if err != nil {
		t.Fatalf("ResolveName: %v", err)
	}
	if res.State != StateResolved {
		t.Fatalf("expected Resolved, got %s", res.State)
	}

	if _, err := ResolveNameStrict([][]byte{att}, []byte(policy), name, version); err == nil {
		t.Fatalf("expected strict mode error")
	}
}
