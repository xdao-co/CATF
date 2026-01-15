package tpdl

import (
	"testing"

	"xdao.co/catf/compliance"
)

const validTPDL = `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

Description: test

TRUST
Key: ed25519:AUTHOR_KEY
Role: author

RULES
Require:
  Type: authorship
  Role: author
-----END XDAO TRUST POLICY-----`

func TestParseValidTPDL(t *testing.T) {
	policy, err := Parse([]byte(validTPDL))
	if err != nil {
		t.Fatalf("expected valid TPDL, got error: %v", err)
	}
	if len(policy.Trust) != 1 || policy.Trust[0].Key != "ed25519:AUTHOR_KEY" {
		t.Errorf("expected trust entry for AUTHOR_KEY, got %+v", policy.Trust)
	}
	if len(policy.Rules) != 1 || policy.Rules[0].Type != "authorship" {
		t.Errorf("expected rule Type=authorship, got %+v", policy.Rules)
	}
}

func TestParseTPDL_Quorum(t *testing.T) {
	policyText := `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:K1
Role: board-member

RULES
Require:
  Type: approval
  Role: board-member
  Quorum: 3
-----END XDAO TRUST POLICY-----`

	policy, err := Parse([]byte(policyText))
	if err != nil {
		t.Fatalf("expected valid TPDL, got error: %v", err)
	}
	if len(policy.Rules) != 1 || policy.Rules[0].Quorum != 3 {
		t.Fatalf("expected quorum=3, got %+v", policy.Rules)
	}
}

func TestParseStrictTPDL_RequiresExplicitQuorum(t *testing.T) {
	// This policy omits Quorum; Parse() defaults it to 1, but strict parsing must reject.
	policy, err := Parse([]byte(validTPDL))
	if err != nil {
		t.Fatalf("Parse(validTPDL): %v", err)
	}
	if len(policy.Rules) != 1 || policy.Rules[0].Quorum != 1 {
		t.Fatalf("expected default quorum=1, got %+v", policy.Rules)
	}

	if _, err := ParseStrict([]byte(validTPDL)); err == nil {
		t.Fatalf("expected strict parse error")
	}
	if _, err := ParseWithCompliance([]byte(validTPDL), compliance.Strict); err == nil {
		t.Fatalf("expected strict parse error")
	}
}

func TestParseStrictTPDL_AllowsExplicitQuorumOne(t *testing.T) {
	policyText := `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:K1
Role: author

RULES
Require:
  Type: authorship
  Role: author
  Quorum: 1
-----END XDAO TRUST POLICY-----`

	if _, err := ParseStrict([]byte(policyText)); err != nil {
		t.Fatalf("expected strict parse ok, got %v", err)
	}
}

func TestParseInvalidTPDL_MissingPreamble(t *testing.T) {
	_, err := Parse([]byte("META\nVersion: 1\n"))
	if err == nil {
		t.Error("expected error for missing preamble")
	}
}

func TestParseInvalidTPDL_MissingMetaSpec(t *testing.T) {
	policyText := `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1

TRUST
Key: ed25519:K1
Role: author

RULES
Require:
  Type: authorship
  Role: author
-----END XDAO TRUST POLICY-----`

	_, err := Parse([]byte(policyText))
	if err == nil {
		t.Fatalf("expected error for missing META Spec")
	}
}

func TestParseTPDL_SupersedesAllowedBy(t *testing.T) {
	policyText := `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:K1
Role: buyer

RULES
Supersedes:
  Allowed-By: buyer, seller
-----END XDAO TRUST POLICY-----`

	policy, err := Parse([]byte(policyText))
	if err != nil {
		t.Fatalf("expected valid TPDL, got error: %v", err)
	}
	if len(policy.SupersedesAllowedBy) != 2 {
		t.Fatalf("expected 2 allowed-by roles, got %+v", policy.SupersedesAllowedBy)
	}
}

func TestParseInvalidTPDL_RequireUnknownField(t *testing.T) {
	policyText := `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:K1
Role: author

RULES
Require:
  Type: authorship
  Role: author
  Nope: 1
-----END XDAO TRUST POLICY-----`

	if _, err := Parse([]byte(policyText)); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseInvalidTPDL_InvalidQuorum(t *testing.T) {
	policyText := `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:K1
Role: author

RULES
Require:
  Type: authorship
  Role: author
  Quorum: 0
-----END XDAO TRUST POLICY-----`

	if _, err := Parse([]byte(policyText)); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseStrictTPDL_RejectsAnyRequireMissingQuorum(t *testing.T) {
	// First Require omits Quorum (permissive defaults to 1), second includes it.
	// Strict should reject because *any* Require block missing Quorum violates "no defaults".
	policyText := `-----BEGIN XDAO TRUST POLICY-----
META
Version: 1
Spec: xdao-tpdl-1

TRUST
Key: ed25519:K1
Role: author

RULES
Require:
  Type: authorship
  Role: author

Require:
  Type: approval
  Role: author
  Quorum: 1
-----END XDAO TRUST POLICY-----`

	if _, err := Parse([]byte(policyText)); err != nil {
		t.Fatalf("expected permissive Parse ok, got %v", err)
	}
	if _, err := ParseStrict([]byte(policyText)); err == nil {
		t.Fatalf("expected strict parse error")
	}
}
