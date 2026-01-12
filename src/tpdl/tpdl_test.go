package tpdl

import (
	"testing"
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
