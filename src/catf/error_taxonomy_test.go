package catf

import (
	"errors"
	"testing"
)

func TestParse_ErrorTaxonomy_UTF8RuleID(t *testing.T) {
	bad := []byte{0xff, 0xfe, 0xfd}
	_, err := Parse(bad)
	if err == nil {
		t.Fatalf("expected error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected structured *catf.Error, got %T", err)
	}
	if e.Kind != KindParse {
		t.Fatalf("expected KindParse, got %s", e.Kind)
	}
	if e.RuleID != "CATF-STR-001" {
		t.Fatalf("expected RuleID CATF-STR-001, got %s", e.RuleID)
	}
}

func TestParse_ErrorTaxonomy_CRLFRuleID(t *testing.T) {
	bad := []byte("-----BEGIN XDAO ATTESTATION-----\r\n")
	// Suffix checks will fail too, but CRLF is checked early.
	_, err := Parse(bad)
	if err == nil {
		t.Fatalf("expected error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected structured *catf.Error, got %T", err)
	}
	if e.RuleID != "CATF-CANON-001" {
		t.Fatalf("expected RuleID CATF-CANON-001, got %s", e.RuleID)
	}
}

func TestValidateCoreClaims_ErrorTaxonomy_RuleID(t *testing.T) {
	// Minimal valid structure; missing CLAIMS:Type triggers CATF-VAL-102.
	doc := Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": "bafy-doc-1", "Description": "d"},
		Claims:  map[string]string{},
		Crypto:  map[string]string{"Hash-Alg": "sha256", "Issuer-Key": "ed25519:AA==", "Signature": "AA==", "Signature-Alg": "ed25519"},
	}
	b, err := Render(doc)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed, err := Parse(b)
	if err == nil {
		// Parse will likely reject because signature fields aren't meaningful for Verify,
		// but Parse is structural/canonical; it should accept this if canonical.
		_ = parsed
	}
	// If Parse rejected due to canonical equivalence, skip (not expected).
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	verr := ValidateCoreClaims(parsed)
	if verr == nil {
		t.Fatalf("expected validation error")
	}
	var e *Error
	if !errors.As(verr, &e) {
		t.Fatalf("expected structured *catf.Error, got %T", verr)
	}
	if e.Kind != KindValidation {
		t.Fatalf("expected KindValidation, got %s", e.Kind)
	}
	if e.RuleID != "CATF-VAL-102" {
		t.Fatalf("expected RuleID CATF-VAL-102, got %s", e.RuleID)
	}
}

func TestCID_ErrorTaxonomy_NilReceiver(t *testing.T) {
	var c *CATF
	_, err := c.CID()
	if err == nil {
		t.Fatalf("expected error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected structured *catf.Error, got %T", err)
	}
	if e.Kind != KindCID {
		t.Fatalf("expected KindCID, got %s", e.Kind)
	}
	if e.RuleID != "CATF-CID-001" {
		t.Fatalf("expected RuleID CATF-CID-001, got %s", e.RuleID)
	}
}

func TestVerify_ErrorTaxonomy_MissingSignatureAlg(t *testing.T) {
	// Verify is expected to surface structured crypto errors with stable RuleIDs.
	// Omit Signature-Alg to force CATF-CRYPTO-101.
	doc := Document{
		Meta:    map[string]string{"Spec": "xdao-catf-1", "Version": "1"},
		Subject: map[string]string{"CID": "bafy-doc-1", "Description": "d"},
		Claims:  map[string]string{"Type": "authorship", "Role": "author"},
		Crypto:  map[string]string{"Hash-Alg": "sha256", "Issuer-Key": "ed25519:AA==", "Signature": "AA=="},
	}
	b, err := Render(doc)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	verr := parsed.Verify()
	if verr == nil {
		t.Fatalf("expected error")
	}
	var e *Error
	if !errors.As(verr, &e) {
		t.Fatalf("expected structured *catf.Error, got %T", verr)
	}
	if e.Kind != KindCrypto {
		t.Fatalf("expected KindCrypto, got %s", e.Kind)
	}
	if e.RuleID != "CATF-CRYPTO-101" {
		t.Fatalf("expected RuleID CATF-CRYPTO-101, got %s", e.RuleID)
	}
}
