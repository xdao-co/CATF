package crof

import (
	"testing"

	"xdao.co/catf/resolver"
)

func TestValidateSupersession_OK(t *testing.T) {
	oldRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateUnresolved, Confidence: resolver.ConfidenceUndefined}
	oldBytes := Render(oldRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})
	oldCID, err := CID(oldBytes)
	if err != nil {
		t.Fatalf("CID(old): %v", err)
	}

	newRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	newBytes := Render(newRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference", SupersedesCROFCID: oldCID})

	if err := ValidateSupersession(newBytes, oldBytes); err != nil {
		t.Fatalf("ValidateSupersession: %v", err)
	}
}

func TestValidateSupersession_RejectsDifferentSubject(t *testing.T) {
	oldRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateUnresolved, Confidence: resolver.ConfidenceUndefined}
	oldBytes := Render(oldRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})
	oldCID, err := CID(oldBytes)
	if err != nil {
		t.Fatalf("CID(old): %v", err)
	}

	newRes := &resolver.Resolution{SubjectCID: "bafy-doc-2", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	newBytes := Render(newRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference", SupersedesCROFCID: oldCID})

	if err := ValidateSupersession(newBytes, oldBytes); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateSupersession_RejectsMissingSupersedesField(t *testing.T) {
	oldRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateUnresolved, Confidence: resolver.ConfidenceUndefined}
	oldBytes := Render(oldRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})

	newRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	newBytes := Render(newRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})

	if err := ValidateSupersession(newBytes, oldBytes); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateSupersession_RejectsWrongSupersedesCID(t *testing.T) {
	oldRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateUnresolved, Confidence: resolver.ConfidenceUndefined}
	oldBytes := Render(oldRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})

	newRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	newBytes := Render(newRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference", SupersedesCROFCID: "bafy-not-the-old-cid"})

	if err := ValidateSupersession(newBytes, oldBytes); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateSupersession_RejectsDifferentResolverID(t *testing.T) {
	oldRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateUnresolved, Confidence: resolver.ConfidenceUndefined}
	oldBytes := Render(oldRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})
	oldCID, err := CID(oldBytes)
	if err != nil {
		t.Fatalf("CID(old): %v", err)
	}

	newRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	newBytes := Render(newRes, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-other", SupersedesCROFCID: oldCID})

	if err := ValidateSupersession(newBytes, oldBytes); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateSupersession_RejectsDifferentTrustPolicyCID(t *testing.T) {
	oldRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateUnresolved, Confidence: resolver.ConfidenceUndefined}
	oldBytes := Render(oldRes, "bafy-policy-1", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})
	target, err := CID(oldBytes)
	if err != nil {
		t.Fatalf("CID(old): %v", err)
	}

	newRes := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	newBytes := Render(newRes, "bafy-policy-2", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference", SupersedesCROFCID: target})

	if err := ValidateSupersession(newBytes, oldBytes); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateSupersession_RejectsIdenticalBytes(t *testing.T) {
	res := &resolver.Resolution{SubjectCID: "bafy-doc-1", State: resolver.StateResolved, Confidence: resolver.ConfidenceHigh}
	bytes := Render(res, "bafy-policy", []string{"bafy-a1"}, RenderOptions{ResolverID: "xdao-resolver-reference"})
	if err := ValidateSupersession(bytes, bytes); err == nil {
		t.Fatalf("expected error")
	}
}
