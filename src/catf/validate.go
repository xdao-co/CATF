package catf

import (
	"fmt"
)

// ValidateCoreClaims enforces the v1 core required claims per attestation type.
// This is separate from Parse() so callers can choose whether missing semantics
// are treated as parse failures or as exclusions.
func ValidateCoreClaims(a *CATF) error {
	claims, ok := a.Sections["CLAIMS"]
	if !ok {
		return newError(KindValidation, "CATF-VAL-101", "missing CLAIMS")
	}
	typ := claims.Pairs["Type"]
	if typ == "" {
		return newError(KindValidation, "CATF-VAL-102", "missing required claim: Type")
	}

	required := func(ruleID, key string) Rule {
		return Rule{ID: ruleID, Apply: func(_ *CATF) error {
			if claims.Pairs[key] == "" {
				return newError(KindValidation, ruleID, fmt.Sprintf("missing required claim: %s", key))
			}
			return nil
		}}
	}

	// Deterministic evaluation order per claim type.
	var rules []Rule
	switch typ {
	case "authorship":
		rules = []Rule{required("CATF-VAL-201", "Role")}
	case "approval":
		rules = []Rule{required("CATF-VAL-211", "Role"), required("CATF-VAL-212", "Effective-Date")}
	case "supersedes":
		rules = []Rule{required("CATF-VAL-221", "Supersedes")}
	case "revocation":
		rules = []Rule{required("CATF-VAL-231", "Target-Attestation")}
	case "name-binding":
		rules = []Rule{required("CATF-VAL-241", "Name"), required("CATF-VAL-242", "Version"), required("CATF-VAL-243", "Points-To")}
	default:
		// Unknown claim types are permitted; this function only validates v1 core.
		return nil
	}

	// Ensure the rule IDs are set (defensive), then evaluate.
	for _, r := range rules {
		if r.ID == "" {
			return newError(KindInternal, "CATF-INTERNAL-002", "empty validation rule ID")
		}
	}
	return ValidateRules(a, rules)
}
