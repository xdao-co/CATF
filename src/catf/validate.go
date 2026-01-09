package catf

import (
	"errors"
	"fmt"
)

// ValidateCoreClaims enforces the v1 core required claims per attestation type.
// This is separate from Parse() so callers can choose whether missing semantics
// are treated as parse failures or as exclusions.
func ValidateCoreClaims(a *CATF) error {
	claims, ok := a.Sections["CLAIMS"]
	if !ok {
		return errors.New("missing CLAIMS")
	}
	typ := claims.Pairs["Type"]
	if typ == "" {
		return errors.New("missing required claim: Type")
	}

	req := func(key string) error {
		if claims.Pairs[key] == "" {
			return fmt.Errorf("missing required claim: %s", key)
		}
		return nil
	}

	switch typ {
	case "authorship":
		return req("Role")
	case "approval":
		if err := req("Role"); err != nil {
			return err
		}
		return req("Effective-Date")
	case "supersedes":
		return req("Supersedes")
	case "revocation":
		return req("Target-Attestation")
	case "name-binding":
		if err := req("Name"); err != nil {
			return err
		}
		if err := req("Version"); err != nil {
			return err
		}
		return req("Points-To")
	default:
		// Unknown claim types are permitted; this function only validates v1 core.
		return nil
	}
}
