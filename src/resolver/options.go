package resolver

import (
	"fmt"

	"xdao.co/catf/compliance"
)

// Options controls resolver compliance behavior.
//
// Default behavior is Permissive when Options{} is used.
type Options struct {
	Mode compliance.ComplianceMode
}

func (o Options) withDefaults() Options {
	if o.Mode == 0 {
		// compliance.Permissive is the zero value.
		return o
	}
	return o
}

func enforceStrictResolution(res *Resolution) error {
	if len(res.Exclusions) > 0 {
		return fmt.Errorf("strict mode: exclusions present (%d)", len(res.Exclusions))
	}
	if res.State != StateResolved {
		return fmt.Errorf("strict mode: expected StateResolved, got %s", res.State)
	}
	return nil
}

func enforceStrictNameResolution(res *NameResolution) error {
	if len(res.Exclusions) > 0 {
		return fmt.Errorf("strict mode: exclusions present (%d)", len(res.Exclusions))
	}
	if res.State != StateResolved {
		return fmt.Errorf("strict mode: expected StateResolved, got %s", res.State)
	}
	return nil
}
