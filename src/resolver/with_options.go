package resolver

import "xdao.co/catf/compliance"

// ResolveWithOptions runs Resolve and then applies the requested compliance mode.
//
// This is intentionally layered on top of the v1 reference resolver so we can
// keep its behavior stable while giving callers an explicit knob.
func ResolveWithOptions(attestationBytes [][]byte, policyBytes []byte, subjectCID string, opts Options) (*Resolution, error) {
	opts = opts.withDefaults()
	res, err := Resolve(attestationBytes, policyBytes, subjectCID)
	if err != nil {
		return nil, err
	}
	if opts.Mode == compliance.Strict {
		if err := enforceStrictResolution(res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// ResolveNameWithOptions runs ResolveName and then applies the requested compliance mode.
func ResolveNameWithOptions(attestationBytes [][]byte, policyBytes []byte, name, version string, opts Options) (*NameResolution, error) {
	opts = opts.withDefaults()
	res, err := ResolveName(attestationBytes, policyBytes, name, version)
	if err != nil {
		return nil, err
	}
	if opts.Mode == compliance.Strict {
		if err := enforceStrictNameResolution(res); err != nil {
			return nil, err
		}
	}
	return res, nil
}
