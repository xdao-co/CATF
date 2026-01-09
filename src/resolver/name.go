package resolver

import (
	"sort"

	"xdao.co/catf/catf"
	"xdao.co/catf/tpdl"
)

type NameResolution struct {
	Name    string
	Version string

	State      State
	Confidence Confidence

	PointsTo string

	// Head binding CIDs (one when Resolved, multiple when Forked)
	Bindings []string

	Forks      []NameFork
	Exclusions []Exclusion
}

type NameFork struct {
	ID                 string
	ConflictingBinding []string
}

// ResolveName deterministically resolves a symbolic name (and optional version)
// per ReferenceDesign.md §5.1.
func ResolveName(attestationBytes [][]byte, policyBytes []byte, name, version string) (*NameResolution, error) {
	policy, err := tpdl.Parse(policyBytes)
	if err != nil {
		return nil, err
	}
	trustIndex := indexTrust(policy)

	var atts []*attestation
	var exclusions []Exclusion

	for _, b := range attestationBytes {
		a, perr := catf.Parse(b)
		if perr != nil {
			exclusions = append(exclusions, Exclusion{Reason: "CATF parse/canonicalization failed"})
			continue
		}
		cid := a.CID()
		if err := catf.ValidateCoreClaims(a); err != nil {
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: err.Error()})
			continue
		}
		if err := a.Verify(); err != nil {
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: "Signature invalid"})
			continue
		}
		att := &attestation{catf: a, cid: cid}
		if role, ok := trustIndex[a.IssuerKey()]; ok {
			att.trusted = true
			att.trustRole = role
		}
		atts = append(atts, att)
	}

	sort.Slice(atts, func(i, j int) bool { return atts[i].cid < atts[j].cid })
	applyRevocations(atts)

	res := &NameResolution{Name: name, Version: version, Confidence: ConfidenceUndefined, Exclusions: exclusions}

	// Collect all name-binding attestations for the requested name (+ optional version).
	var candidates []*attestation
	anyRevoked := false
	for _, a := range atts {
		if !a.trusted {
			continue
		}
		if a.catf.ClaimType() != "name-binding" {
			continue
		}
		c := a.catf.Sections["CLAIMS"].Pairs
		if c["Name"] != name {
			continue
		}
		if version != "" && c["Version"] != version {
			continue
		}
		if a.revoked {
			anyRevoked = true
			continue
		}
		candidates = append(candidates, a)
	}

	if len(candidates) == 0 {
		if anyRevoked {
			res.State = StateRevoked
		} else {
			res.State = StateUnresolved
		}
		return res, nil
	}

	// Construct supersession DAG among name-bindings.
	// A name-binding may optionally include CLAIMS: Supersedes: <CID> to supersede an older binding.
	supersedes := make(map[string]string)
	superseded := make(map[string]bool)
	candidateSet := make(map[string]bool)
	for _, a := range candidates {
		candidateSet[a.cid] = true
	}
	for _, a := range candidates {
		old := a.catf.Sections["CLAIMS"].Pairs["Supersedes"]
		if old == "" {
			continue
		}
		if !candidateSet[old] {
			continue
		}
		supersedes[a.cid] = old
		superseded[old] = true
	}

	var heads []string
	for _, a := range candidates {
		if !superseded[a.cid] {
			heads = append(heads, a.cid)
		}
	}
	sort.Strings(heads)
	res.Bindings = heads

	if len(heads) == 1 {
		// Selected binding.
		selectedCID := heads[0]
		for _, a := range candidates {
			if a.cid == selectedCID {
				res.PointsTo = a.catf.Sections["CLAIMS"].Pairs["Points-To"]
				break
			}
		}
		res.State = StateResolved
		res.Confidence = ConfidenceHigh
		return res, nil
	}

	res.State = StateForked
	res.Confidence = ConfidenceMedium
	res.Forks = []NameFork{{ID: "name-fork-1", ConflictingBinding: heads}}
	return res, nil
}
