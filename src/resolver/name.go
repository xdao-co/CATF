package resolver

import (
	"sort"

	"xdao.co/catf/catf"
	"xdao.co/catf/cidutil"
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
	Verdicts   []Verdict
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
	var verdicts []Verdict
	verdictIndex := make(map[string]int)

	for _, b := range attestationBytes {
		v := Verdict{}
		a, perr := catf.Parse(b)
		if perr != nil {
			v.CID = cidutil.CIDv1RawSHA256(b)
			v.ExcludedReason = "CATF parse/canonicalization failed"
			verdicts = append(verdicts, v)
			exclusions = append(exclusions, Exclusion{CID: v.CID, Reason: v.ExcludedReason})
			continue
		}
		cid := a.CID()
		v.CID = cid
		v.IssuerKey = a.IssuerKey()
		v.ClaimType = a.ClaimType()
		if err := catf.ValidateCoreClaims(a); err != nil {
			v.ExcludedReason = err.Error()
			verdicts = append(verdicts, v)
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: v.ExcludedReason})
			continue
		}
		if err := a.Verify(); err != nil {
			v.ExcludedReason = "Signature invalid"
			verdicts = append(verdicts, v)
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: v.ExcludedReason})
			continue
		}
		att := &attestation{catf: a, cid: cid}
		if roles, ok := trustIndex[a.IssuerKey()]; ok {
			att.trusted = true
			att.trustRoles = roles
			v.Trusted = true
			for r := range roles {
				v.TrustRoles = append(v.TrustRoles, r)
			}
			sort.Strings(v.TrustRoles)
		} else {
			v.ExcludedReason = "Issuer not trusted"
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: v.ExcludedReason})
		}
		verdictIndex[cid] = len(verdicts)
		verdicts = append(verdicts, v)
		atts = append(atts, att)
	}

	sort.Slice(atts, func(i, j int) bool { return atts[i].cid < atts[j].cid })
	applyRevocations(atts)
	for _, a := range atts {
		if !a.revoked {
			continue
		}
		if idx, ok := verdictIndex[a.cid]; ok {
			verdicts[idx].Revoked = true
		}
	}
	sort.Slice(verdicts, func(i, j int) bool {
		if verdicts[i].CID == verdicts[j].CID {
			return verdicts[i].ExcludedReason < verdicts[j].ExcludedReason
		}
		return verdicts[i].CID < verdicts[j].CID
	})

	res := &NameResolution{Name: name, Version: version, Confidence: ConfidenceUndefined, Exclusions: exclusions, Verdicts: verdicts}

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
