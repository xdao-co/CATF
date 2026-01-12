// Package resolver implements the Deterministic Resolver Contract (DRC).
package resolver

import (
	"sort"

	"xdao.co/catf/catf"
	"xdao.co/catf/cidutil"
	"xdao.co/catf/tpdl"
)

type State string

const (
	StateResolved   State = "Resolved"
	StateForked     State = "Forked"
	StateUnresolved State = "Unresolved"
	StateRevoked    State = "Revoked"
)

type Confidence string

const (
	ConfidenceHigh      Confidence = "High"
	ConfidenceMedium    Confidence = "Medium"
	ConfidenceLow       Confidence = "Low"
	ConfidenceUndefined Confidence = "Undefined"
)

type Resolution struct {
	SubjectCID string
	State      State
	Confidence Confidence

	Paths      []Path
	Forks      []Fork
	Exclusions []Exclusion
}

type Path struct {
	ID   string
	CIDs []string
}

type Fork struct {
	ID              string
	ConflictingPath []string
}

type Exclusion struct {
	CID    string
	Reason string
}

type attestation struct {
	catf       *catf.CATF
	cid        string
	trusted    bool
	trustRoles map[string]bool
	revoked    bool
}

// Resolve parses inputs and produces a deterministic resolution for a single subject CID.
//
// This v1 reference resolver supports the spec's reference test vectors:
// authorship, approval, supersedes, revocation.
func Resolve(attestationBytes [][]byte, policyBytes []byte, subjectCID string) (*Resolution, error) {
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
			exclusions = append(exclusions, Exclusion{CID: cidutil.CIDv1RawSHA256(b), Reason: "CATF parse/canonicalization failed"})
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
		if roles, ok := trustIndex[a.IssuerKey()]; ok {
			att.trusted = true
			att.trustRoles = roles
		} else {
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: "Issuer not trusted"})
		}
		if att.trusted && a.ClaimType() == "supersedes" && len(policy.SupersedesAllowedBy) > 0 {
			allowed := false
			for _, role := range policy.SupersedesAllowedBy {
				if att.trustRoles[role] {
					allowed = true
					break
				}
			}
			if !allowed {
				att.trusted = false
				exclusions = append(exclusions, Exclusion{CID: cid, Reason: "Supersedes not allowed by policy"})
			}
		}
		atts = append(atts, att)
	}

	sort.Slice(atts, func(i, j int) bool { return atts[i].cid < atts[j].cid })
	applyRevocations(atts)

	// Only consider attestations about this subject.
	var subjectAtts []*attestation
	for _, a := range atts {
		if a.catf.SubjectCID() == subjectCID {
			subjectAtts = append(subjectAtts, a)
		}
	}

	res := &Resolution{SubjectCID: subjectCID, Confidence: ConfidenceUndefined, Exclusions: exclusions}
	if len(subjectAtts) == 0 {
		res.State = StateUnresolved
		return res, nil
	}

	var activeTrusted []*attestation
	for _, a := range subjectAtts {
		if a.trusted && !a.revoked {
			activeTrusted = append(activeTrusted, a)
		}
	}

	// Revocations affect trust but should not count as active semantic claims.
	var activeTrustedClaims []*attestation
	for _, a := range activeTrusted {
		if a.catf.ClaimType() == "revocation" {
			continue
		}
		activeTrustedClaims = append(activeTrustedClaims, a)
	}

	if len(activeTrustedClaims) == 0 {
		anyRevoked := false
		for _, a := range subjectAtts {
			if a.revoked {
				anyRevoked = true
				break
			}
		}
		if anyRevoked {
			res.State = StateRevoked
		} else {
			res.State = StateUnresolved
		}
		return res, nil
	}

	if !rulesSatisfied(policy, activeTrustedClaims) {
		res.State = StateUnresolved
		return res, nil
	}

	paths, forks := buildPaths(policy, activeTrustedClaims)
	res.Paths = paths
	res.Forks = forks

	if len(forks) > 0 {
		res.State = StateForked
		res.Confidence = ConfidenceMedium
		return res, nil
	}

	res.State = StateResolved
	res.Confidence = ConfidenceHigh
	return res, nil
}

func indexTrust(policy *tpdl.Policy) map[string]map[string]bool {
	idx := make(map[string]map[string]bool)
	for _, t := range policy.Trust {
		m := idx[t.Key]
		if m == nil {
			m = make(map[string]bool)
			idx[t.Key] = m
		}
		m[t.Role] = true
	}
	return idx
}

func applyRevocations(atts []*attestation) {
	byCID := make(map[string]*attestation)
	for _, a := range atts {
		byCID[a.cid] = a
	}
	for _, a := range atts {
		if !a.trusted {
			continue
		}
		if a.catf.ClaimType() != "revocation" {
			continue
		}
		target := a.catf.Sections["CLAIMS"].Pairs["Target-Attestation"]
		if target == "" {
			continue
		}
		if t, ok := byCID[target]; ok {
			t.revoked = true
		}
	}
}

func rulesSatisfied(policy *tpdl.Policy, activeTrusted []*attestation) bool {
	if len(policy.Rules) == 0 {
		return true
	}
	typeRoleToKeys := make(map[string]map[string]bool)
	for _, a := range activeTrusted {
		issuer := a.catf.IssuerKey()
		for role := range a.trustRoles {
			key := a.catf.ClaimType() + "|" + role
			m := typeRoleToKeys[key]
			if m == nil {
				m = make(map[string]bool)
				typeRoleToKeys[key] = m
			}
			m[issuer] = true
		}
	}
	for _, r := range policy.Rules {
		q := r.Quorum
		if q < 1 {
			q = 1
		}
		key := r.Type + "|" + r.Role
		m := typeRoleToKeys[key]
		count := 0
		for range m {
			count++
		}
		if count < q {
			return false
		}
	}
	return true
}

func buildPaths(policy *tpdl.Policy, activeTrusted []*attestation) ([]Path, []Fork) {
	// Model supersession using CLAIMS: Supersedes: <CID>
	supersedes := make(map[string]string)
	for _, a := range activeTrusted {
		if a.catf.ClaimType() == "supersedes" {
			t := a.catf.Sections["CLAIMS"].Pairs["Supersedes"]
			if t != "" {
				supersedes[a.cid] = t
			}
		}
	}

	// If supersession is present, treat non-superseded attestations as path heads.
	if len(supersedes) > 0 {
		superseded := make(map[string]bool)
		for _, target := range supersedes {
			superseded[target] = true
		}
		var heads []string
		for _, a := range activeTrusted {
			if !superseded[a.cid] {
				heads = append(heads, a.cid)
			}
		}
		sort.Strings(heads)

		var paths []Path
		for i, head := range heads {
			id := "path-" + itoa(i+1)
			var cids []string
			seen := make(map[string]bool)
			cur := head
			for cur != "" {
				if seen[cur] {
					break
				}
				seen[cur] = true
				cids = append(cids, cur)
				cur = supersedes[cur]
			}
			paths = append(paths, Path{ID: id, CIDs: cids})
		}

		var forks []Fork
		if len(paths) > 1 {
			fork := Fork{ID: "fork-1"}
			for _, p := range paths {
				fork.ConflictingPath = append(fork.ConflictingPath, p.ID)
			}
			forks = append(forks, fork)
		}
		return paths, forks
	}

	// No supersession: only treat competing authorship attestations as forks.
	// Additionally, if the trust policy requires a single attestation (Quorum=1)
	// for a specific (Type, Role), and multiple trusted candidates exist, surface
	// the ambiguity as a fork rather than silently combining.
	if policy != nil {
		type roleKey struct{ typ, role string }
		ambiguous := make(map[roleKey][]string)
		for _, r := range policy.Rules {
			q := r.Quorum
			if q < 1 {
				q = 1
			}
			if q != 1 {
				continue
			}
			k := roleKey{typ: r.Type, role: r.Role}
			for _, a := range activeTrusted {
				if a.catf.ClaimType() != r.Type {
					continue
				}
				if !a.trustRoles[r.Role] {
					continue
				}
				ambiguous[k] = append(ambiguous[k], a.cid)
			}
		}

		// Pick the first ambiguous rule (deterministically) and fork only across
		// its candidates to avoid combinatorial explosion.
		var keys []roleKey
		for k, cids := range ambiguous {
			if len(cids) > 1 {
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 {
			sort.Slice(keys, func(i, j int) bool {
				if keys[i].typ == keys[j].typ {
					return keys[i].role < keys[j].role
				}
				return keys[i].typ < keys[j].typ
			})
			k := keys[0]
			cands := ambiguous[k]
			sort.Strings(cands)

			candidateSet := make(map[string]bool)
			for _, cid := range cands {
				candidateSet[cid] = true
			}
			var others []string
			for _, a := range activeTrusted {
				if !candidateSet[a.cid] {
					others = append(others, a.cid)
				}
			}
			sort.Strings(others)

			var paths []Path
			for i, cid := range cands {
				ids := append([]string{cid}, others...)
				paths = append(paths, Path{ID: "path-" + itoa(i+1), CIDs: ids})
			}
			fork := Fork{ID: "fork-1"}
			for _, p := range paths {
				fork.ConflictingPath = append(fork.ConflictingPath, p.ID)
			}
			return paths, []Fork{fork}
		}
	}

	var allCIDs []string
	allAuthorship := true
	for _, a := range activeTrusted {
		allCIDs = append(allCIDs, a.cid)
		if a.catf.ClaimType() != "authorship" {
			allAuthorship = false
		}
	}
	sort.Strings(allCIDs)

	if allAuthorship {
		// Each authorship attestation is a distinct path; multiple implies a fork.
		var paths []Path
		for i, cid := range allCIDs {
			paths = append(paths, Path{ID: "path-" + itoa(i+1), CIDs: []string{cid}})
		}
		var forks []Fork
		if len(paths) > 1 {
			fork := Fork{ID: "fork-1"}
			for _, p := range paths {
				fork.ConflictingPath = append(fork.ConflictingPath, p.ID)
			}
			forks = append(forks, fork)
		}
		return paths, forks
	}

	// Otherwise, consider the set compatible and produce one combined path.
	return []Path{{ID: "path-1", CIDs: allCIDs}}, nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [32]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + (i % 10))
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
