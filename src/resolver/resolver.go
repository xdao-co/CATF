// Package resolver implements the Deterministic Resolver Contract (DRC).
//
// API stability: see STABILITY.md (repository root) for Stable vs Experimental tiers.
package resolver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"

	"xdao.co/catf/catf"
	"xdao.co/catf/compliance"
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
	Verdicts   []Verdict

	// PolicyVerdicts materialize trust-policy requirement evaluation as durable evidence.
	// This allows consumers to distinguish missing/insufficient evidence from other failures
	// without re-running the resolver.
	PolicyVerdicts []PolicyVerdict
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
	CID       string
	InputHash string // stable handle for invalid/unparseable inputs (not a CATF CID)
	Reason    string
}

type VerdictStatus string

const (
	VerdictTrusted  VerdictStatus = "Trusted"
	VerdictExcluded VerdictStatus = "Excluded"
	VerdictInvalid  VerdictStatus = "Invalid"
	VerdictRevoked  VerdictStatus = "Revoked"

	// VerdictUntrusted is retained for compatibility; "Excluded" is the canonical status.
	VerdictUntrusted VerdictStatus = VerdictExcluded
)

// Verdict is an explicit per-attestation policy/trust evaluation record.
//
// These are intended to be surfaced as evidence (e.g. in CROF) so callers do
// not need to reverse-engineer resolver decisions from a final Path/Fork alone.
type Verdict struct {
	CID                string
	InputHash          string // stable handle for invalid/unparseable inputs (not a CATF CID)
	AttestedSubjectCID string
	IssuerKey          string
	ClaimType          string

	Trusted    bool
	TrustRoles []string
	Revoked    bool
	RevokedBy  []string

	// Status and Reasons are explicit, durable evidence of why this attestation was trusted,
	// rejected, revoked, or considered invalid.
	Status  VerdictStatus
	Reasons []string

	ExcludedReason string // retained for compatibility; also included in Reasons when set
}

type attestation struct {
	catf       *catf.CATF
	cid        string
	trusted    bool
	trustRoles map[string]bool
	revoked    bool
	revokedBy  []string
}

// inputHash computes a stable, non-CID handle for raw input bytes.
// This is used only when an attestation has no CATF identity (e.g. parse/canonicalization failure).
func inputHash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Resolve parses inputs and produces a deterministic resolution for a single subject CID.
//
// This v1 reference resolver supports the spec's reference test vectors:
// authorship, approval, supersedes, revocation.
func Resolve(attestationBytes [][]byte, policyBytes []byte, subjectCID string) (*Resolution, error) {
	policy, err := tpdl.ParseWithCompliance(policyBytes, compliance.Permissive)
	if err != nil {
		return nil, err
	}
	return resolveWithPolicy(attestationBytes, policy, subjectCID)
}

func resolveWithPolicy(attestationBytes [][]byte, policy *tpdl.Policy, subjectCID string) (*Resolution, error) {
	trustIndex := indexTrust(policy)

	var atts []*attestation
	var exclusions []Exclusion
	var verdicts []Verdict
	verdictIndex := make(map[string]int)

	for _, b := range attestationBytes {
		v := Verdict{}
		a, perr := catf.Parse(b)
		if perr != nil {
			v.CID = ""
			v.InputHash = inputHash(b)
			v.Status = VerdictInvalid
			v.ExcludedReason = "CATF parse/canonicalization failed"
			v.Reasons = []string{v.ExcludedReason}
			verdicts = append(verdicts, v)
			exclusions = append(exclusions, Exclusion{CID: v.CID, InputHash: v.InputHash, Reason: v.ExcludedReason})
			continue
		}
		cid, err := a.CID()
		if err != nil {
			v.CID = ""
			v.InputHash = inputHash(b)
			v.Status = VerdictInvalid
			v.ExcludedReason = "CATF parse/canonicalization failed"
			v.Reasons = []string{v.ExcludedReason}
			verdicts = append(verdicts, v)
			exclusions = append(exclusions, Exclusion{CID: v.CID, InputHash: v.InputHash, Reason: v.ExcludedReason})
			continue
		}
		v.CID = cid
		v.AttestedSubjectCID = a.SubjectCID()
		v.IssuerKey = a.IssuerKey()
		v.ClaimType = a.ClaimType()
		if err := catf.ValidateCoreClaims(a); err != nil {
			v.Status = VerdictInvalid
			v.ExcludedReason = stableCATFReason(err)
			v.Reasons = []string{v.ExcludedReason}
			verdicts = append(verdicts, v)
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: v.ExcludedReason})
			continue
		}
		if err := a.Verify(); err != nil {
			v.Status = VerdictInvalid
			v.ExcludedReason = "Signature invalid"
			v.Reasons = []string{v.ExcludedReason}
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
			v.Status = VerdictTrusted
			v.Reasons = []string{"Issuer trusted by policy"}
		} else {
			v.Status = VerdictExcluded
			v.ExcludedReason = "Issuer not trusted"
			v.Reasons = []string{v.ExcludedReason}
			exclusions = append(exclusions, Exclusion{CID: cid, Reason: v.ExcludedReason})
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
				v.Trusted = false
				v.TrustRoles = nil
				v.Status = VerdictExcluded
				v.ExcludedReason = "Supersedes not allowed by policy"
				v.Reasons = []string{v.ExcludedReason}
				exclusions = append(exclusions, Exclusion{CID: cid, Reason: v.ExcludedReason})
			}
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
			if len(a.revokedBy) > 0 {
				verdicts[idx].RevokedBy = appendUniqueSorted(append([]string(nil), a.revokedBy...))
			}
			// Preserve existing trust fields, but make revocation explicit in status/reasons.
			verdicts[idx].Status = VerdictRevoked
			verdicts[idx].Reasons = appendUniqueSorted(verdicts[idx].Reasons, "Revoked")
		}
	}
	for i := range verdicts {
		verdicts[i].Reasons = appendUniqueSorted(verdicts[i].Reasons)
	}
	sort.SliceStable(verdicts, func(i, j int) bool { return verdictLessV2(verdicts[i], verdicts[j]) })

	// Only consider attestations about this subject.
	var subjectAtts []*attestation
	for _, a := range atts {
		if a.catf.SubjectCID() == subjectCID {
			subjectAtts = append(subjectAtts, a)
		}
	}

	res := &Resolution{SubjectCID: subjectCID, Confidence: ConfidenceUndefined, Exclusions: exclusions, Verdicts: verdicts}
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

	policyVerdicts, ok := evaluatePolicyRules(policy, activeTrustedClaims, "")
	res.PolicyVerdicts = policyVerdicts
	if !ok {
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

func stableCATFReason(err error) string {
	if err == nil {
		return ""
	}
	var e *catf.Error
	if errors.As(err, &e) {
		if e.RuleID != "" {
			return e.RuleID
		}
	}
	return err.Error()
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
			t.revokedBy = appendUniqueSorted(t.revokedBy, a.cid)
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

func rulesSatisfiedForType(policy *tpdl.Policy, activeTrusted []*attestation, typ string) bool {
	if policy == nil || len(policy.Rules) == 0 {
		return true
	}
	relevant := false
	for _, r := range policy.Rules {
		if r.Type == typ {
			relevant = true
			break
		}
	}
	if !relevant {
		return true
	}

	typeRoleToKeys := make(map[string]map[string]bool)
	for _, a := range activeTrusted {
		if a.catf.ClaimType() != typ {
			continue
		}
		issuer := a.catf.IssuerKey()
		for role := range a.trustRoles {
			key := typ + "|" + role
			m := typeRoleToKeys[key]
			if m == nil {
				m = make(map[string]bool)
				typeRoleToKeys[key] = m
			}
			m[issuer] = true
		}
	}

	for _, r := range policy.Rules {
		if r.Type != typ {
			continue
		}
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
