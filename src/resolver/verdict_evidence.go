package resolver

import (
	"sort"
	"strings"

	"xdao.co/catf/tpdl"
)

// PolicyVerdict materializes the evaluation of a single trust-policy requirement.
//
// This is representation-only evidence. It does not change trust semantics.
// It exists so a future reader can answer "why unresolved?" without re-running the resolver.
type PolicyVerdict struct {
	Type   string
	Role   string
	Quorum int

	Observed   int
	IssuerKeys []string

	Satisfied bool
	Reasons   []string
}

func appendUniqueSorted(items []string, extra ...string) []string {
	if len(extra) > 0 {
		items = append(items, extra...)
	}
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, s := range items {
		if s == "" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func verdictLessV2(a, b Verdict) bool {
	if a.CID != b.CID {
		return a.CID < b.CID
	}
	if a.InputHash != b.InputHash {
		return a.InputHash < b.InputHash
	}
	if a.ExcludedReason != b.ExcludedReason {
		return a.ExcludedReason < b.ExcludedReason
	}
	if a.IssuerKey != b.IssuerKey {
		return a.IssuerKey < b.IssuerKey
	}
	if a.ClaimType != b.ClaimType {
		return a.ClaimType < b.ClaimType
	}
	if a.AttestedSubjectCID != b.AttestedSubjectCID {
		return a.AttestedSubjectCID < b.AttestedSubjectCID
	}
	if a.Status != b.Status {
		return a.Status < b.Status
	}
	if a.Trusted != b.Trusted {
		return a.Trusted && !b.Trusted
	}
	if a.Revoked != b.Revoked {
		return !a.Revoked && b.Revoked
	}
	if strings.Join(a.TrustRoles, ",") != strings.Join(b.TrustRoles, ",") {
		return strings.Join(a.TrustRoles, ",") < strings.Join(b.TrustRoles, ",")
	}
	if strings.Join(a.Reasons, ",") != strings.Join(b.Reasons, ",") {
		return strings.Join(a.Reasons, ",") < strings.Join(b.Reasons, ",")
	}
	return strings.Join(a.RevokedBy, ",") < strings.Join(b.RevokedBy, ",")
}

func evaluatePolicyRules(policy *tpdl.Policy, activeTrusted []*attestation, typFilter string) ([]PolicyVerdict, bool) {
	if policy == nil || len(policy.Rules) == 0 {
		return nil, true
	}

	relevant := false
	for _, r := range policy.Rules {
		if typFilter == "" || r.Type == typFilter {
			relevant = true
			break
		}
	}
	if !relevant {
		return nil, true
	}

	// Map (Type,Role) -> unique issuer keys that provide trusted evidence.
	typeRoleToKeys := make(map[string]map[string]bool)
	for _, a := range activeTrusted {
		if typFilter != "" && a.catf.ClaimType() != typFilter {
			continue
		}
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

	ok := true
	out := make([]PolicyVerdict, 0, len(policy.Rules))
	for _, r := range policy.Rules {
		if typFilter != "" && r.Type != typFilter {
			continue
		}
		q := r.Quorum
		if q < 1 {
			q = 1
		}
		k := r.Type + "|" + r.Role
		m := typeRoleToKeys[k]
		issuerKeys := make([]string, 0, len(m))
		for key := range m {
			issuerKeys = append(issuerKeys, key)
		}
		sort.Strings(issuerKeys)
		observed := len(issuerKeys)
		satisfied := observed >= q
		pv := PolicyVerdict{Type: r.Type, Role: r.Role, Quorum: q, Observed: observed, IssuerKeys: issuerKeys, Satisfied: satisfied}
		if satisfied {
			pv.Reasons = []string{"Satisfied"}
		} else {
			ok = false
			if observed == 0 {
				pv.Reasons = []string{"Missing required evidence"}
			} else {
				pv.Reasons = []string{"Insufficient quorum"}
			}
		}
		out = append(out, pv)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			if out[i].Role == out[j].Role {
				return out[i].Quorum < out[j].Quorum
			}
			return out[i].Role < out[j].Role
		}
		return out[i].Type < out[j].Type
	})

	return out, ok
}
