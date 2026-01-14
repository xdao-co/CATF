// Package crof implements the Canonical Resolver Output Format (CROF).
//
// API stability: see STABILITY.md (repository root) for Stable vs Experimental tiers.
package crof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"xdao.co/catf/cidutil"
	"xdao.co/catf/compliance"
	"xdao.co/catf/resolver"
)

const (
	Preamble  = "-----BEGIN XDAO RESOLUTION-----"
	Postamble = "-----END XDAO RESOLUTION-----"
)

// PolicyCID returns a deterministic local identifier for a trust policy document.
// This is an IPFS-compatible CIDv1 (raw + sha2-256) derived from canonical bytes.
func PolicyCID(policyBytes []byte) string {
	return cidutil.CIDv1RawSHA256(policyBytes)
}

type RenderOptions struct {
	ResolverID string
	ResolvedAt time.Time // informational only; zero means omit

	// Optional CROF supersession.
	// If set, the CROF asserts it supersedes a prior CROF identified by CID.
	SupersedesCROFCID string

	// Optional CROF signing. If PrivateKey is set, the output will include a CRYPTO
	// section populated and Signature computed over the CROF bytes excluding the
	// Signature: line.
	ResolverKey string
	PrivateKey  ed25519.PrivateKey
}

// Render produces a canonical CROF document binding a resolution to its inputs.
// Sections are always present and ordering is deterministic.
func Render(res *resolver.Resolution, trustPolicyCID string, attestationCIDs []string, opts RenderOptions) []byte {
	resolverID := opts.ResolverID
	if resolverID == "" {
		resolverID = "xdao-resolver-reference"
	}

	inputIDs := append([]string(nil), attestationCIDs...)
	var attCIDs []string
	var inputHashes []string
	for _, id := range inputIDs {
		if strings.HasPrefix(id, "sha256:") {
			inputHashes = append(inputHashes, id)
			continue
		}
		attCIDs = append(attCIDs, id)
	}
	sort.Strings(attCIDs)
	sort.Strings(inputHashes)

	var sb strings.Builder
	sb.WriteString(Preamble)
	sb.WriteString("\n")

	// META
	sb.WriteString("META\n")
	metaLines := []string{
		"Resolver-ID: " + resolverID,
		"Spec: xdao-crof-1",
		"Version: 1",
	}
	if !opts.ResolvedAt.IsZero() {
		metaLines = append(metaLines, "Resolved-At: "+opts.ResolvedAt.UTC().Format(time.RFC3339))
	}
	if opts.SupersedesCROFCID != "" {
		metaLines = append(metaLines, "Supersedes-CROF-CID: "+opts.SupersedesCROFCID)
	}
	sort.Strings(metaLines)
	for _, l := range metaLines {
		sb.WriteString(l)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// INPUTS
	sb.WriteString("INPUTS\n")
	sb.WriteString("Trust-Policy-CID: ")
	sb.WriteString(trustPolicyCID)
	sb.WriteString("\n")
	for _, cid := range attCIDs {
		sb.WriteString("Attestation-CID: ")
		sb.WriteString(cid)
		sb.WriteString("\n")
	}
	for _, h := range inputHashes {
		sb.WriteString("Input-Hash: ")
		sb.WriteString(h)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// RESULT
	sb.WriteString("RESULT\n")
	resultLines := []string{
		"Subject-CID: " + res.SubjectCID,
		"Confidence: " + string(res.Confidence),
		"State: " + string(res.State),
	}
	if len(res.PolicyVerdicts) > 0 {
		pvs := append([]resolver.PolicyVerdict(nil), res.PolicyVerdicts...)
		sort.Slice(pvs, func(i, j int) bool {
			if pvs[i].Type == pvs[j].Type {
				if pvs[i].Role == pvs[j].Role {
					return pvs[i].Quorum < pvs[j].Quorum
				}
				return pvs[i].Role < pvs[j].Role
			}
			return pvs[i].Type < pvs[j].Type
		})
		for _, pv := range pvs {
			resultLines = append(resultLines, fmt.Sprintf(
				"Policy-Verdict: Type=%s; Role=%s; Quorum=%d; Observed=%d; Satisfied=%t",
				pv.Type, pv.Role, pv.Quorum, pv.Observed, pv.Satisfied,
			))
			issuerKeys := uniqueSorted(pv.IssuerKeys)
			for _, k := range issuerKeys {
				resultLines = append(resultLines, fmt.Sprintf(
					"Policy-Issuer-Key: Type=%s; Role=%s; Issuer-Key=%s",
					pv.Type, pv.Role, k,
				))
			}
			reasons := uniqueSorted(pv.Reasons)
			for _, r := range reasons {
				resultLines = append(resultLines, fmt.Sprintf(
					"Policy-Verdict-Reason: Type=%s; Role=%s; Reason=%s",
					pv.Type, pv.Role, r,
				))
			}
		}
	}
	sort.Strings(resultLines)
	for _, l := range resultLines {
		sb.WriteString(l)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// PATHS
	sb.WriteString("PATHS\n")
	paths := append([]resolver.Path(nil), res.Paths...)
	sort.Slice(paths, func(i, j int) bool { return paths[i].ID < paths[j].ID })
	for _, p := range paths {
		sb.WriteString("Path-ID: ")
		sb.WriteString(p.ID)
		sb.WriteString("\n")
		for _, cid := range p.CIDs {
			sb.WriteString("Attestation-CID: ")
			sb.WriteString(cid)
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")

	// FORKS
	sb.WriteString("FORKS\n")
	forks := append([]resolver.Fork(nil), res.Forks...)
	sort.Slice(forks, func(i, j int) bool { return forks[i].ID < forks[j].ID })
	for _, f := range forks {
		sb.WriteString("Fork-ID: ")
		sb.WriteString(f.ID)
		sb.WriteString("\n")
		paths := append([]string(nil), f.ConflictingPath...)
		sort.Strings(paths)
		for _, pid := range paths {
			sb.WriteString("Conflicting-Path: ")
			sb.WriteString(pid)
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")

	// EXCLUSIONS
	sb.WriteString("EXCLUSIONS\n")
	ex := append([]resolver.Exclusion(nil), res.Exclusions...)
	sort.SliceStable(ex, func(i, j int) bool {
		if ex[i].CID == ex[j].CID {
			if ex[i].InputHash == ex[j].InputHash {
				return ex[i].Reason < ex[j].Reason
			}
			return ex[i].InputHash < ex[j].InputHash
		}
		return ex[i].CID < ex[j].CID
	})
	for _, e := range ex {
		if e.CID != "" {
			sb.WriteString("Attestation-CID: ")
			sb.WriteString(e.CID)
			sb.WriteString("\n")
		}
		if e.InputHash != "" {
			sb.WriteString("Input-Hash: ")
			sb.WriteString(e.InputHash)
			sb.WriteString("\n")
		}
		sb.WriteString("Reason: ")
		sb.WriteString(e.Reason)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// VERDICTS
	sb.WriteString("VERDICTS\n")
	verdicts := append([]resolver.Verdict(nil), res.Verdicts...)
	for i := range verdicts {
		verdicts[i].TrustRoles = uniqueSorted(verdicts[i].TrustRoles)
		verdicts[i].RevokedBy = uniqueSorted(verdicts[i].RevokedBy)
		verdicts[i].Reasons = uniqueSorted(verdicts[i].Reasons)
		if len(verdicts[i].Reasons) == 0 && verdicts[i].ExcludedReason != "" {
			verdicts[i].Reasons = []string{verdicts[i].ExcludedReason}
		}
	}
	sort.SliceStable(verdicts, func(i, j int) bool { return verdictLessV2(verdicts[i], verdicts[j]) })
	for _, v := range verdicts {
		if v.CID != "" {
			sb.WriteString("Attestation-CID: ")
			sb.WriteString(v.CID)
			sb.WriteString("\n")
		}
		if v.InputHash != "" {
			sb.WriteString("Input-Hash: ")
			sb.WriteString(v.InputHash)
			sb.WriteString("\n")
		}
		if v.AttestedSubjectCID != "" {
			sb.WriteString("Attested-Subject-CID: ")
			sb.WriteString(v.AttestedSubjectCID)
			sb.WriteString("\n")
		}
		if v.IssuerKey != "" {
			sb.WriteString("Issuer-Key: ")
			sb.WriteString(v.IssuerKey)
			sb.WriteString("\n")
		}
		if v.ClaimType != "" {
			sb.WriteString("Claim-Type: ")
			sb.WriteString(v.ClaimType)
			sb.WriteString("\n")
		}
		if v.Status != "" {
			sb.WriteString("Status: ")
			sb.WriteString(string(v.Status))
			sb.WriteString("\n")
		}
		sb.WriteString("Trusted: ")
		if v.Trusted {
			sb.WriteString("true\n")
		} else {
			sb.WriteString("false\n")
		}
		sb.WriteString("Revoked: ")
		if v.Revoked {
			sb.WriteString("true\n")
		} else {
			sb.WriteString("false\n")
		}
		for _, cid := range v.RevokedBy {
			sb.WriteString("Revoked-By: ")
			sb.WriteString(cid)
			sb.WriteString("\n")
		}
		for _, r := range v.TrustRoles {
			sb.WriteString("Trust-Role: ")
			sb.WriteString(r)
			sb.WriteString("\n")
		}
		for _, r := range v.Reasons {
			sb.WriteString("Reason: ")
			sb.WriteString(r)
			sb.WriteString("\n")
		}
		if v.ExcludedReason != "" {
			sb.WriteString("Excluded-Reason: ")
			sb.WriteString(v.ExcludedReason)
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")

	// CRYPTO (left empty in this reference implementation)
	sb.WriteString("CRYPTO\n")
	cryptoLines := []string{}
	if opts.ResolverKey != "" {
		cryptoLines = append(cryptoLines,
			"Hash-Alg: sha256",
			"Resolver-Key: "+opts.ResolverKey,
			"Signature-Alg: ed25519",
			"Signature: 0",
		)
	}
	sort.Strings(cryptoLines)
	for _, l := range cryptoLines {
		sb.WriteString(l)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	sb.WriteString(Postamble)
	sb.WriteString("\n")
	out := []byte(sb.String())

	if len(opts.PrivateKey) > 0 && opts.ResolverKey != "" {
		sig, err := signCROF(out, opts.PrivateKey)
		if err != nil {
			panic("crof: signing requested but failed: " + err.Error())
		}
		out = []byte(strings.Replace(string(out), "Signature: 0", "Signature: "+sig, 1))
	}

	return out
}

func uniqueSorted(items []string) []string {
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

func verdictLessV2(a, b resolver.Verdict) bool {
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

// RenderWithCompliance renders CROF and enforces compliance-mode constraints.
//
// In strict mode, this rejects ambiguous outputs (forks/exclusions/non-resolved)
// and disallows non-deterministic fields like Resolved-At.
func RenderWithCompliance(res *resolver.Resolution, trustPolicyCID string, attestationCIDs []string, opts RenderOptions, mode compliance.ComplianceMode) ([]byte, error) {
	if mode == compliance.Strict {
		if res == nil {
			return nil, errors.New("strict mode: nil resolution")
		}
		if len(res.Exclusions) > 0 {
			return nil, fmt.Errorf("strict mode: exclusions present (%d)", len(res.Exclusions))
		}
		if len(res.Forks) > 0 {
			return nil, fmt.Errorf("strict mode: forks present (%d)", len(res.Forks))
		}
		if res.State != resolver.StateResolved {
			return nil, fmt.Errorf("strict mode: expected StateResolved, got %s", res.State)
		}
		if !opts.ResolvedAt.IsZero() {
			return nil, errors.New("strict mode: Resolved-At not permitted")
		}
	}
	return Render(res, trustPolicyCID, attestationCIDs, opts), nil
}

func signCROF(crofBytes []byte, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid ed25519 private key length")
	}
	scope, err := crofSignatureScope(crofBytes)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(scope)
	sig := ed25519.Sign(privateKey, digest[:])
	return base64.StdEncoding.EncodeToString(sig), nil
}

func crofSignatureScope(crofBytes []byte) ([]byte, error) {
	lines := strings.Split(string(crofBytes), "\n")
	var out []string
	removed := false
	for _, l := range lines {
		if strings.HasPrefix(l, "Signature: ") {
			if removed {
				return nil, errors.New("multiple Signature lines")
			}
			removed = true
			continue
		}
		out = append(out, l)
	}
	if !removed {
		return nil, errors.New("missing Signature line")
	}
	return []byte(strings.Join(out, "\n")), nil
}
