// Package crof implements the Canonical Resolver Output Format (CROF).
package crof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	"xdao.co/catf/cidutil"
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

	attCIDs := append([]string(nil), attestationCIDs...)
	sort.Strings(attCIDs)

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
	sb.WriteString("\n")

	// RESULT
	sb.WriteString("RESULT\n")
	resultLines := []string{
		"Subject-CID: " + res.SubjectCID,
		"Confidence: " + string(res.Confidence),
		"State: " + string(res.State),
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
	sort.Slice(ex, func(i, j int) bool {
		if ex[i].CID == ex[j].CID {
			return ex[i].Reason < ex[j].Reason
		}
		return ex[i].CID < ex[j].CID
	})
	for _, e := range ex {
		if e.CID != "" {
			sb.WriteString("Attestation-CID: ")
			sb.WriteString(e.CID)
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
	sort.Slice(verdicts, func(i, j int) bool {
		if verdicts[i].CID == verdicts[j].CID {
			if verdicts[i].ExcludedReason == verdicts[j].ExcludedReason {
				if verdicts[i].IssuerKey == verdicts[j].IssuerKey {
					if verdicts[i].ClaimType == verdicts[j].ClaimType {
						if verdicts[i].Trusted == verdicts[j].Trusted {
							if verdicts[i].Revoked == verdicts[j].Revoked {
								return strings.Join(verdicts[i].TrustRoles, ",") < strings.Join(verdicts[j].TrustRoles, ",")
							}
							return !verdicts[i].Revoked && verdicts[j].Revoked
						}
						return verdicts[i].Trusted && !verdicts[j].Trusted
					}
					return verdicts[i].ClaimType < verdicts[j].ClaimType
				}
				return verdicts[i].IssuerKey < verdicts[j].IssuerKey
			}
			return verdicts[i].ExcludedReason < verdicts[j].ExcludedReason
		}
		return verdicts[i].CID < verdicts[j].CID
	})
	for _, v := range verdicts {
		if v.CID != "" {
			sb.WriteString("Attestation-CID: ")
			sb.WriteString(v.CID)
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
		roles := append([]string(nil), v.TrustRoles...)
		sort.Strings(roles)
		for _, r := range roles {
			sb.WriteString("Trust-Role: ")
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
		if err == nil {
			out = []byte(strings.Replace(string(out), "Signature: 0", "Signature: "+sig, 1))
		}
	}

	return out
}

func signCROF(crofBytes []byte, privateKey ed25519.PrivateKey) (string, error) {
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
