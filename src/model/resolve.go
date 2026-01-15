package model

import (
	"errors"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/compliance"
	"xdao.co/catf/crof"
	"xdao.co/catf/resolver"
	"xdao.co/catf/storage"
)

type ResolveOptions struct {
	CAS         storage.CAS
	CASAdapters []storage.CAS

	CROFOptions crof.RenderOptions
}

// ResolveResult runs the resolver (hydrating by CID via CAS when needed) and returns a compact,
// Go-friendly view of the outcome.
func ResolveResult(req ResolverRequest, opts ResolveOptions) (*ResolutionResult, error) {
	out, crofBytes, _, crofCID, err := resolveAndRender(req, opts)
	if err != nil {
		return nil, err
	}

	res := fromResolution(out.Resolution)
	return &ResolutionResult{
		CROF:       crofBytes,
		CROFCID:    crofCID,
		Verdicts:   append([]PolicyVerdict(nil), res.PolicyVerdicts...),
		Forks:      append([]Fork(nil), res.Forks...),
		Exclusions: append([]Exclusion(nil), res.Exclusions...),
	}, nil
}

// ResolveAndRenderCROF runs the resolver (hydrating by CID via CAS when needed) and renders
// canonical CROF bytes bound to the inputs.
func ResolveAndRenderCROF(req ResolverRequest, opts ResolveOptions) (*ResolverResponse, error) {
	out, crofBytes, crofCIDStr, _, err := resolveAndRender(req, opts)
	if err != nil {
		return nil, err
	}

	resp := &ResolverResponse{
		Resolution:     fromResolution(out.Resolution),
		TrustPolicyCID: out.TrustPolicyCID,
		AttestationIDs: append([]string(nil), out.AttestationIDs...),
		CROF: CROFDocument{
			Bytes: crofBytes,
			CID:   crofCIDStr,
		},
	}
	return resp, nil
}

func resolveAndRender(req ResolverRequest, opts ResolveOptions) (*resolver.ResolveOutputCAS, []byte, string, cid.Cid, error) {
	policyRef, err := toBlobRef(req.Policy)
	if err != nil {
		return nil, nil, "", cid.Undef, err
	}

	attRefs := make([]resolver.BlobRef, 0, len(req.Attestations))
	for i, a := range req.Attestations {
		ref, err := toBlobRef(a)
		if err != nil {
			return nil, nil, "", cid.Undef, NewError(ErrInvalidRequest, "invalid attestation["+itoa(i)+"]: "+err.Error())
		}
		attRefs = append(attRefs, ref)
	}

	mode, err := toCompliance(req.Compliance)
	if err != nil {
		return nil, nil, "", cid.Undef, err
	}

	out, err := resolver.ResolveWithCAS(resolver.ResolveRequestCAS{
		Attestations: attRefs,
		Policy:       policyRef,
		SubjectCID:   req.SubjectCID,
		Compliance:   mode,
		CAS:          opts.CAS,
		CASAdapters:  opts.CASAdapters,
	})
	if err != nil {
		return nil, nil, "", cid.Undef, mapErr(err)
	}

	crofBytes, crofCIDStr, err := crof.RenderWithCID(out.Resolution, out.TrustPolicyCID, out.AttestationIDs, opts.CROFOptions)
	if err != nil {
		return nil, nil, "", cid.Undef, mapErr(err)
	}

	crofCID, err := cid.Decode(crofCIDStr)
	if err != nil {
		return nil, nil, "", cid.Undef, NewError(ErrInvalidCID, "invalid crof cid")
	}

	return out, crofBytes, crofCIDStr, crofCID, nil
}

func toBlobRef(b BlobRef) (resolver.BlobRef, error) {
	if len(b.Bytes) > 0 && b.CID != "" {
		return resolver.BlobRef{}, NewError(ErrInvalidRequest, "blob ref has both bytes and cid")
	}
	if len(b.Bytes) > 0 {
		return resolver.BlobRef{Bytes: b.Bytes}, nil
	}
	if b.CID != "" {
		id, err := cid.Decode(b.CID)
		if err != nil {
			return resolver.BlobRef{}, NewError(ErrInvalidCID, "invalid cid")
		}
		return resolver.BlobRef{CID: id}, nil
	}
	return resolver.BlobRef{}, NewError(ErrInvalidRequest, "blob ref missing bytes/cid")
}

func toCompliance(m ComplianceMode) (compliance.ComplianceMode, error) {
	switch m {
	case CompliancePermissive:
		return compliance.Permissive, nil
	case ComplianceStrict:
		return compliance.Strict, nil
	case "":
		return 0, NewError(ErrInvalidRequest, "missing compliance mode")
	default:
		return 0, NewError(ErrInvalidRequest, "invalid compliance mode")
	}
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce
	}
	if errors.Is(err, resolver.ErrMissingCAS) {
		return NewError(ErrMissingCAS, err.Error())
	}
	if errors.Is(err, storage.ErrNotFound) {
		return NewError(ErrNotFound, err.Error())
	}
	if errors.Is(err, storage.ErrCIDMismatch) {
		return NewError(ErrCIDMismatch, err.Error())
	}
	if errors.Is(err, storage.ErrInvalidCID) {
		return NewError(ErrInvalidCID, err.Error())
	}
	return NewError(ErrInternal, err.Error())
}

func fromResolution(r *resolver.Resolution) Resolution {
	out := Resolution{
		SubjectCID:     r.SubjectCID,
		State:          string(r.State),
		Confidence:     string(r.Confidence),
		Paths:          make([]Path, 0, len(r.Paths)),
		Forks:          make([]Fork, 0, len(r.Forks)),
		Exclusions:     make([]Exclusion, 0, len(r.Exclusions)),
		Verdicts:       make([]Verdict, 0, len(r.Verdicts)),
		PolicyVerdicts: make([]PolicyVerdict, 0, len(r.PolicyVerdicts)),
	}
	for _, p := range r.Paths {
		out.Paths = append(out.Paths, Path{ID: p.ID, CIDs: append([]string(nil), p.CIDs...)})
	}
	for _, f := range r.Forks {
		out.Forks = append(out.Forks, Fork{ID: f.ID, ConflictingPath: append([]string(nil), f.ConflictingPath...)})
	}
	for _, e := range r.Exclusions {
		out.Exclusions = append(out.Exclusions, Exclusion{CID: e.CID, InputHash: e.InputHash, Reason: e.Reason})
	}
	for _, v := range r.Verdicts {
		out.Verdicts = append(out.Verdicts, Verdict{
			CID:                v.CID,
			InputHash:          v.InputHash,
			AttestedSubjectCID: v.AttestedSubjectCID,
			IssuerKey:          v.IssuerKey,
			ClaimType:          v.ClaimType,
			Trusted:            v.Trusted,
			TrustRoles:         append([]string(nil), v.TrustRoles...),
			Revoked:            v.Revoked,
			RevokedBy:          append([]string(nil), v.RevokedBy...),
			Status:             string(v.Status),
			Reasons:            append([]string(nil), v.Reasons...),
			ExcludedReason:     v.ExcludedReason,
		})
	}
	for _, pv := range r.PolicyVerdicts {
		out.PolicyVerdicts = append(out.PolicyVerdicts, PolicyVerdict{
			Type:       pv.Type,
			Role:       pv.Role,
			Quorum:     pv.Quorum,
			Observed:   pv.Observed,
			Satisfied:  pv.Satisfied,
			IssuerKeys: append([]string(nil), pv.IssuerKeys...),
			Reasons:    append([]string(nil), pv.Reasons...),
		})
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [32]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + (i % 10))
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}
