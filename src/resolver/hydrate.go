package resolver

import (
	"errors"
	"fmt"

	"github.com/ipfs/go-cid"

	"xdao.co/catf/catf"
	"xdao.co/catf/cidutil"
	"xdao.co/catf/compliance"
	"xdao.co/catf/storage"
	"xdao.co/catf/tpdl"
)

var ErrMissingCAS = errors.New("resolver: missing CAS for CID hydration")

// BlobRef refers to bytes directly or by CID (hydrated via CAS).
// Exactly one of Bytes or CID MUST be set.
type BlobRef struct {
	Bytes []byte
	CID   cid.Cid
}

// ResolveRequestCAS is a resolver request that supports CID hydration through an injected CAS.
//
// Deterministic hydration order:
// - If CASAdapters is provided, adapters are consulted in the provided slice order.
// - No randomization or map iteration is used.
// - If both CAS and CASAdapters are set, the request is rejected.
type ResolveRequestCAS struct {
	Attestations []BlobRef
	Policy       BlobRef
	SubjectCID   string

	Compliance compliance.ComplianceMode

	CAS         storage.CAS
	CASAdapters []storage.CAS
}

// ResolveOutputCAS bundles the resolution with the deterministic input identifiers used to
// bind a CROF document to its inputs.
type ResolveOutputCAS struct {
	Resolution      *Resolution
	TrustPolicyCID  string
	AttestationIDs  []string
	AttestationCIDV []cid.Cid
}

func ResolveWithCAS(req ResolveRequestCAS) (*ResolveOutputCAS, error) {
	cas, err := casFromRequest(req.CAS, req.CASAdapters)
	if err != nil {
		return nil, err
	}

	policyBytes, policyCID, err := hydrateOne(req.Policy, cas)
	if err != nil {
		return nil, fmt.Errorf("resolver: hydrate policy: %w", err)
	}
	policy, err := tpdl.ParseWithCompliance(policyBytes, req.Compliance)
	if err != nil {
		return nil, err
	}

	attBytes := make([][]byte, 0, len(req.Attestations))
	attIDs := make([]string, 0, len(req.Attestations))
	attCIDs := make([]cid.Cid, 0, len(req.Attestations))
	for i, a := range req.Attestations {
		b, id, err := hydrateOne(a, cas)
		if err != nil {
			return nil, fmt.Errorf("resolver: hydrate attestation[%d]: %w", i, err)
		}
		attBytes = append(attBytes, b)
		attCIDs = append(attCIDs, id)

		// Bind to either CATF CID (when parse/canonicalization succeeds) or a stable input hash.
		if len(a.Bytes) > 0 {
			parsed, perr := catf.Parse(a.Bytes)
			if perr == nil {
				cidStr, cerr := parsed.CID()
				if cerr == nil {
					attIDs = append(attIDs, cidStr)
					continue
				}
			}
			attIDs = append(attIDs, inputHash(a.Bytes))
			continue
		}
		attIDs = append(attIDs, id.String())
	}

	res, err := resolveWithPolicy(attBytes, policy, req.SubjectCID)
	if err != nil {
		return nil, err
	}

	return &ResolveOutputCAS{
		Resolution:      res,
		TrustPolicyCID:  policyCID.String(),
		AttestationIDs:  attIDs,
		AttestationCIDV: attCIDs,
	}, nil
}

func casFromRequest(single storage.CAS, adapters []storage.CAS) (storage.CAS, error) {
	if single != nil && len(adapters) > 0 {
		return nil, errors.New("resolver: specify either CAS or CASAdapters, not both")
	}
	if single != nil {
		return single, nil
	}
	if len(adapters) > 0 {
		return storage.MultiCAS{Adapters: adapters}, nil
	}
	return nil, nil
}

func hydrateOne(ref BlobRef, cas storage.CAS) ([]byte, cid.Cid, error) {
	if len(ref.Bytes) > 0 && ref.CID.Defined() {
		return nil, cid.Undef, errors.New("ambiguous blob ref: both bytes and CID set")
	}
	if len(ref.Bytes) > 0 {
		computed, err := cidutil.CIDv1RawSHA256CID(ref.Bytes)
		if err != nil {
			return nil, cid.Undef, err
		}
		return ref.Bytes, computed, nil
	}
	if ref.CID.Defined() {
		if cas == nil {
			return nil, cid.Undef, ErrMissingCAS
		}
		b, err := cas.Get(ref.CID)
		if err != nil {
			return nil, cid.Undef, err
		}
		computed, err := cidutil.CIDv1RawSHA256CID(b)
		if err != nil {
			return nil, cid.Undef, err
		}
		if computed != ref.CID {
			return nil, cid.Undef, storage.ErrCIDMismatch
		}
		return b, ref.CID, nil
	}
	return nil, cid.Undef, errors.New("invalid blob ref: neither bytes nor CID set")
}
