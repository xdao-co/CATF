package model

// BlobRef refers to canonical bytes directly or by CID.
// Exactly one of CID or Bytes MUST be set.
//
// JSON note: Bytes are encoded as base64 by encoding/json.
type BlobRef struct {
	CID   string `json:"cid,omitempty"`
	Bytes []byte `json:"bytes,omitempty"`
}

type ComplianceMode string

const (
	CompliancePermissive ComplianceMode = "permissive"
	ComplianceStrict     ComplianceMode = "strict"
)

type ResolverRequest struct {
	SubjectCID   string         `json:"subjectCID"`
	Policy       BlobRef        `json:"policy"`
	Attestations []BlobRef      `json:"attestations"`
	Compliance   ComplianceMode `json:"compliance"`
}

type Path struct {
	ID   string   `json:"id"`
	CIDs []string `json:"cids"`
}

type Fork struct {
	ID              string   `json:"id"`
	ConflictingPath []string `json:"conflictingPath"`
}

type Exclusion struct {
	CID       string `json:"cid"`
	InputHash string `json:"inputHash"`
	Reason    string `json:"reason"`
}

type Verdict struct {
	CID                string   `json:"cid"`
	InputHash          string   `json:"inputHash"`
	AttestedSubjectCID string   `json:"attestedSubjectCID"`
	IssuerKey          string   `json:"issuerKey"`
	ClaimType          string   `json:"claimType"`
	Trusted            bool     `json:"trusted"`
	TrustRoles         []string `json:"trustRoles"`
	Revoked            bool     `json:"revoked"`
	RevokedBy          []string `json:"revokedBy"`
	Status             string   `json:"status"`
	Reasons            []string `json:"reasons"`
	ExcludedReason     string   `json:"excludedReason"`
}

type PolicyVerdict struct {
	Type       string   `json:"type"`
	Role       string   `json:"role"`
	Quorum     int      `json:"quorum"`
	Observed   int      `json:"observed"`
	Satisfied  bool     `json:"satisfied"`
	IssuerKeys []string `json:"issuerKeys"`
	Reasons    []string `json:"reasons"`
}

type Resolution struct {
	SubjectCID     string          `json:"subjectCID"`
	State          string          `json:"state"`
	Confidence     string          `json:"confidence"`
	Paths          []Path          `json:"paths"`
	Forks          []Fork          `json:"forks"`
	Exclusions     []Exclusion     `json:"exclusions"`
	Verdicts       []Verdict       `json:"verdicts"`
	PolicyVerdicts []PolicyVerdict `json:"policyVerdicts"`
}

type CROFDocument struct {
	Bytes []byte `json:"bytes"`
	CID   string `json:"cid"`
}

type ResolverResponse struct {
	Resolution     Resolution   `json:"resolution"`
	TrustPolicyCID string       `json:"trustPolicyCID"`
	AttestationIDs []string     `json:"attestationIDs"`
	CROF           CROFDocument `json:"crof"`
}
