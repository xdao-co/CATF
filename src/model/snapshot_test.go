package model

import (
	"encoding/json"
	"testing"
)

func TestSnapshot_ResolverRequest_JSONShape(t *testing.T) {
	req := ResolverRequest{
		SubjectCID: "bafy-subject-1",
		Policy:     BlobRef{CID: "bafy-policy-1"},
		Attestations: []BlobRef{
			{CID: "bafy-att-1"},
			{CID: "bafy-att-2"},
		},
		Compliance: ComplianceStrict,
	}

	b, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	const want = "{\n" +
		"  \"subjectCID\": \"bafy-subject-1\",\n" +
		"  \"policy\": {\n" +
		"    \"cid\": \"bafy-policy-1\"\n" +
		"  },\n" +
		"  \"attestations\": [\n" +
		"    {\n" +
		"      \"cid\": \"bafy-att-1\"\n" +
		"    },\n" +
		"    {\n" +
		"      \"cid\": \"bafy-att-2\"\n" +
		"    }\n" +
		"  ],\n" +
		"  \"compliance\": \"strict\"\n" +
		"}"

	if string(b) != want {
		t.Fatalf("snapshot mismatch:\n%s", string(b))
	}
}

func TestSnapshot_ResolverResponse_JSONShape(t *testing.T) {
	resp := ResolverResponse{
		Resolution: Resolution{
			SubjectCID:     "bafy-subject-1",
			State:          "Resolved",
			Confidence:     "High",
			Paths:          []Path{{ID: "path-1", CIDs: []string{"bafy-a"}}},
			Forks:          []Fork{},
			Exclusions:     []Exclusion{},
			Verdicts:       []Verdict{},
			PolicyVerdicts: []PolicyVerdict{},
		},
		TrustPolicyCID: "bafy-policy-1",
		AttestationIDs: []string{"bafy-att-1"},
		CROF:           CROFDocument{Bytes: []byte("crof-bytes"), CID: "bafy-crof-1"},
	}

	b, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	const want = "{\n" +
		"  \"resolution\": {\n" +
		"    \"subjectCID\": \"bafy-subject-1\",\n" +
		"    \"state\": \"Resolved\",\n" +
		"    \"confidence\": \"High\",\n" +
		"    \"paths\": [\n" +
		"      {\n" +
		"        \"id\": \"path-1\",\n" +
		"        \"cids\": [\n" +
		"          \"bafy-a\"\n" +
		"        ]\n" +
		"      }\n" +
		"    ],\n" +
		"    \"forks\": [],\n" +
		"    \"exclusions\": [],\n" +
		"    \"verdicts\": [],\n" +
		"    \"policyVerdicts\": []\n" +
		"  },\n" +
		"  \"trustPolicyCID\": \"bafy-policy-1\",\n" +
		"  \"attestationIDs\": [\n" +
		"    \"bafy-att-1\"\n" +
		"  ],\n" +
		"  \"crof\": {\n" +
		"    \"bytes\": \"Y3JvZi1ieXRlcw==\",\n" +
		"    \"cid\": \"bafy-crof-1\"\n" +
		"  }\n" +
		"}"

	if string(b) != want {
		t.Fatalf("snapshot mismatch:\n%s", string(b))
	}
}
