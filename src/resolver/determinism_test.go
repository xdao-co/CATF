package resolver

import (
	"testing"
)

func permuteIndices(n int) [][]int {
	var out [][]int
	idx := make([]int, n)
	for i := 0; i < n; i++ {
		idx[i] = i
	}
	var gen func(int)
	gen = func(i int) {
		if i == n {
			p := append([]int(nil), idx...)
			out = append(out, p)
			return
		}
		for j := i; j < n; j++ {
			idx[i], idx[j] = idx[j], idx[i]
			gen(i + 1)
			idx[i], idx[j] = idx[j], idx[i]
		}
	}
	gen(0)
	return out
}

func TestDeterminism_Resolve_ShuffledInputs(t *testing.T) {
	subject := "bafy-resolve-determinism-1"

	pubA, privA := mustKeypair(t, 0xA1)
	pubR, privR := mustKeypair(t, 0xB2)

	issuerA := issuerKey(pubA)
	issuerR := issuerKey(pubR)

	a1 := mustAttestation(t, subject, "Determinism", map[string]string{"Type": "authorship", "Role": "author"}, issuerA, privA)
	r1 := mustAttestation(t, subject, "Determinism", map[string]string{"Type": "approval", "Role": "reviewer", "Effective-Date": "2026-01-01T00:00:00Z"}, issuerR, privR)

	policy := trustPolicy(
		[]trustEntry{{key: issuerA, role: "author"}, {key: issuerR, role: "reviewer"}},
		[]requireRule{{typ: "authorship", role: "author", quorum: 1}, {typ: "approval", role: "reviewer", quorum: 1}},
	)

	inputs := [][]byte{a1, r1}
	perms := permuteIndices(len(inputs))

	var golden *Resolution
	for run := 0; run < 25; run++ {
		for _, p := range perms {
			var attBytes [][]byte
			for _, i := range p {
				attBytes = append(attBytes, inputs[i])
			}
			res, err := Resolve(attBytes, []byte(policy), subject)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if golden == nil {
				golden = res
				continue
			}

			// Structural determinism checks.
			if res.State != golden.State {
				t.Fatalf("State changed: %s vs %s", res.State, golden.State)
			}
			if res.Confidence != golden.Confidence {
				t.Fatalf("Confidence changed: %s vs %s", res.Confidence, golden.Confidence)
			}
			if len(res.Paths) != len(golden.Paths) || len(res.Forks) != len(golden.Forks) || len(res.Exclusions) != len(golden.Exclusions) {
				t.Fatalf("resolution structure changed")
			}
			for i := range res.Paths {
				if res.Paths[i].ID != golden.Paths[i].ID {
					t.Fatalf("Path ID changed")
				}
				if len(res.Paths[i].CIDs) != len(golden.Paths[i].CIDs) {
					t.Fatalf("Path CIDs length changed")
				}
				for j := range res.Paths[i].CIDs {
					if res.Paths[i].CIDs[j] != golden.Paths[i].CIDs[j] {
						t.Fatalf("Path CID changed")
					}
				}
			}
		}
	}
}

func TestStrictMode_RejectsForksAndExclusions(t *testing.T) {
	subject := "bafy-strict-1"

	pubA, privA := mustKeypair(t, 0xA1)
	pubB, privB := mustKeypair(t, 0xA2)
	issuerA := issuerKey(pubA)
	issuerB := issuerKey(pubB)

	a1 := mustAttestation(t, subject, "Fork", map[string]string{"Type": "authorship", "Role": "author"}, issuerA, privA)
	a2 := mustAttestation(t, subject, "Fork", map[string]string{"Type": "authorship", "Role": "author"}, issuerB, privB)

	policy := trustPolicy(
		[]trustEntry{{key: issuerA, role: "author"}, {key: issuerB, role: "author"}},
		[]requireRule{{typ: "authorship", role: "author", quorum: 1}},
	)

	// Normal resolver should surface forks.
	res, err := Resolve([][]byte{a1, a2}, []byte(policy), subject)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != StateForked {
		t.Fatalf("expected Forked, got %s", res.State)
	}

	// Strict mode should reject.
	if _, err := ResolveStrict([][]byte{a1, a2}, []byte(policy), subject); err == nil {
		t.Fatalf("expected strict mode error")
	}
}
