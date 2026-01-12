package crof

import (
	"errors"
	"fmt"
	"strings"
)

// SupersedesCROFCID returns the CID referenced by META: Supersedes-CROF-CID.
func SupersedesCROFCID(crofBytes []byte) (string, bool, error) {
	v, ok, err := singleFieldFromSection(crofBytes, "META", "Supersedes-CROF-CID")
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	return v, true, nil
}

// ValidateSupersession enforces minimal CROF supersession semantics.
//
// A CROF B supersedes CROF A when:
// - B's META includes Supersedes-CROF-CID equal to CID(A)
// - B and A bind the same Subject-CID
// - B and A use the same Resolver-ID
// - B and A use the same Trust-Policy-CID
func ValidateSupersession(newCROF, oldCROF []byte) error {
	oldCID := CID(oldCROF)
	newCID := CID(newCROF)
	if newCID == oldCID {
		return errors.New("supersession invalid: new CROF bytes identical to old")
	}

	sup, ok, err := SupersedesCROFCID(newCROF)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("supersession invalid: new CROF does not declare Supersedes-CROF-CID")
	}
	if sup != oldCID {
		return fmt.Errorf("supersession invalid: Supersedes-CROF-CID=%q does not match old CID=%q", sup, oldCID)
	}

	oldSubject, err := requiredFieldFromSection(oldCROF, "RESULT", "Subject-CID")
	if err != nil {
		return err
	}
	newSubject, err := requiredFieldFromSection(newCROF, "RESULT", "Subject-CID")
	if err != nil {
		return err
	}
	if oldSubject != newSubject {
		return fmt.Errorf("supersession invalid: subject mismatch old=%q new=%q", oldSubject, newSubject)
	}

	oldResolverID, err := requiredFieldFromSection(oldCROF, "META", "Resolver-ID")
	if err != nil {
		return err
	}
	newResolverID, err := requiredFieldFromSection(newCROF, "META", "Resolver-ID")
	if err != nil {
		return err
	}
	if oldResolverID != newResolverID {
		return fmt.Errorf("supersession invalid: resolver-id mismatch old=%q new=%q", oldResolverID, newResolverID)
	}

	oldPolicy, err := requiredFieldFromSection(oldCROF, "INPUTS", "Trust-Policy-CID")
	if err != nil {
		return err
	}
	newPolicy, err := requiredFieldFromSection(newCROF, "INPUTS", "Trust-Policy-CID")
	if err != nil {
		return err
	}
	if oldPolicy != newPolicy {
		return fmt.Errorf("supersession invalid: trust-policy mismatch old=%q new=%q", oldPolicy, newPolicy)
	}

	return nil
}

func sectionLines(crofBytes []byte, section string) ([]string, error) {
	lines := strings.Split(string(crofBytes), "\n")
	idx := -1
	for i, l := range lines {
		if l == section {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("missing section %q", section)
	}
	start := idx + 1
	var out []string
	for i := start; i < len(lines); i++ {
		l := lines[i]
		if l == "" {
			break
		}
		out = append(out, l)
	}
	return out, nil
}

func fieldValues(lines []string, key string) []string {
	prefix := key + ": "
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			out = append(out, strings.TrimPrefix(l, prefix))
		}
	}
	return out
}

func requiredFieldFromSection(crofBytes []byte, section, key string) (string, error) {
	v, ok, err := singleFieldFromSection(crofBytes, section, key)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("missing %s: %s", section, key)
	}
	return v, nil
}

func singleFieldFromSection(crofBytes []byte, section, key string) (string, bool, error) {
	lines, err := sectionLines(crofBytes, section)
	if err != nil {
		return "", false, err
	}
	vals := fieldValues(lines, key)
	if len(vals) == 0 {
		return "", false, nil
	}
	if len(vals) > 1 {
		return "", false, fmt.Errorf("multiple %s: %s", section, key)
	}
	if vals[0] == "" {
		return "", false, fmt.Errorf("empty %s: %s", section, key)
	}
	return vals[0], true, nil
}
