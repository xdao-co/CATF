package catf

// Rule is an explicit, named validation rule.
//
// ID must be stable across versions.
// Apply must be deterministic and side-effect free.
type Rule struct {
	ID    string
	Apply func(*CATF) error
}

func (r Rule) apply(a *CATF) error {
	if r.Apply == nil {
		return newError(KindInternal, "CATF-INTERNAL-001", "nil rule Apply")
	}
	if err := r.Apply(a); err != nil {
		return err
	}
	return nil
}

// ValidateRules runs rules in order, returning the first failure.
//
// Determinism note: rule order is the evaluation order; keep it stable.
func ValidateRules(a *CATF, rules []Rule) error {
	for _, r := range rules {
		if err := r.apply(a); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRulesAll runs all rules in order, returning a (deterministically ordered)
// slice of all violations.
func ValidateRulesAll(a *CATF, rules []Rule) []error {
	var out []error
	for _, r := range rules {
		if err := r.apply(a); err != nil {
			out = append(out, err)
		}
	}
	return out
}
