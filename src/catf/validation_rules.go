package catf

// Rule is an explicit, named validation rule.
//
// UNSUPPORTED (GAP-07): this rule-engine plumbing is not part of the stable
// protocol-facing library API. Downstream callers SHOULD NOT depend on it.
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
// UNSUPPORTED (GAP-07): not part of the stable API; may change without notice.
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
//
// UNSUPPORTED (GAP-07): not part of the stable API; may change without notice.
func ValidateRulesAll(a *CATF, rules []Rule) []error {
	var out []error
	for _, r := range rules {
		if err := r.apply(a); err != nil {
			out = append(out, err)
		}
	}
	return out
}
