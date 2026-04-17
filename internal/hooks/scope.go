package hooks

import (
	"github.com/fsc/telepath-core/pkg/schema"
)

// ScopeCheck evaluates whether target is in scope. v0.1 week 1-2 ships a
// pass-through stub: no ROE loaded yet, so every target is considered
// in-scope with a clear reason string so operators can see from logs that
// real enforcement hasn't kicked in yet. Week-3 work replaces this with the
// real ROE evaluator (docs/ARCHITECTURE.md §8.2).
func ScopeCheck(target, protocol string) schema.ScopeCheckResult {
	return schema.ScopeCheckResult{
		OK:      true,
		InScope: true,
		Reason:  "scope checker stub (v0.1 pre-ROE): target accepted pending ROE evaluator",
	}
}

// ROESummary returns a placeholder summary until the ROE package lands.
func ROESummary() schema.ROESummaryResult {
	return schema.ROESummaryResult{
		OK:      true,
		Summary: "ROE not yet implemented (v0.1 pre-ROE). SessionStart hook should defer scope-dependent messaging.",
	}
}
