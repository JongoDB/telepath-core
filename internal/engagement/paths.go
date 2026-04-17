package engagement

import "path/filepath"

// Filesystem layout for a single engagement. Kept in one place so callers
// don't build paths ad-hoc.
//
//	<rootDir>/<id>/
//	├── engagement.yaml    — metadata (this package owns it)
//	├── audit.jsonl        — hash-chained audit log
//	├── sessions/          — reserved for operator-facing summary artifacts
//	├── vault/             — evidence (week 3+)
//	└── .claude/
//	    ├── CLAUDE.md      — rendered from templates/ at load
//	    ├── rules/         — copied at load
//	    ├── hooks/         — wired at load
//	    ├── mcp.json       — written at load
//	    └── sessions/      — day-end summaries (telepath_hook_lib reads here)

func engagementDir(rootDir, id string) string {
	return filepath.Join(rootDir, id)
}

func engagementYAMLPath(rootDir, id string) string {
	return filepath.Join(engagementDir(rootDir, id), "engagement.yaml")
}

func auditLogPath(rootDir, id string) string {
	return filepath.Join(engagementDir(rootDir, id), "audit.jsonl")
}

func claudeDir(rootDir, id string) string {
	return filepath.Join(engagementDir(rootDir, id), ".claude")
}

func claudeSessionsDir(rootDir, id string) string {
	return filepath.Join(claudeDir(rootDir, id), "sessions")
}
