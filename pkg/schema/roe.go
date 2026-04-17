package schema

import "time"

// RulesOfEngagement is the per-engagement scope/approval/rate-limit policy.
// Serialized to engagements/<id>/roe.yaml; loaded at engagement.Load; queried
// by the ROE evaluator in internal/roe.
//
// Any field added here needs a parallel change in the evaluator so it's
// actually enforced. Ignoring a field silently is the kind of thing that
// produces scope violations under bad faith.
type RulesOfEngagement struct {
	EngagementID     string          `yaml:"engagement_id" json:"engagement_id"`
	Version          int             `yaml:"version" json:"version"`
	InScope          Scope           `yaml:"in_scope" json:"in_scope"`
	OutOfScope       OutOfScope      `yaml:"out_of_scope" json:"out_of_scope"`
	AllowedProtocols []string        `yaml:"allowed_protocols" json:"allowed_protocols"`
	BlackoutWindows  []BlackoutWindow `yaml:"blackout_windows,omitempty" json:"blackout_windows,omitempty"`
	DataHandling     DataHandling    `yaml:"data_handling" json:"data_handling"`
	RateLimits       RateLimits      `yaml:"rate_limits" json:"rate_limits"`
	WriteActions     WriteActions    `yaml:"write_actions" json:"write_actions"`
}

// Scope is the in_scope block. Hosts are a mix of exact hostnames, domain
// suffixes (leading "." or "*."), and CIDR blocks. SaaSTenants pairs a
// provider key (microsoft_365, google_workspace, salesforce, generic_oauth)
// with the tenant identifier.
type Scope struct {
	Hosts       []string         `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Domains     []string         `yaml:"domains,omitempty" json:"domains,omitempty"`
	SaaSTenants []map[string]string `yaml:"saas_tenants,omitempty" json:"saas_tenants,omitempty"`
}

// OutOfScope takes precedence over InScope; a target matching both is
// denied. DataClasses flag classes of data that must not be retrieved at all
// (payroll, PII CSR recordings, etc.).
type OutOfScope struct {
	Hosts       []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Domains     []string `yaml:"domains,omitempty" json:"domains,omitempty"`
	DataClasses []string `yaml:"data_classes,omitempty" json:"data_classes,omitempty"`
}

// BlackoutWindow forbids actions within a time range. Only absolute windows
// are supported in v0.1 (start/end). Cron-style recurring windows land in
// v0.2 along with multi-operator scheduling.
type BlackoutWindow struct {
	Start  *time.Time `yaml:"start,omitempty" json:"start,omitempty"`
	End    *time.Time `yaml:"end,omitempty" json:"end,omitempty"`
	Reason string     `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// DataHandling governs retention, export, and redaction of engagement data.
type DataHandling struct {
	RetentionDays        int      `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	AllowedExportFormats []string `yaml:"allowed_export_formats,omitempty" json:"allowed_export_formats,omitempty"`
	RequireRedaction     bool     `yaml:"require_redaction,omitempty" json:"require_redaction,omitempty"`
}

// RateLimits bound how fast telepath can query client systems.
type RateLimits struct {
	PerHostPerMinute int `yaml:"per_host_per_minute,omitempty" json:"per_host_per_minute,omitempty"`
	BulkDataMB       int `yaml:"bulk_data_mb,omitempty" json:"bulk_data_mb,omitempty"`
}

// WriteActions governs which write operations require operator approval.
type WriteActions struct {
	Policy     string   `yaml:"policy,omitempty" json:"policy,omitempty"` // always|require_approval|never
	Exceptions []string `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

// Write policy constants.
const (
	WritePolicyAlwaysApprove  = "always"
	WritePolicyRequireApproval = "require_approval"
	WritePolicyNever          = "never"
)
