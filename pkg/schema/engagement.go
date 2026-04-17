package schema

import "time"

// Engagement lifecycle statuses.
const (
	StatusDraft    = "draft"
	StatusActive   = "active"
	StatusSealed   = "sealed"
	StatusArchived = "archived"
)

// Engagement is the top-level record for an assessment. Persisted at
// engagements/<id>/engagement.yaml; credentials and vault live in sibling files.
type Engagement struct {
	ID             string     `yaml:"id" json:"id"`
	ClientName     string     `yaml:"client_name" json:"client_name"`
	AssessmentType string     `yaml:"assessment_type" json:"assessment_type"`
	StartDate      time.Time  `yaml:"start_date" json:"start_date"`
	EndDate        time.Time  `yaml:"end_date" json:"end_date"`
	Status         string     `yaml:"status" json:"status"`
	SOWReference   string     `yaml:"sow_reference,omitempty" json:"sow_reference,omitempty"`
	OperatorID     string     `yaml:"operator_id" json:"operator_id"`
	PrimarySkill   string     `yaml:"primary_skill,omitempty" json:"primary_skill,omitempty"`
	TransportMode  string     `yaml:"transport_mode,omitempty" json:"transport_mode,omitempty"`
	CreatedAt      time.Time  `yaml:"created_at" json:"created_at"`
	SealedAt       *time.Time `yaml:"sealed_at,omitempty" json:"sealed_at,omitempty"`
}
