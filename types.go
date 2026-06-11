package main

type Technique struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Tactics        []string `json:"tactics"`
	Platforms      []string `json:"platforms"`
	DataSources    []string `json:"data_sources"`
	DetectionNotes string   `json:"detection_notes"`
	DataComponents []string `json:"data_components"`
}

type STIXBundle struct {
	Objects []STIXObject `json:"objects"`
}

type STIXObject struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`

	KillChainPhases []struct {
		PhaseName string `json:"phase_name"`
	} `json:"kill_chain_phases"`

	XMitrePlatforms      []string `json:"x_mitre_platforms"`
	XMitreDataSources    []string `json:"x_mitre_data_sources"`
	XMitreDetection      string   `json:"x_mitre_detection"`
	XMitreAliases        []string `json:"x_mitre_aliases"`
	XMitreDeprecated     bool     `json:"x_mitre_deprecated"`
	XMitreDataComponents []string `json:"x_mitre_data_components"`
	XMitreAnalyticRefs []string `json:"x_mitre_analytic_refs"`
	XMitreLogSourceReferences []struct {
		XMitreDataComponentRef string `json:"x_mitre_data_component_ref"`
	} `json:"x_mitre_log_source_references"`
	Revoked              bool     `json:"revoked"`

	ID               string   `json:"id"`
	RelationshipType string   `json:"relationship_type"`
	SourceRef        string   `json:"source_ref"`
	TargetRef        string   `json:"target_ref"`
	ObjectRefs       []string `json:"object_refs"`

	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
}

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
}

type Mitigation struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Relationship struct {
	Type       string `json:"type"`
	SourceType string `json:"source_type"`
	SourceID   string `json:"source_id"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
}

type Software struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
}

type Campaign struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
}

type DataComponent struct {
	ID          string `json:"id"` // DC if available, else STIX ID fallback
	StixID      string `json:"stix_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type DetectionStrategy struct {
	ID string `json:"id"`
	StixID string `json:"stix_id"`
	Name string `json:"name"`
	Description string `json:"description"`
	Analytics []string `json:"analytics"`
}

type Analytic struct {
	ID string `json:"id"`
	StixID string `json:"stix_id"`
	Name string `json:"name"`
	Description string `json:"description"`
	DataComponents []string `json:"data_components"`
}

type CacheData struct {
	Techniques     []Technique     `json:"techniques"`
	Groups         []Group         `json:"groups"`
	Mitigations    []Mitigation    `json:"mitigations"`
	Softwares      []Software      `json:"softwares"`
	Campaigns      []Campaign      `json:"campaigns"`
	Relationships  []Relationship  `json:"relationships"`
	DataComponents []DataComponent `json:"data_components"`
	DetectionStrategies []DetectionStrategy `json:"detection_strategies"`
	Analytics []Analytic `json:"analytics"`
}

const (
	cachePath = "data/mitre-cache.json"
	metaPath  = "data/update-meta.json"
)

type UpdateMeta struct {
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
}
