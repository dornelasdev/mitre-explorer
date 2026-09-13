// Package attack provides ATT&CK models, dataset normalization, and local storage.
package attack

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
	ID          string   `json:"id"`
	StixID      string   `json:"stix_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Analytics   []string `json:"analytics"`
}

type Analytic struct {
	ID             string   `json:"id"`
	StixID         string   `json:"stix_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	DataComponents []string `json:"data_components"`
}

type CacheData struct {
	Techniques          []Technique         `json:"techniques"`
	Groups              []Group             `json:"groups"`
	Mitigations         []Mitigation        `json:"mitigations"`
	Softwares           []Software          `json:"softwares"`
	Campaigns           []Campaign          `json:"campaigns"`
	Relationships       []Relationship      `json:"relationships"`
	DataComponents      []DataComponent     `json:"data_components"`
	DetectionStrategies []DetectionStrategy `json:"detection_strategies"`
	Analytics           []Analytic          `json:"analytics"`
}

type UpdateMeta struct {
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
}
